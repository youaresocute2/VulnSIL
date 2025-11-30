# scripts/evaluate.py
import sys
import os
import typer
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score

# 适配路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
from vulnsil.database import get_db_session
from vulnsil.models import AnalysisResultRecord, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("evaluation")


def get_metrics(y_true, y_pred, y_prob=None):
    """辅助函数：计算核心指标"""
    metrics = {
        "Accuracy": accuracy_score(y_true, y_pred),
        "Precision": precision_score(y_true, y_pred, zero_division=0),
        "Recall": recall_score(y_true, y_pred, zero_division=0),
        "F1-Score": f1_score(y_true, y_pred, zero_division=0)
    }
    # [Fix 10] Robust AUC Calculation
    if y_prob is not None and len(y_prob) > 0:
        unique_classes = len(set(y_true))
        # Handle cases where only 1 class exists in the batch (cannot calc AUC)
        if unique_classes < 2:
            log.warning("Dataset contains only one class label. AUC cannot be defined (set to 0.5).")
            metrics["AUC"] = 0.5
        else:
            try:
                # Handle possible NaN in probabilities from unfinished features
                clean_prob = np.nan_to_num(y_prob, nan=0.0)
                metrics["AUC"] = roc_auc_score(y_true, clean_prob)
            except Exception as e:
                log.warning(f"AUC calculation failed: {e}")
                metrics["AUC"] = 0.0
    else:
        metrics["AUC"] = 0.0

    return metrics


@app.command()
def eval(
        split_name: str = typer.Option(..., help="Dataset prefix (e.g., 'diversevul_test')"),
        force_threshold: float = typer.Option(None, help="Override the loaded calibration threshold temporarily")
):
    """
    Run comprehensive evaluation.
    Unified CWE ID support.
    """
    log.info(f"📊 Evaluating split: {split_name}")

    # 1. 确定使用的阈值
    final_threshold = force_threshold if force_threshold is not None else settings.CALIBRATION_THRESHOLD
    log.info(f"⚙️ Using Calibration Threshold: {final_threshold:.4f}")

    data = []

    with get_db_session() as db:
        records = db.query(AnalysisResultRecord).join(Vulnerability).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status == "Success"
        ).all()

        if not records:
            log.error(f"❌ No records found for '{split_name}'.")
            return

        print(f"📉 Loaded {len(records)} test samples.")

        for r in records:
            gt_label = r.vuln.ground_truth_label
            # [Fix] Unified cwe_id field
            gt_cwe = r.vuln.cwe_id if r.vuln.cwe_id and str(r.vuln.cwe_id).upper() != 'N/A' else "Other"

            # --- A. Raw LLM Decision (Baseline) ---
            raw_pred = 1 if r.final_decision == "VULNERABLE" else 0

            # --- B. Calibrated Decision (Ours) ---
            cal_score = float(r.calibrated_confidence or 0.0)
            cal_pred = 1 if cal_score >= final_threshold else 0

            data.append({
                "gt_label": gt_label,
                "raw_pred": raw_pred,
                "cal_pred": cal_pred,
                "cal_score": cal_score,
                "cwe": gt_cwe
            })

    # 转 DataFrame
    df = pd.DataFrame(data)
    y_true = df['gt_label'].values
    y_raw = df['raw_pred'].values
    y_cal = df['cal_pred'].values
    y_score = df['cal_score'].values

    # 计算指标
    metrics_raw = get_metrics(y_true, y_raw)
    metrics_cal = get_metrics(y_true, y_cal, y_score)

    # --- 输出报表 (Preserving Original Format) ---
    print("\n" + "=" * 70)
    print(f" 📊 VULNSIL FINAL EVALUATION REPORT: {split_name}")
    print(f" 🎯 Decision Threshold: {final_threshold:.4f}")
    print("=" * 70)

    # 1. 核心对比表
    print(f"{'METRIC':<15} | {'BASELINE (Raw LLM)':<20} | {'OURS (Calibrated)':<20} | {'IMPROVEMENT':<12}")
    print("-" * 75)

    order = ["Accuracy", "Precision", "Recall", "F1-Score"]

    for k in order:
        v_base = metrics_raw[k]
        v_ours = metrics_cal[k]
        delta = v_ours - v_base
        delta_str = f"{'+' if delta >= 0 else ''}{delta:.2%}"
        print(f"{k:<15} | {v_base:<20.2%} | {v_ours:<20.2%} | {delta_str:<12}")

    print(f"{'AUC (ROC)':<15} | {'N/A':<20} | {metrics_cal['AUC']:<20.4f} | {'N/A':<12}")
    print("-" * 75)

    # 2. 混淆矩阵
    tn, fp, fn, tp = confusion_matrix(y_true, y_cal).ravel()
    print("\n[🔍 Confusion Matrix - Calibrated Model]")
    print(f"{'':<10} {'Pred Safe (0)':<15} {'Pred Vuln (1)':<15}")
    print(f"{'GT Safe':<10} {tn:<15} {fp:<15}")
    print(f"{'GT Vuln':<10} {fn:<15} {tp:<15}")

    print("\n" + "-" * 70)
    print(" 📉 Top 10 CWE Breakdown (Sensitivity Analysis)")
    print("-" * 70)

    # CWE 召回率分析
    vuln_only = df[df['gt_label'] == 1]
    top_cwes = vuln_only['cwe'].value_counts().head(10).index.tolist()

    print(f"{'CWE ID':<25} | {'Count':<8} | {'Raw Recall':<12} | {'Ours Recall':<12}")
    for cwe in top_cwes:
        sub = vuln_only[vuln_only['cwe'] == cwe]
        if len(sub) == 0: continue

        rec_raw = sub[sub['raw_pred'] == 1].shape[0] / len(sub)
        rec_ours = sub[sub['cal_pred'] == 1].shape[0] / len(sub)
        print(f"{cwe:<25} | {len(sub):<8} | {rec_raw:.1%}      | {rec_ours:.1%}")

    print("=" * 70 + "\n")


if __name__ == "__main__":
    app()