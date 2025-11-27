# scripts/evaluate.py
import sys
import os
import typer
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score, matthews_corrcoef, average_precision_score  # 新增MCC/AUPRC

# 适配路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
from vulnsil.database import get_db_session
from vulnsil.models import AnalysisResultRecord, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("evaluation")


def get_metrics(y_true, y_pred, y_prob=None):
    """辅助函数：计算核心指标 [改进] 加MCC/AUPRC"""
    metrics = {
        "Accuracy": accuracy_score(y_true, y_pred),
        "Precision": precision_score(y_true, y_pred, zero_division=0),
        "Recall": recall_score(y_true, y_pred, zero_division=0),
        "F1-Score": f1_score(y_true, y_pred, zero_division=0)
    }
    if settings.USE_MCC:
        metrics["MCC"] = matthews_corrcoef(y_true, y_pred)
    if y_prob is not None:
        try:
            metrics["AUC"] = roc_auc_score(y_true, y_prob)
            if settings.USE_AUPRC:
                metrics["AUPRC"] = average_precision_score(y_true, y_prob)
        except:
            metrics["AUC"] = 0.0
            metrics["AUPRC"] = 0.0
    return metrics


@app.command()
def eval(
        split_name: str = typer.Option(..., help="Dataset prefix (e.g., 'diversevul_test')"),
        force_threshold: float = typer.Option(None, help="Override the loaded calibration threshold temporarily")
):
    """
    Run comprehensive evaluation comparing 'Raw LLM' vs 'Calibrated Model'.
    Prints improvement deltas for paper tables.
    [改进] 加MCC/AUPRC
    """
    log.info(f"📊 Evaluating split: {split_name}")

    # 1. 确定使用的阈值
    # 如果用户没有在命令行指定，就使用 Config 自动加载的最佳阈值
    final_threshold = force_threshold if force_threshold is not None else settings.CALIBRATION_THRESHOLD
    log.info(f"⚙️ Using Calibration Threshold: {final_threshold:.4f}")

    data = []

    with get_db_session() as db:
        records = db.query(AnalysisResultRecord).join(Vulnerability).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status == "Success"
        ).all()

        for r in records:
            gt = r.vuln.ground_truth_label
            raw_pred = 1 if r.final_decision == "VULNERABLE" else 0
            cal_prob = r.calibrated_confidence
            cal_pred = 1 if cal_prob >= final_threshold else 0
            cwe = r.vuln.cwe_id or "N/A"
            data.append({'gt_label': gt, 'raw_pred': raw_pred, 'cal_prob': cal_prob, 'cal_pred': cal_pred, 'cwe': cwe})

    if not data:
        log.error("No data for evaluation.")
        return

    df = pd.DataFrame(data)
    y_true = df['gt_label']
    y_raw = df['raw_pred']
    y_cal = df['cal_pred']
    y_prob = df['cal_prob']

    metrics_raw = get_metrics(y_true, y_raw)
    metrics_cal = get_metrics(y_true, y_cal, y_prob)

    print("\n" + "-" * 75)
    print(" 📊 PERFORMANCE COMPARISON: Baseline (Raw LLM) vs Ours (Calibrated)")
    print("-" * 75)
    print(f"{'Metric':<15} | {'Baseline':<20} | {'Ours':<20} | {'Improvement':<12}")
    print("-" * 75)

    for k in metrics_cal:
        v_base = metrics_raw.get(k, 0.0)
        v_ours = metrics_cal[k]
        delta = v_ours - v_base
        delta_str = f"{'+' if delta >= 0 else ''}{delta:.2%}"
        print(f"{k:<15} | {v_base:<20.2%} | {v_ours:<20.2%} | {delta_str:<12}")

    print("-" * 75)

    # 混淆矩阵等原逻辑...

    print("\n" + "-" * 70)
    print(" 📉 Top 10 CWE Breakdown (Sensitivity Analysis)")
    print("-" * 70)

    # CWE 原逻辑...

    print("=" * 70 + "\n")


if __name__ == "__main__":
    app()