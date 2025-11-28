# --- START OF FILE evaluate.py ---

import sys
import os
import typer
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, matthews_corrcoef, \
    average_precision_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings, init_runtime

from vulnsil.database import get_db_session
from vulnsil.models import Prediction, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("evaluation")


def get_metrics(y_true, y_pred, y_prob=None):
    """通用指标计算"""
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
            pass
    return metrics


@app.command()
def eval(
        split_name: str = typer.Option(..., help="Target dataset split (e.g. diversevul_test)"),
        force_threshold: float = typer.Option(None, help="Manually override calibration threshold")
):
    """
    Evaluate Model Performance.
    Can switch between legacy results and new prediction table results.
    """
    init_runtime()
    log.info(f"Evaluating Split: {split_name}")
    threshold = force_threshold if force_threshold is not None else settings.CALIBRATION_THRESHOLD
    log.info(f"Using Threshold: {threshold:.4f}")

    data = []

    with get_db_session() as db:
        log.info("Querying 'Prediction' table...")
        records = db.query(Prediction).join(Vulnerability).filter(
            Vulnerability.name.like(f"{split_name}%")
        ).all()

        for r in records:
            data.append({
                'gt': r.vuln.ground_truth_label,
                'raw_pred': r.llm_pred,
                'prob': r.calibrated_confidence,
                # 可以基于存储的 prob 动态调整阈值，而不是仅仅读 final_pred
                'cal_pred': 1 if r.calibrated_confidence >= threshold else 0,
                'cwe': r.vuln.cwe_id
            })

    if not data:
        log.error("No results found for this split.")
        return

    df = pd.DataFrame(data)

    # 打印对比报告
    m_raw = get_metrics(df['gt'], df['raw_pred'])
    m_cal = get_metrics(df['gt'], df['cal_pred'], df['prob'])

    print("\n" + "=" * 60)
    print(f"📊 Evaluation Report [{split_name}]")
    print(f"Sample Count: {len(df)}")
    print("=" * 60)
    print(f"{'Metric':<12} | {'Raw LLM':<15} | {'Calibrated':<15} | {'Delta':<10}")
    print("-" * 60)

    for k, v_cal in m_cal.items():
        v_raw = m_raw.get(k, 0.0)
        diff = v_cal - v_raw
        sign = "+" if diff >= 0 else ""
        print(f"{k:<12} | {v_raw:.4f}          | {v_cal:.4f}          | {sign}{diff:.4f}")

    print("-" * 60 + "\n")


if __name__ == "__main__":
    app()