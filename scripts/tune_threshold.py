# scripts/tune_threshold.py
import sys
import os
import json
import typer
from sklearn.metrics import f1_score
import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings, init_runtime

init_runtime()

from vulnsil.database import get_db_session
from vulnsil.models import Prediction, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("tune_threshold")


@app.command()
def tune(
        split_name: str = typer.Option(..., help="Dataset prefix (e.g., 'diversevul_test')"),
):
    """
    Tune calibration threshold on target dataset for domain adaptation.
    Searches 0.1-0.9 for Max F1.
    """
    init_runtime()
    data = []

    with get_db_session() as db:
        records = db.query(Prediction).join(Vulnerability).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status == "Success"
        ).all()

        for r in records:
            gt = r.vuln.ground_truth_label
            cal_prob = r.calibrated_confidence
            data.append({'gt_label': gt, 'cal_prob': cal_prob})

    if not data:
        log.error("No data for tuning.")
        return

    df = pd.DataFrame(data)
    y_true = df['gt_label']
    y_prob = df['cal_prob']

    best_th = 0.5
    best_f1 = 0.0

    for th in np.arange(0.1, 0.91, 0.01):
        y_pred = (y_prob >= th).astype(int)
        current_f1 = f1_score(y_true, y_pred)
        if current_f1 > best_f1:
            best_f1 = current_f1
            best_th = th

    log.info(f"Best Threshold: {best_th:.4f} with F1: {best_f1:.4f}")

    # 保存到meta
    meta_path = settings.CONFIDENCE_META_PATH
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            meta = json.load(f)
    else:
        meta = {}

    meta['tuned_threshold'] = float(best_th)
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)

    log.info(f"✅ Tuned threshold saved to {meta_path}")


if __name__ == "__main__":
    app()