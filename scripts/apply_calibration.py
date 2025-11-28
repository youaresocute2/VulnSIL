# scripts/apply_calibration.py
import sys
import os
import json
import numpy as np
from tqdm import tqdm
import typer

# 路径适配
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings, init_runtime

from vulnsil.database import get_db_session
from vulnsil.models import Prediction, Vulnerability
from vulnsil.utils_log import setup_logging
from vulnsil.core.confidence import ConfidenceModel

app = typer.Typer()
log = setup_logging("apply_calibration")


@app.command()
def apply(split_name: str = typer.Option(..., help="Target dataset split to update")):
    """
    Load the trained LightGBM model and UPDATE the 'calibrated_confidence'
    field in the database for the specified split.
    """
    init_runtime()

    # 1. 加载模型
    if not os.path.exists(settings.CONFIDENCE_MODEL_PATH):
        log.error(f"❌ Model not found at {settings.CONFIDENCE_MODEL_PATH}. Train it first!")
        return

    log.info(f"♻️ Loading model from {settings.CONFIDENCE_MODEL_PATH}...")
    conf_model = ConfidenceModel()

    updated_count = 0

    with get_db_session() as db:
        # 2. 查询数据
        records = db.query(Prediction).join(Vulnerability).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status == "Success"
        ).all()

        if not records:
            log.error("No records found.")
            return

        log.info(f"🔄 Re-calculating scores for {len(records)} records...")

        update_mappings = []
        feature_names = conf_model.get_feature_names()

        for rec in records:
            feat_dict = {}
            if rec.feature_json:
                try:
                    feat_dict = json.loads(rec.feature_json)
                except Exception:
                    feat_dict = {}

            vector = np.array([float(feat_dict.get(name, 0.0)) for name in feature_names], dtype=np.float32)
            calib_conf, _ = conf_model.predict(vector)
            update_mappings.append({"id": rec.id, "calibrated_confidence": float(calib_conf)})

        log.info("💾 Committing updates to database...")
        db.bulk_update_mappings(Prediction, update_mappings)
        updated_count = len(update_mappings)

    log.info(f"✅ Successfully updated {updated_count} records.")
    print(f"\n🎉 Calibration Applied! Now run: python scripts/evaluate.py --split-name {split_name}")


if __name__ == "__main__":
    app()