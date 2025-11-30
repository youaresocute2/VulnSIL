# scripts/apply_calibration.py
import sys
import os
import joblib
import numpy as np
import pandas as pd
import json
from tqdm import tqdm
import typer

# 路径适配
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings, ML_FEATURE_NAMES  # [Fix I] Import feature defs
from vulnsil.database import get_db_session
from vulnsil.models import AnalysisResultRecord, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("apply_calibration")


@app.command()
def apply(split_name: str = typer.Option(..., help="Target dataset split to update")):
    """
    Load the trained model and UPDATE 'calibrated_confidence' for a split.
    Updated for 15-Dimensional feature vectors with Alignment & Numerical Safety.
    """
    # 1. 加载模型
    if not os.path.exists(settings.CONFIDENCE_MODEL_PATH):
        log.error(f"❌ Model not found at {settings.CONFIDENCE_MODEL_PATH}. Train it first!")
        return

    log.info(f"♻️ Loading model from {settings.CONFIDENCE_MODEL_PATH}...")
    try:
        model = joblib.load(settings.CONFIDENCE_MODEL_PATH)
    except Exception as e:
        log.error(f"Failed to load model: {e}")
        return

    updated_count = 0

    with get_db_session() as db:
        # 2. 查询数据
        records = db.query(AnalysisResultRecord).join(Vulnerability).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status == "Success"
        ).all()

        if not records:
            log.error("No records found.")
            return

        log.info(f"🔄 Re-calculating scores for {len(records)} records...")

        batch_features = []
        batch_ids = []

        for rec in tqdm(records, desc="Feature Extract"):
            # Feature extraction MUST align with config.ML_FEATURE_NAMES
            w_conflict = float(rec.feat_conflict_disagreement or 0.0)

            # [Fix I] Dict construction ensures alignment regardless of Config order changes
            # Convert bools to floats strictly
            f_map = {
                "llm_native_conf": float(rec.native_confidence or 0.5),
                "static_has_flow": 1.0 if rec.static_has_flow else 0.0,
                "static_complexity": float(rec.static_complexity or 0),
                "static_apis_count": float(rec.feat_static_apis_count or 0),
                "static_risk_density": float(rec.feat_static_risk_density or 0.0),
                "static_graph_density": float(rec.feat_static_graph_density or 0.0),
                "source_type": float(rec.feat_static_source_type or 0),
                "code_len_log": np.log1p(float(rec.feat_code_len or 0)),
                "is_compressed": 1.0 if rec.feat_is_compressed else 0.0,
                "rag_sim_avg": float(rec.feature_rag_similarity or 0.0),
                "rag_top1_sim": float(rec.feat_rag_top1_sim or 0.0),
                "rag_var": float(rec.feat_rag_sim_variance or 0.0),
                "conflict_disagree_weighted": float(w_conflict),
                "conflict_special": float(rec.feat_conflict_static_yes_llm_no or 0),
                "llm_entropy": float(rec.feat_llm_uncertainty or 0.0)
            }

            # Map using global keys definition
            # Use .get(k, 0.0) to safeguard against Schema updates missing older DB records
            feats = [f_map.get(name, 0.0) for name in ML_FEATURE_NAMES]

            batch_features.append(feats)
            batch_ids.append(rec.id)

        # 4. 模型推理 (使用 DataFrame 以支持 Pipeline 可能需要的列名)
        X = pd.DataFrame(batch_features, columns=ML_FEATURE_NAMES)

        # [Fix I] Verification
        if list(X.columns) != ML_FEATURE_NAMES:
            log.critical("FATAL: Feature Alignment Mismatch! Aborting.")
            return

        # [Fix IV] Numerical Stability Guard
        # Pipeline output might contain None or Infs, clean before inference
        X_values = X.values
        X_values = np.nan_to_num(X_values, nan=0.0, posinf=1.0, neginf=-1.0)
        X = pd.DataFrame(X_values, columns=ML_FEATURE_NAMES)

        # 获取属于类别 1 (Vulnerable) 的概率
        try:
            new_scores = model.predict_proba(X)[:, 1]
        except Exception as e:
            log.error(f"Inference Prediction Error: {e}")
            return

        # 5. 写回数据库
        update_mappings = []
        for rid, score in zip(batch_ids, new_scores):
            update_mappings.append({"id": rid, "calibrated_confidence": float(score)})

        log.info("💾 Committing updates to database...")
        db.bulk_update_mappings(AnalysisResultRecord, update_mappings)
        updated_count = len(update_mappings)

    log.info(f"✅ Successfully updated {updated_count} records.")
    print(f"\n🎉 Calibration Applied! Now run: python scripts/evaluate.py --split-name {split_name}")


if __name__ == "__main__":
    app()