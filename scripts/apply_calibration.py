# scripts/apply_calibration.py
import sys
import os
import joblib
import numpy as np
import json
from tqdm import tqdm
import typer

# 路径适配
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
from vulnsil.database import get_db_session
from vulnsil.models import AnalysisResultRecord, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("apply_calibration")


@app.command()
def apply(split_name: str = typer.Option(..., help="Target dataset split to update")):
    """
    Load the trained LightGBM model and UPDATE the 'calibrated_confidence'
    field in the database for the specified split.
    """
    # 1. 加载模型
    if not os.path.exists(settings.CONFIDENCE_MODEL_PATH):
        log.error(f"❌ Model not found at {settings.CONFIDENCE_MODEL_PATH}. Train it first!")
        return

    log.info(f"♻️ Loading model from {settings.CONFIDENCE_MODEL_PATH}...")
    model = joblib.load(settings.CONFIDENCE_MODEL_PATH)

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

        # 3. 批量重算
        # 注意：特征顺序必须与训练时(confidence.py)完全一致
        batch_features = []
        batch_ids = []

        for rec in records:
            code_len = float(rec.feat_code_len or 0)
            log_len = np.log1p(code_len)

            feats = [
                float(rec.native_confidence or 0.5),  # 1. llm_native_conf
                1.0 if rec.static_has_flow else 0.0,  # 2. static_has_flow
                float(rec.static_complexity or 0),  # 3. static_complexity
                float(rec.feat_static_apis_count or 0),  # 4. static_apis_count
                float(rec.feat_static_source_type or 0),  # 5. source_type
                log_len,  # 6. code_len_log
                1.0 if rec.feat_is_compressed else 0.0,  # 7. is_compressed
                float(rec.feature_rag_similarity or 0.0),  # 8. rag_sim_avg
                float(rec.feat_rag_top1_sim or 0.0),  # 9. rag_top1_sim
                float(rec.feat_rag_sim_variance or 0.0),  # 10. rag_var
                float(rec.feat_conflict_disagreement or 0),  # 11. conflict_disagree
                float(rec.feat_conflict_static_yes_llm_no or 0)  # 12. conflict_special
            ]
            batch_features.append(feats)
            batch_ids.append(rec.id)

        # 4. 模型推理
        X = np.array(batch_features)
        # 获取属于类别 1 (Vulnerable) 的概率
        new_scores = model.predict_proba(X)[:, 1]

        # 5. 写回数据库
        # 为了速度，使用 mappings 更新
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