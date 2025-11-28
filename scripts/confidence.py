# scripts/confidence.py
import sys
import os
import joblib
import json
import numpy as np
import pandas as pd
import typer
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, precision_recall_curve

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings, init_runtime

init_runtime()

from vulnsil.database import get_db_session
from vulnsil.models import Prediction, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("train_calibrator")

# [更新] 特征列表来源于配置，训练/推理保持一致
FEATURE_NAMES = settings.DEFAULT_FEATURE_ORDER

def custom_pca(X, n_components):
    """用numpy SVD实现PCA（环境兼容）"""
    mean = np.mean(X, axis=0)
    X_centered = X - mean
    U, S, Vt = np.linalg.svd(X_centered, full_matrices=False)
    components = Vt[:n_components]
    X_reduced = np.dot(X_centered, components.T)
    return X_reduced

def find_best_threshold_f1(y_true, y_probs):
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_probs)
    numerator = 2 * (precisions * recalls)
    denominator = precisions + recalls + 1e-10
    f1_scores = numerator / denominator
    best_idx = np.argmax(f1_scores)
    best_th = thresholds[best_idx] if best_idx < len(thresholds) else 0.5
    return best_th, f1_scores[best_idx], precisions[best_idx], recalls[best_idx]

@app.command()
def train(split_name: str = typer.Option(..., help="Dataset prefix (e.g., 'confidence_train')")):
    X, y = [], []

    with get_db_session() as db:
        records = db.query(Prediction).join(Vulnerability).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status == "Success"
        ).all()

        if not records:
            log.error("No data for training.")
            return

        for r in records:
            feat_dict = {}
            if r.feature_json:
                try:
                    feat_dict = json.loads(r.feature_json)
                except Exception:
                    feat_dict = {}

            features = [float(feat_dict.get(name, 0.0)) for name in settings.DEFAULT_FEATURE_ORDER]
            label = 1 if r.vuln.ground_truth_label == 1 else 0
            X.append(features)
            y.append(label)

    if not X:
        log.error("No valid data.")
        return

    X = np.array(X)
    y = np.array(y)

    # [改进] PCA降维（用custom_pca）
    if settings.PCA_N_COMPONENTS < X.shape[1]:
        X = custom_pca(X, settings.PCA_N_COMPONENTS)

    # [改进] 客观防泄露：计算统计阈值
    rag_sims = X[:, 9]  # feat_rag_top1_sim index
    sim_th = np.mean(rag_sims) + 3 * np.std(rag_sims)
    X[:, 9] = np.where(X[:, 9] > sim_th, 0.8, X[:, 9])

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    params = {
        'objective': 'binary',
        'metric': 'auc',
        'verbose': 1,
        'learning_rate': 0.05,
        'num_leaves': 31,
        'max_depth': -1,
    }

    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)

    callbacks = [
        lgb.early_stopping(stopping_rounds=50, verbose=True),
        lgb.log_evaluation(period=100)
    ]

    model = lgb.train(
        params,
        train_data,
        num_boost_round=1000,
        valid_sets=[train_data, val_data],
        valid_names=['train', 'valid'],
        callbacks=callbacks
    )

    y_prob_val = model.predict(X_val)
    best_th, best_f1, prec_at_best, recall_at_best = find_best_threshold_f1(y_val, y_prob_val)
    val_auc = roc_auc_score(y_val, y_prob_val)

    print("\n" + "=" * 60)
    print(" 🚀 CALIBRATION MODEL PERFORMANCE REPORT")
    print("=" * 60)
    print(f"Dataset Size     : Train={len(y_train)}, Val={len(y_val)}")
    print(f"Validation AUC   : {val_auc:.4f} (Robustness Metric)")
    print("-" * 60)
    print(f"✅ Optimal Threshold : {best_th:.4f} (Decision Boundary)")
    print(f"🎯 Max F1-Score      : {best_f1:.4f}")
    print(f"   Corresponding P   : {prec_at_best:.4f}")
    print(f"   Corresponding R   : {recall_at_best:.4f}")
    print("-" * 60)

    print("\n📊 Feature Importance (Gain):")
    importance = model.feature_importance(importance_type='gain')
    if sum(importance) > 0:
        importance = importance / sum(importance) * 100

    indices = np.argsort(importance)[::-1]
    for i in indices:
        print(f"   {FEATURE_NAMES[i]:<30}: {importance[i]:6.2f}%")

    model_dir = os.path.dirname(settings.CONFIDENCE_MODEL_PATH)
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(model, settings.CONFIDENCE_MODEL_PATH)

    meta_path = settings.CONFIDENCE_META_PATH
    meta_data = {
        "best_threshold": float(best_th),
        "best_f1": float(best_f1),
        "auc": float(val_auc),
        "train_info": f"Split: {split_name}, Samples: {len(X)}",
        "feature_names": settings.DEFAULT_FEATURE_ORDER
    }
    with open(meta_path, "w") as f:
        json.dump(meta_data, f, indent=2)

    print(f"\n✅ Model saved to: {settings.CONFIDENCE_MODEL_PATH}")
    print(f"✅ Threshold info saved to: {meta_path}")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    app()