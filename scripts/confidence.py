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
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# [Fix I] Import feature names
from config import settings, ML_FEATURE_NAMES
from vulnsil.database import get_db_session
from vulnsil.models import AnalysisResultRecord, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("train_calibrator")


class NumpyPCA(BaseEstimator, TransformerMixin):
    """
    [PCA] Standard dimensionality reduction using SVD.
    Keeps feature space compact for robustness.
    [Fix VII] Enhanced Numerical Stability
    """

    def __init__(self, n_components=10):
        self.n_components = n_components
        self.mean_ = None
        self.components_ = None

    def fit(self, X, y=None):
        if hasattr(X, 'values'): X = X.values

        # [Fix VII] Robust check
        if X.shape[0] == 0:
            return self

        X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=-1.0)
        self.mean_ = np.mean(X, axis=0)
        X_centered = X - self.mean_

        # [Fix VII] Safety against full-zero matrices
        if np.all(X_centered == 0):
            self.components_ = np.zeros((self.n_components, X.shape[1]))
        else:
            u, s, vt = np.linalg.svd(X_centered, full_matrices=False)
            self.components_ = vt[:self.n_components]
        return self

    def transform(self, X):
        if hasattr(X, 'values'): X = X.values
        X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=-1.0)
        return np.dot(X - self.mean_, self.components_.T)


def statistical_guardrails(X_df):
    """
    [Stat Check] Leakage Prevention: Cap extremely high RAG similarities.
    Target feature index 10: 'rag_top1_sim'
    """
    target = "rag_top1_sim"
    if target in X_df.columns:
        vals = X_df[target].values
        mu, sigma = np.mean(vals), np.std(vals)
        th = mu + 3 * sigma
        X_df[target] = np.where(vals > th, 0.8, vals)
        print(f"   [Guardrail] Anti-Leakage {target} Cap at {th:.3f}")
    return X_df


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
        records = db.query(AnalysisResultRecord).join(Vulnerability).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status == "Success"
        ).all()

        if not records:
            log.error(f"❌ No data found for split '{split_name}'.")
            return

        log.info(f"📚 Extracting 15-Dim features from {len(records)} samples...")

        for rec in records:
            # Feature Map Construction first
            # [Fix I] Construct dictionary first
            f_map = {
                "llm_native_conf": float(rec.native_confidence or 0.5),
                "static_has_flow": 1.0 if rec.static_has_flow else 0.0,
                "static_complexity": float(rec.static_complexity or 0),
                "static_apis_count": float(rec.feat_static_apis_count or 0),
                "static_risk_density": float(rec.feat_static_risk_density or 0.0),
                "static_graph_density": float(rec.feat_static_graph_density or 0.0),  # [New]
                "source_type": float(rec.feat_static_source_type or 0),
                "code_len_log": np.log1p(float(rec.feat_code_len or 0)),
                "is_compressed": 1.0 if rec.feat_is_compressed else 0.0,
                "rag_sim_avg": float(rec.feature_rag_similarity or 0.0),
                "rag_top1_sim": float(rec.feat_rag_top1_sim or 0.0),
                "rag_var": float(rec.feat_rag_sim_variance or 0.0),
                "conflict_disagree_weighted": float(rec.feat_conflict_disagreement or 0.0),
                "conflict_special": float(rec.feat_conflict_static_yes_llm_no or 0),
                "llm_entropy": float(rec.feat_llm_uncertainty or 0.0)
            }

            # Map Dict to Ordered List based on ML_FEATURE_NAMES
            feats = [f_map[name] for name in ML_FEATURE_NAMES]
            X.append(feats)
            y.append(rec.vuln.ground_truth_label)

    # Use DataFrame to work with names inside logic
    try:
        X_df = pd.DataFrame(X, columns=ML_FEATURE_NAMES)
    except ValueError as e:
        log.error(f"FATAL: Dimension Mismatch constructing DataFrame. {e}")
        return

    # [Fix I] Critical assertion for order
    assert list(X_df.columns) == ML_FEATURE_NAMES, \
        f"FATAL: Column Mismatch! Config definition does not match training dataframe structure."

    y = np.array(y)

    pos_count = np.sum(y == 1)
    neg_count = np.sum(y == 0)
    log.info(f"📊 Class Distribution: Vuln(1)={pos_count}, Safe(0)={neg_count}")

    if len(X) < 100:
        log.error("❌ Not enough data to train. Need at least 100 samples.")
        return

    # Apply Guardrails
    X_clean = statistical_guardrails(X_df)

    X_train, X_val, y_train, y_val = train_test_split(X_clean, y, test_size=0.2, random_state=42, stratify=y)

    log.info("🔥 Training Pipeline (Scaler -> PCA -> LGBM)...")

    model = Pipeline([
        ('scaler', StandardScaler()),
        ('pca', NumpyPCA(n_components=10)),
        ('clf', lgb.LGBMClassifier(
            n_estimators=1000,
            learning_rate=0.03,
            max_depth=6,
            num_leaves=31,
            objective='binary',
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
            metric=['auc', 'average_precision']
        ))
    ])

    callbacks = [
        lgb.early_stopping(stopping_rounds=50, verbose=False),
        lgb.log_evaluation(period=100)
    ]

    model.fit(
        X_train, y_train,
        clf__eval_set=[(model[:-1].transform(X_val), y_val)],
        clf__eval_names=['valid'],
        clf__callbacks=callbacks
    )

    y_prob_val = model.predict_proba(X_val)[:, 1]
    best_th, best_f1, prec_at_best, recall_at_best = find_best_threshold_f1(y_val, y_prob_val)
    val_auc = roc_auc_score(y_val, y_prob_val)

    print("\n" + "=" * 60)
    print(" 🚀 CALIBRATION MODEL PERFORMANCE REPORT")
    print("=" * 60)
    print(f"Validation AUC   : {val_auc:.4f}")
    print("-" * 60)
    print(f"✅ Optimal Threshold : {best_th:.4f}")
    print(f"🎯 Max F1-Score      : {best_f1:.4f}")
    print(f"   Precision         : {prec_at_best:.4f}")
    print(f"   Recall            : {recall_at_best:.4f}")
    print("=" * 60 + "\n")

    os.makedirs(os.path.dirname(settings.CONFIDENCE_MODEL_PATH), exist_ok=True)
    joblib.dump(model, settings.CONFIDENCE_MODEL_PATH)

    meta_path = settings.CONFIDENCE_META_PATH
    meta_data = {
        "best_threshold": float(best_th),
        "best_f1": float(best_f1),
        "auc": float(val_auc),
        "features": ML_FEATURE_NAMES
    }
    with open(meta_path, "w") as f:
        json.dump(meta_data, f, indent=2)

    print(f"✅ Saved model & meta to {settings.RESULTS_DIR}/confidence/")


if __name__ == "__main__":
    app()