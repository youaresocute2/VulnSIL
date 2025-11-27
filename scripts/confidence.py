import json
import os
from typing import Any, Dict, List, Sequence

import joblib
import lightgbm as lgb
import numpy as np
import typer
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_curve, roc_auc_score

import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
sys.path.append(PROJECT_ROOT)

from config import settings  # noqa: E402
from vulnsil.database import Base, get_db_session  # noqa: E402
from vulnsil.models import Vulnerability  # noqa: E402
from vulnsil.utils_log import setup_logging  # noqa: E402
from sqlalchemy import Column, Float, Integer, String, Text  # noqa: E402

log = setup_logging("train_calibrator")

FEATURE_ORDER: Sequence[str] = (
    "llm_confidence",
    "llm_pred",
    "has_flow",
    "complexity",
    "api_count",
    "ast_has_dangerous",
    "graph_density",
    "rag_top1_similarity",
    "rag_mean_similarity",
    "rag_std_similarity",
    "rag_positive_ratio",
    "rag_support_agreement",
    "conflict_disagree",
    "rag_vote_margin",
    "api_per_complexity",
)


class Prediction(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, index=True, nullable=False)
    dataset = Column(String, index=True, nullable=False)
    llm_pred = Column(Integer, nullable=False)
    llm_conf = Column(Float, nullable=False)
    calibrated_conf = Column(Float, nullable=False)
    final_pred = Column(Integer, nullable=False)
    rag_result_json = Column(Text, nullable=False)
    feature_json = Column(Text, nullable=False)


def find_best_threshold_f1(y_true: np.ndarray, y_probs: np.ndarray) -> float:
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_probs)
    numerator = 2 * (precisions * recalls)
    denominator = precisions + recalls + 1e-10
    f1_scores = numerator / denominator
    best_idx = np.argmax(f1_scores)
    return float(thresholds[best_idx]) if best_idx < len(thresholds) else 0.5


def _extract_features(feature_json: str) -> Dict[str, float]:
    try:
        payload = json.loads(feature_json)
    except json.JSONDecodeError:
        payload = {}
    return {k: float(payload.get(k, 0.0)) for k in FEATURE_ORDER}


app = typer.Typer()


@app.command()
def train(dataset_prefix: str = typer.Option(..., help="Dataset prefix stored in predictions.dataset")) -> None:
    X: List[List[float]] = []
    y: List[int] = []

    with get_db_session() as session:
        records = (
            session.query(Prediction, Vulnerability)
            .join(Vulnerability, Vulnerability.name == Prediction.name)
            .filter(Prediction.dataset.like(f"{dataset_prefix}%"))
            .all()
        )

        if not records:
            log.error("No prediction records found for training.")
            return

        for pred, vuln in records:
            features = _extract_features(pred.feature_json)
            X.append([features.get(k, 0.0) for k in FEATURE_ORDER])
            y.append(1 if vuln.ground_truth_label == 1 else 0)

    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y, dtype=int)

    if settings.PCA_N_COMPONENTS < X_arr.shape[1]:
        # simple PCA using numpy SVD for compatibility
        mean = np.mean(X_arr, axis=0)
        X_centered = X_arr - mean
        U, S, Vt = np.linalg.svd(X_centered, full_matrices=False)
        components = Vt[: settings.PCA_N_COMPONENTS]
        X_reduced = np.dot(X_centered, components.T)
        pca_model = {"mean": mean, "components": components}

        def _pca_transform(arr: np.ndarray) -> np.ndarray:
            return np.dot(arr - mean, components.T)

    else:
        X_reduced = X_arr
        pca_model = None

        def _pca_transform(arr: np.ndarray) -> np.ndarray:
            return arr

    X_train, X_val, y_train, y_val = train_test_split(X_reduced, y_arr, test_size=0.2, random_state=42, stratify=y_arr)

    params = {
        "objective": "binary",
        "metric": "auc",
        "learning_rate": 0.05,
        "num_leaves": 31,
        "max_depth": -1,
        "verbose": -1,
    }

    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)

    model = lgb.train(
        params,
        train_data,
        num_boost_round=400,
        valid_sets=[train_data, val_data],
        valid_names=["train", "valid"],
        callbacks=[lgb.early_stopping(stopping_rounds=50, verbose=False)],
    )

    val_probs = model.predict(X_val)
    best_th = find_best_threshold_f1(y_val, val_probs)
    val_auc = roc_auc_score(y_val, val_probs)

    models_dir = os.path.join(PROJECT_ROOT, "models")
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(model, os.path.join(models_dir, "confidence_model.pkl"))
    if pca_model is not None:
        joblib.dump(pca_model, os.path.join(models_dir, "pca.pkl"))

    meta = {
        "best_threshold": float(best_th),
        "feature_order": list(FEATURE_ORDER),
        "val_auc": float(val_auc),
        "dataset_prefix": dataset_prefix,
    }
    with open(os.path.join(models_dir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    log.info("Training complete. AUC=%.4f Threshold=%.4f", val_auc, best_th)


if __name__ == "__main__":
    app()
