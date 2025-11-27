import json
import logging
import os
from typing import Any, Dict, List, Sequence, Tuple

import joblib
import numpy as np
import typer
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from tqdm import tqdm

import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
sys.path.append(PROJECT_ROOT)

from config import settings  # noqa: E402
from prompts import build_vuln_prompt  # noqa: E402
from vulnsil.core.llm.service import LLMService  # noqa: E402
from vulnsil.core.retrieval.rag_client import RAGClient  # noqa: E402
from vulnsil.database import Base, engine, get_db_session  # noqa: E402
from vulnsil.models import StaticAnalysisCache, Vulnerability  # noqa: E402
from vulnsil.schemas import KnowledgeBaseEntry  # noqa: E402
from vulnsil.utils_log import setup_logging  # noqa: E402

app = typer.Typer()
logger = setup_logging("run_pipeline")

DEFAULT_FEATURE_ORDER: Sequence[str] = (
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
    created_at = Column(DateTime(timezone=True), server_default=func.now())


Base.metadata.create_all(bind=engine)


def _load_static_features(cache: StaticAnalysisCache) -> Dict[str, Any]:
    try:
        payload = json.loads(cache.feature_json or "{}")
    except json.JSONDecodeError:
        payload = {}
    apis = payload.get("apis", [])
    api_count = payload.get("api_count")
    if api_count is None:
        api_count = len(apis) if isinstance(apis, list) else 0
    graph_density = payload.get("graph_density", payload.get("graphDensity", 0.0))
    return {
        "has_flow": bool(payload.get("has_flow", False)),
        "complexity": int(payload.get("complexity", 0)),
        "api_count": int(api_count),
        "ast_has_dangerous": bool(payload.get("ast_has_dangerous", False)),
        "graph_density": float(graph_density or 0.0),
        "apis": apis if isinstance(apis, list) else [],
    }


def _compute_rag_features(rag_entries: List[KnowledgeBaseEntry]) -> Dict[str, Any]:
    similarities = [float(e.similarity_score or 0.0) for e in rag_entries]
    labels = [int(e.label) if e.label is not None else 0 for e in rag_entries]
    k = len(rag_entries)
    top1_similarity = similarities[0] if similarities else 0.0
    mean_similarity = float(np.mean(similarities)) if similarities else 0.0
    std_similarity = float(np.std(similarities)) if similarities else 0.0
    positive_count = sum(1 for l in labels if l == 1)
    positive_ratio = float(positive_count / k) if k else 0.0
    support_agreement = 1 if positive_count > k / 2 else 0
    vote_margin = float((positive_count - (k - positive_count)) / k) if k else 0.0
    return {
        "rag_top1_similarity": top1_similarity,
        "rag_mean_similarity": mean_similarity,
        "rag_std_similarity": std_similarity,
        "rag_positive_ratio": positive_ratio,
        "rag_support_agreement": support_agreement,
        "rag_vote_margin": vote_margin,
        "rag_labels": labels,
    }


def _build_features(llm_confidence: float, llm_pred: int, static_feat: Dict[str, Any], rag_feat: Dict[str, Any]) -> Dict[str, Any]:
    has_flow = int(static_feat.get("has_flow", False))
    complexity = int(static_feat.get("complexity", 0))
    api_count = int(static_feat.get("api_count", 0))
    ast_has_dangerous = int(static_feat.get("ast_has_dangerous", False))
    graph_density = float(static_feat.get("graph_density", 0.0))
    rag_support = int(rag_feat.get("rag_support_agreement", 0))
    conflict_disagree = 1 if ((llm_pred == 1 and rag_support == 0) or (llm_pred == 0 and rag_support == 1)) else 0
    api_per_complexity = float(api_count / complexity) if complexity else float(api_count)

    return {
        "llm_confidence": float(llm_confidence),
        "llm_pred": int(llm_pred),
        "has_flow": has_flow,
        "complexity": complexity,
        "api_count": api_count,
        "ast_has_dangerous": ast_has_dangerous,
        "graph_density": graph_density,
        "rag_top1_similarity": float(rag_feat.get("rag_top1_similarity", 0.0)),
        "rag_mean_similarity": float(rag_feat.get("rag_mean_similarity", 0.0)),
        "rag_std_similarity": float(rag_feat.get("rag_std_similarity", 0.0)),
        "rag_positive_ratio": float(rag_feat.get("rag_positive_ratio", 0.0)),
        "rag_support_agreement": rag_support,
        "conflict_disagree": conflict_disagree,
        "rag_vote_margin": float(rag_feat.get("rag_vote_margin", 0.0)),
        "api_per_complexity": api_per_complexity,
    }


def _features_to_array(feature_dict: Dict[str, Any], feature_order: Sequence[str], pca_model: Any | None = None) -> np.ndarray:
    values = [float(feature_dict.get(key, 0.0)) for key in feature_order]
    arr = np.array(values, dtype=float).reshape(1, -1)
    if pca_model is not None:
        try:
            if hasattr(pca_model, "transform"):
                arr = pca_model.transform(arr)
            elif isinstance(pca_model, dict) and "mean" in pca_model and "components" in pca_model:
                mean = np.array(pca_model["mean"])
                components = np.array(pca_model["components"])
                arr = np.dot(arr - mean, components.T)
        except Exception as exc:  # pragma: no cover
            logger.error("PCA transform failed: %s", exc)
    return arr


def _load_confidence_model() -> Tuple[Any, Any | None, float, Sequence[str]]:
    model_path = os.path.join(PROJECT_ROOT, "models", "confidence_model.pkl")
    pca_path = os.path.join(PROJECT_ROOT, "models", "pca.pkl")
    meta_path = os.path.join(PROJECT_ROOT, "models", "meta.json")

    model = None
    pca_model = None
    threshold = settings.CALIBRATION_THRESHOLD
    feature_order: Sequence[str] = DEFAULT_FEATURE_ORDER

    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r") as f:
                meta = json.load(f)
                threshold = float(meta.get("best_threshold", threshold))
                if "feature_order" in meta:
                    feature_order = tuple(meta["feature_order"])
        except Exception as exc:
            logger.error("Failed to load meta.json: %s", exc)

    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            logger.info("Loaded confidence model from %s", model_path)
        except Exception as exc:
            logger.error("Failed to load confidence model: %s", exc)
    if os.path.exists(pca_path):
        try:
            pca_model = joblib.load(pca_path)
            logger.info("Loaded PCA model from %s", pca_path)
        except Exception as exc:
            logger.error("Failed to load PCA model: %s", exc)

    if model is None:
        class _FallbackModel:
            def predict(self, X: np.ndarray) -> np.ndarray:
                return np.array([min(1.0, max(0.0, float(X[0][0])))] * X.shape[0])

            def predict_proba(self, X: np.ndarray) -> np.ndarray:
                preds = self.predict(X)
                return np.vstack([1 - preds, preds]).T

        model = _FallbackModel()
        logger.warning("Using fallback confidence model.")

    return model, pca_model, threshold, feature_order


def _predict_confidence(model: Any, feature_array: np.ndarray) -> float:
    try:
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(feature_array)
            if proba.ndim == 2 and proba.shape[1] > 1:
                return float(proba[0][1])
            return float(proba[0][0]) if proba.ndim == 2 else float(proba[0])
        pred = model.predict(feature_array)
        return float(pred[0])
    except Exception as exc:  # pragma: no cover
        logger.error("Confidence prediction failed: %s", exc)
        return float(feature_array[0][0])


def _persist_prediction(
    session: Session,
    dataset: str,
    name: str,
    llm_pred: int,
    llm_conf: float,
    calibrated_conf: float,
    final_pred: int,
    rag_entries: List[KnowledgeBaseEntry],
    feature_dict: Dict[str, Any],
):
    record = Prediction(
        dataset=dataset,
        name=name,
        llm_pred=llm_pred,
        llm_conf=llm_conf,
        calibrated_conf=calibrated_conf,
        final_pred=final_pred,
        rag_result_json=json.dumps([entry.model_dump() for entry in rag_entries]),
        feature_json=json.dumps(feature_dict),
    )
    session.add(record)


def _process_single(
    session: Session,
    rag_client: RAGClient,
    llm_service: LLMService,
    model: Any,
    pca_model: Any | None,
    threshold: float,
    feature_order: Sequence[str],
    vuln: Vulnerability,
    cache: StaticAnalysisCache,
    dataset: str,
) -> None:
    static_feat = _load_static_features(cache)
    rag_entries = rag_client.search(vuln.code or "", top_k=settings.RAG_TOP_K)
    prompt = build_vuln_prompt(code=vuln.code or "", static_features=static_feat, rag_entries=rag_entries, meta={"dataset": dataset})

    llm_result = llm_service.analyze(prompt)
    llm_pred = 1 if llm_result.is_vulnerable else 0
    llm_confidence = float(llm_result.confidence)

    rag_features = _compute_rag_features(rag_entries)
    feature_dict = _build_features(llm_confidence, llm_pred, static_feat, rag_features)
    feature_array = _features_to_array(feature_dict, feature_order, pca_model)

    calibrated_conf = _predict_confidence(model, feature_array)
    final_pred = 1 if calibrated_conf >= threshold else 0

    _persist_prediction(
        session=session,
        dataset=dataset,
        name=vuln.name,
        llm_pred=llm_pred,
        llm_conf=llm_confidence,
        calibrated_conf=calibrated_conf,
        final_pred=final_pred,
        rag_entries=rag_entries,
        feature_dict=feature_dict,
    )


def _fetch_static_cache_map(session: Session, names: List[str]) -> Dict[str, StaticAnalysisCache]:
    caches = session.query(StaticAnalysisCache).filter(StaticAnalysisCache.task_name.in_(names)).all()
    return {c.task_name: c for c in caches}


@app.command()
def run(
    split_name: str = typer.Option(..., "--split-name", help="Dataset split prefix, e.g., diversevul_test"),
    limit: int = typer.Option(None, "--limit", help="Optional limit for number of samples"),
    batch_size: int = typer.Option(8, "--batch-size", help="Batch size for iteration"),
):
    logger.info("Starting vulnerability analysis pipeline")
    model, pca_model, threshold, feature_order = _load_confidence_model()
    rag_client = RAGClient()
    llm_service = LLMService()

    with get_db_session() as session:
        query = (
            session.query(Vulnerability)
            .filter(Vulnerability.name.like(f"{split_name}%"))
            .order_by(Vulnerability.id.asc())
        )
        if limit:
            query = query.limit(limit)
        vulnerabilities = query.all()

    if not vulnerabilities:
        logger.warning("No vulnerabilities found for the given split.")
        return

    names = [v.name for v in vulnerabilities]
    with get_db_session() as session:
        cache_map = _fetch_static_cache_map(session, names)

    with get_db_session() as session:
        for idx in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[idx : idx + batch_size]
            for vuln in tqdm(batch, desc="Processing", unit="sample"):
                cache = cache_map.get(vuln.name)
                if cache is None:
                    logger.warning("Missing static cache for %s, skipping.", vuln.name)
                    continue
                try:
                    _process_single(session, rag_client, llm_service, model, pca_model, threshold, feature_order, vuln, cache, split_name)
                    session.commit()
                except SQLAlchemyError as exc:
                    session.rollback()
                    logger.error("Database error on %s: %s", vuln.name, exc)
                except Exception as exc:  # pragma: no cover
                    session.rollback()
                    logger.error("Failed to process %s: %s", vuln.name, exc)

    logger.info("Pipeline finished.")


if __name__ == "__main__":
    app()
