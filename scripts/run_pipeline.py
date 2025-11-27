import json
import logging
import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

import joblib
import numpy as np
import typer
from sqlalchemy import Column, DateTime, Float, Integer, String, Text, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from tqdm import tqdm

# Ensure local packages are importable when running as a script
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
sys.path.append(PROJECT_ROOT)

from config import settings  # noqa: E402
from vulnsil.core.llm.prompts import PromptManager  # noqa: E402
from vulnsil.core.llm.vllm_client import VLLMClient  # noqa: E402
from vulnsil.core.retrieval.hybrid_search import HybridRetriever  # noqa: E402
from vulnsil.database import Base, SessionLocal, engine, get_db_session  # noqa: E402
from vulnsil.models import StaticAnalysisCache, Vulnerability  # noqa: E402
from vulnsil.schemas import KnowledgeBaseEntry  # noqa: E402
from vulnsil.utils_log import setup_logging  # noqa: E402

app = typer.Typer()
logger = setup_logging("run_pipeline")


class Prediction(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, index=True, nullable=False)
    llm_pred = Column(Integer, nullable=False)
    llm_conf = Column(Float, nullable=False)
    calibrated_conf = Column(Float, nullable=False)
    final_pred = Column(Integer, nullable=False)
    rag_result_json = Column(Text, nullable=False)
    feature_json = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


Base.metadata.create_all(bind=engine)

FEATURE_KEYS: Sequence[str] = (
    "llm_confidence",
    "llm_binary_prediction",
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


def _load_static_features(cache: StaticAnalysisCache) -> Dict[str, Any]:
    try:
        payload = json.loads(cache.feature_json or "{}")
    except json.JSONDecodeError:
        payload = {}
    return {
        "has_flow": bool(payload.get("has_flow", False)),
        "complexity": int(payload.get("complexity", 0)),
        "api_count": int(payload.get("api_count", payload.get("apis", []) and len(payload.get("apis", [])) or 0)),
        "ast_has_dangerous": bool(payload.get("ast_has_dangerous", False)),
        "graph_density": float(payload.get("graph_density", 0.0)),
        "apis": payload.get("apis", []) if isinstance(payload.get("apis", []), list) else [],
    }


def _placeholder_retrieve(code: str, top_k: int) -> List[KnowledgeBaseEntry]:
    results: List[KnowledgeBaseEntry] = []
    for _ in range(top_k):
        results.append(
            KnowledgeBaseEntry(
                code="",
                label=0,
                similarity_score=0.0,
                cwe=None,
                project=None,
                commit_id=None,
            )
        )
    return results


def _run_retrieval(retriever: Optional[HybridRetriever], code: str, top_k: int) -> List[KnowledgeBaseEntry]:
    if retriever is None:
        return _placeholder_retrieve(code, top_k)
    try:
        return retriever.search(code, top_k=top_k) or _placeholder_retrieve(code, top_k)
    except Exception as exc:  # pragma: no cover - best effort fallback
        logger.error(f"RAG retrieval failed: {exc}")
        return _placeholder_retrieve(code, top_k)


def _compute_rag_features(rag_entries: List[KnowledgeBaseEntry]) -> Dict[str, Any]:
    similarities = [float(e.similarity_score or 0.0) for e in rag_entries]
    labels = [int(e.label) if e.label is not None else 0 for e in rag_entries]
    k = len(rag_entries) if rag_entries else 0
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
        "rag_similarities": similarities,
    }


def _build_features(
    llm_confidence: float,
    llm_pred: int,
    static_feat: Dict[str, Any],
    rag_feat: Dict[str, Any],
) -> Dict[str, Any]:
    has_flow = int(static_feat.get("has_flow", False))
    complexity = int(static_feat.get("complexity", 0))
    api_count = int(static_feat.get("api_count", 0))
    ast_has_dangerous = int(static_feat.get("ast_has_dangerous", False))
    graph_density = float(static_feat.get("graph_density", 0.0))

    rag_support = int(rag_feat.get("rag_support_agreement", 0))
    conflict_disagree = 1 if ((llm_pred == 1 and rag_support == 0) or (llm_pred == 0 and rag_support == 1)) else 0
    api_per_complexity = float(api_count / complexity) if complexity else float(api_count)

    feature_dict: Dict[str, Any] = {
        "llm_confidence": float(llm_confidence),
        "llm_binary_prediction": int(llm_pred),
        "has_flow": has_flow,
        "complexity": complexity,
        "api_count": api_count,
        "ast_has_dangerous": ast_has_dangerous,
        "graph_density": graph_density,
        "rag_top1_similarity": float(rag_feat.get("rag_top1_similarity", 0.0)),
        "rag_mean_similarity": float(rag_feat.get("rag_mean_similarity", 0.0)),
        "rag_std_similarity": float(rag_feat.get("rag_std_similarity", 0.0)),
        "rag_positive_ratio": float(rag_feat.get("rag_positive_ratio", 0.0)),
        "rag_support_agreement": int(rag_support),
        "conflict_disagree": conflict_disagree,
        "rag_vote_margin": float(rag_feat.get("rag_vote_margin", 0.0)),
        "api_per_complexity": api_per_complexity,
    }
    return feature_dict


def _features_to_array(feature_dict: Dict[str, Any], pca_model: Any = None) -> np.ndarray:
    values = [float(feature_dict.get(key, 0.0)) for key in FEATURE_KEYS]
    arr = np.array(values, dtype=float).reshape(1, -1)
    if pca_model is not None:
        try:
            arr = pca_model.transform(arr)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(f"PCA transform failed: {exc}")
    return arr


def _load_confidence_model() -> Tuple[Any, Any, float]:
    model_path = os.path.join(PROJECT_ROOT, "models", "confidence_model.pkl")
    pca_path = os.path.join(PROJECT_ROOT, "models", "pca.pkl")
    meta_path = os.path.join(PROJECT_ROOT, "models", "meta.json")

    model = None
    pca_model = None
    threshold = settings.CALIBRATION_THRESHOLD

    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            logger.info(f"Loaded confidence model from {model_path}")
        except Exception as exc:
            logger.error(f"Failed to load confidence model: {exc}")
    if os.path.exists(pca_path):
        try:
            pca_model = joblib.load(pca_path)
            logger.info(f"Loaded PCA model from {pca_path}")
        except Exception as exc:
            logger.error(f"Failed to load PCA model: {exc}")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r") as f:
                meta = json.load(f)
                threshold = float(meta.get("best_threshold", threshold))
                logger.info(f"Loaded threshold {threshold} from meta.json")
        except Exception as exc:
            logger.error(f"Failed to load meta.json: {exc}")

    if model is None:
        class _FallbackModel:
            def predict(self, X: np.ndarray) -> np.ndarray:
                return np.array([min(1.0, max(0.0, float(X[0][0])))] * X.shape[0])

            def predict_proba(self, X: np.ndarray) -> np.ndarray:
                preds = self.predict(X)
                return np.vstack([1 - preds, preds]).T

        model = _FallbackModel()
        logger.warning("Using fallback confidence model (identity on llm_confidence).")

    return model, pca_model, threshold


def _predict_confidence(model: Any, feature_array: np.ndarray) -> float:
    try:
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(feature_array)
            if proba.ndim == 2 and proba.shape[1] > 1:
                return float(proba[0][1])
            return float(proba[0][0]) if proba.ndim == 2 else float(proba[0])
        pred = model.predict(feature_array)
        return float(pred[0])
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(f"Confidence prediction failed: {exc}")
        return float(feature_array[0][0])


def _persist_prediction(
    session: Session,
    name: str,
    llm_pred: int,
    llm_conf: float,
    calibrated_conf: float,
    final_pred: int,
    rag_entries: List[KnowledgeBaseEntry],
    feature_dict: Dict[str, Any],
):
    record = Prediction(
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
    retriever: Optional[HybridRetriever],
    model: Any,
    pca_model: Any,
    threshold: float,
    vuln: Vulnerability,
    cache: StaticAnalysisCache,
) -> None:
    static_feat = _load_static_features(cache)
    rag_entries = _run_retrieval(retriever, vuln.code or "", settings.RAG_TOP_K)
    prompt = PromptManager.build_prompt(
        target_code=vuln.code or "",
        rag_entries=rag_entries,
        static_complexity=static_feat.get("complexity", 0),
        static_apis=static_feat.get("apis", []),
        static_has_flow=static_feat.get("has_flow", False),
    )

    llm_client = VLLMClient()
    llm_result, native_confidence = llm_client.generate(prompt, temperature=settings.LLM_TEMPERATURE)
    llm_pred = 1 if llm_result.is_vulnerable else 0

    rag_features = _compute_rag_features(rag_entries)
    feature_dict = _build_features(native_confidence, llm_pred, static_feat, rag_features)
    feature_array = _features_to_array(feature_dict, pca_model)

    calibrated_conf = _predict_confidence(model, feature_array)
    final_pred = 1 if calibrated_conf >= threshold else 0

    _persist_prediction(
        session=session,
        name=vuln.name,
        llm_pred=llm_pred,
        llm_conf=native_confidence,
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
):
    logger.info("Starting vulnerability analysis pipeline")
    model, pca_model, threshold = _load_confidence_model()

    try:
        retriever = HybridRetriever()
    except Exception as exc:  # pragma: no cover - retrieval optional
        logger.error(f"Failed to initialize retriever, falling back to placeholder: {exc}")
        retriever = None

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
        for vuln in tqdm(vulnerabilities, desc="Processing", unit="sample"):
            cache = cache_map.get(vuln.name)
            if cache is None:
                logger.warning(f"Missing static cache for {vuln.name}, skipping.")
                continue
            try:
                _process_single(session, retriever, model, pca_model, threshold, vuln, cache)
                session.commit()
            except SQLAlchemyError as exc:
                session.rollback()
                logger.error(f"Database error on {vuln.name}: {exc}")
            except Exception as exc:  # pragma: no cover - processing errors
                session.rollback()
                logger.error(f"Failed to process {vuln.name}: {exc}")

    logger.info("Pipeline finished.")


if __name__ == "__main__":
    app()
