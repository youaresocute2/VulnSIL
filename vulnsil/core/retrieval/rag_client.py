import logging
from typing import List

from vulnsil.core.retrieval.hybrid_search import HybridRetriever
from vulnsil.schemas import KnowledgeBaseEntry

logger = logging.getLogger(__name__)


class RAGClient:
    """Lightweight wrapper around HybridRetriever for pipeline usage."""

    def __init__(self) -> None:
        try:
            self._retriever = HybridRetriever()
        except Exception as exc:
            logger.error("Failed to initialize HybridRetriever: %s", exc)
            self._retriever = None

    def search(self, code: str, top_k: int = 5) -> List[KnowledgeBaseEntry]:
        if self._retriever is None:
            return []
        try:
            results = self._retriever.search(code, top_k=top_k) or []
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("RAG search failed: %s", exc)
            return []

        normalized: List[KnowledgeBaseEntry] = []
        for entry in results:
            normalized.append(
                KnowledgeBaseEntry(
                    id=getattr(entry, "id", None),
                    code=getattr(entry, "code", ""),
                    cwe=getattr(entry, "cwe_id", None) or getattr(entry, "cwe", None),
                    project=getattr(entry, "project", None),
                    commit_id=getattr(entry, "commit_id", None),
                    label=getattr(entry, "label", None),
                    similarity_score=getattr(entry, "similarity_score", None),
                    source=getattr(entry, "source_dataset", None) if hasattr(entry, "source_dataset") else getattr(entry, "source", None),
                )
            )
        return normalized
