# vulnsil/core/retrieval/hybrid_search.py
import pickle
import numpy as np
import logging
import os
import faiss
import hashlib
from typing import List, Dict

from config import settings
from vulnsil.database import get_db_session
from vulnsil.models import KnowledgeBase
from vulnsil.schemas import KnowledgeBaseEntry
from vulnsil.core.retrieval.vector_db_manager import EmbeddingModel
from vulnsil.core.static_analysis.compressor import SemanticCompressor

logger = logging.getLogger(__name__)

# [Adaptive Gate]
MIN_VECTOR_SIMILARITY_THRESHOLD = 0.60


def compute_md5(text: str) -> str:
    """Helper: Normalize whitespace and hash code for deduplication."""
    return hashlib.md5(text.strip().encode('utf-8', errors='ignore')).hexdigest()


class HybridRetriever:
    """
    Core Retrieval Engine.
    Combines FAISS (Vector) and BM25 (Keyword) with RRF Fusion.
    Includes explicit logic to handle deduplication and integrity checks.
    """

    # [Fix IV] Custom Error
    class IndexCorruptedError(RuntimeError):
        pass

    def __init__(self):
        self.embedding_model = None
        self.faiss_index = None
        self.bm25_model = None
        self.ids_map = []  # FAISS ID (Int) -> Database ID (Int) Mapping
        self.compressor = None
        self._load_resources()

    def _load_resources(self):
        try:
            logger.info("HybridRetriever: Loading resources...")

            # 1. Embedding Model
            self.embedding_model = EmbeddingModel()

            # 2. FAISS Vector Index
            if os.path.exists(settings.FAISS_INDEX_PATH):
                self.faiss_index = faiss.read_index(settings.FAISS_INDEX_PATH)
            else:
                logger.warning(f"⚠️ FAISS index missing at {settings.FAISS_INDEX_PATH}")

            # 3. BM25 Sparse Index & ID Mapping
            if os.path.exists(settings.BM25_INDEX_PATH):
                with open(settings.BM25_INDEX_PATH, 'rb') as f:
                    data = pickle.load(f)
                    self.bm25_model = data.get('model')
                    self.ids_map = data.get('ids', [])

                    # [Fix 2/IV] Integrity Check
                    stored_hash = data.get('integrity_hash')
                    if stored_hash and self.ids_map:
                        # Recalculate hash of current ID map to verify no disk/memory mismatch
                        current_ids_str = "".join(str(x) for x in self.ids_map)
                        current_hash = hashlib.md5(current_ids_str.encode('utf-8')).hexdigest()

                        if current_hash != stored_hash:
                            err_msg = (f"❌ INDEX CORRUPTION: StoredHash={stored_hash} vs "
                                       f"CurrHash={current_hash}. RAG DB and Index mismatch.")
                            logger.critical(err_msg)
                            # Hard fail on data corruption
                            raise self.IndexCorruptedError(err_msg)
                        else:
                            logger.info("✅ RAG Index Integrity Verified.")

            else:
                logger.warning(f"⚠️ BM25 index missing at {settings.BM25_INDEX_PATH}")

            # [CRITICAL AUDIT CHECK] Mapping Integrity Guard
            if self.faiss_index and self.ids_map:
                if self.faiss_index.ntotal != len(self.ids_map):
                    error_msg = (f"❌ INDEX CORRUPTION: FAISS ntotal ({self.faiss_index.ntotal}) "
                                 f"!= IDs map len ({len(self.ids_map)}). "
                                 "Mapping drift detected! Rebuild KnowledgeBase index immediately.")
                    logger.critical(error_msg)
                    raise RuntimeError(error_msg)
                else:
                    logger.info(f"✅ Mapping Integrity OK. Entries: {len(self.ids_map)}")

            # 4. Compressor
            try:
                self.compressor = SemanticCompressor()
                logger.info("Semantic Compressor loaded for Input Alignment.")
            except Exception as e:
                logger.warning(f"Compressor failed ({e}). Queries will be RAW.")
                self.compressor = None

        except Exception as e:
            logger.error(f"HybridRetriever Init Failed: {e}", exc_info=True)
            if isinstance(e, (RuntimeError, self.IndexCorruptedError)):
                raise e

    def _rrf_fusion(self, rank_lists: List[List[int]], k: int = 60) -> Dict[int, float]:
        """
        Reciprocal Rank Fusion (RRF).
        """
        rrf_map = {}
        for rank_list in rank_lists:
            for rank, doc_id in enumerate(rank_list):
                if doc_id not in rrf_map:
                    rrf_map[doc_id] = 0.0
                rrf_map[doc_id] += 1.0 / (k + rank + 1)
        return rrf_map

    def search(self, code_query: str, top_k: int = 5) -> List[KnowledgeBaseEntry]:
        """
        Executes search logic with Anti-Leakage (Deduplication) and Adaptive Gating.
        """
        if not self.faiss_index or not self.embedding_model:
            return []

        # ===========================
        # 1. Input Processing
        # ===========================

        query_hash = compute_md5(code_query)

        process_query = code_query
        if self.compressor and len(code_query) > settings.COMPRESSION_TRIGGER_LEN:
            try:
                process_query = self.compressor.compress(code_query, settings.MAX_CODE_TOKENS_INPUT)
            except Exception:
                pass

        search_limit = top_k * 3
        candidate_k_vector = search_limit * 2

        # ===========================
        # 2. Vector Search (Primary)
        # ===========================
        query_vec = self.embedding_model.encode(process_query).reshape(1, -1)

        D, I = self.faiss_index.search(query_vec, candidate_k_vector)

        max_vector_sim = float(D[0][0]) if D.size > 0 else 0.0

        if max_vector_sim < MIN_VECTOR_SIMILARITY_THRESHOLD:
            return []

        vector_ids = []
        vector_sim_map = {}

        if I.size > 0:
            for rank, idx in enumerate(I[0]):
                # [Fix 2] Robust Index Access Safety
                idx_int = int(idx)
                if idx_int != -1 and 0 <= idx_int < len(self.ids_map):
                    try:
                        real_id = self.ids_map[idx_int]
                        vector_ids.append(real_id)
                        vector_sim_map[real_id] = float(D[0][rank])
                    except IndexError:
                        logger.error(f"Bounds check failed late: {idx_int} vs {len(self.ids_map)}")
                        continue
                elif idx_int != -1:
                    logger.warning(f"RAG Idx Out of Bounds: {idx_int}")

        # ===========================
        # 3. BM25 Search (Fallback)
        # ===========================
        bm25_ids = []
        if self.bm25_model:
            tokens = process_query.split()
            if not tokens: tokens = ["void"]

            try:
                scores = self.bm25_model.get_scores(tokens)
                top_n_idx = np.argsort(scores)[::-1][:candidate_k_vector]

                for idx in top_n_idx:
                    idx_int = int(idx)
                    # [Fix 2] BM25 Access Safety
                    if 0 <= idx_int < len(self.ids_map):
                        bm25_ids.append(self.ids_map[idx_int])
            except Exception:
                pass

        # ===========================
        # 4. Fusion & Ordering
        # ===========================
        fused = self._rrf_fusion([vector_ids, bm25_ids])
        sorted_candidates = sorted(fused.keys(), key=lambda x: fused[x], reverse=True)

        # ===========================
        # 5. DB Fetch & Filter
        # ===========================
        final_results = []
        # [Fix 7] Logic Optimization: slice before filter loop
        limit_k = min(len(sorted_candidates), search_limit)
        candidates_to_fetch = sorted_candidates[:limit_k]

        if candidates_to_fetch:
            with get_db_session() as db:
                rows = db.query(KnowledgeBase).filter(KnowledgeBase.id.in_(candidates_to_fetch)).all()
                row_map = {r.id: r for r in rows}

                for rid in candidates_to_fetch:
                    if rid not in row_map: continue
                    rec = row_map[rid]

                    if compute_md5(rec.code) == query_hash:
                        continue

                    display_sim = vector_sim_map.get(rid, 0.5)

                    entry = KnowledgeBaseEntry(
                        id=rec.id,
                        original_id=rec.original_id,
                        code=rec.code,
                        label=rec.label,
                        cwe_id=rec.cwe_id if rec.cwe_id else "N/A",
                        similarity_score=display_sim
                    )
                    final_results.append(entry)

                    if len(final_results) >= top_k:
                        break

        return final_results