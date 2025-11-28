# vulnsil/core/retrieval/hybrid_search.py
import pickle
import numpy as np
import logging
import os
import faiss
import json
from typing import List, Dict

from config import settings
from vulnsil.database import get_db_session
from vulnsil.models import KnowledgeBase
from vulnsil.schemas import KnowledgeBaseEntry
from vulnsil.core.retrieval.vector_db_manager import EmbeddingModel
from vulnsil.core.static_analysis.compressor import SemanticCompressor  # 新增：统一压缩

logger = logging.getLogger(__name__)


class HybridRetriever:
    def __init__(self):
        self.embedding_model = None
        self.faiss_index = None
        self.bm25_model = None
        self.ids_map = []
        self.compressor = SemanticCompressor()  # 新增：压缩器
        self._load_resources()

    def _load_resources(self):
        try:
            self.embedding_model = EmbeddingModel()

            if os.path.exists(settings.FAISS_INDEX_PATH):
                self.faiss_index = faiss.read_index(settings.FAISS_INDEX_PATH)
            else:
                logger.warning("FAISS index missing.")

            if os.path.exists(settings.FAISS_IDS_MAP_PATH):
                with open(settings.FAISS_IDS_MAP_PATH, "r") as f:
                    raw_map = json.load(f)
                    # JSON keys are str indices
                    self.ids_map = [int(raw_map[str(i)]) for i in sorted(map(int, raw_map.keys()))]
            else:
                logger.error(f"faiss_ids_map.json missing at {settings.FAISS_IDS_MAP_PATH}")

            if os.path.exists(settings.BM25_INDEX_PATH):
                with open(settings.BM25_INDEX_PATH, 'rb') as f:
                    data = pickle.load(f)
                    self.bm25_model = data['model']
                    if not self.ids_map:
                        self.ids_map = data['ids']
            else:
                logger.warning("BM25 index missing.")

        except Exception as e:
            logger.error(f"Retriever Init Error: {e}")

    def _rrf_fusion(self, rank_lists: List[List[int]], k: int) -> Dict[int, float]:
        rrf_map = {}
        for rank_list in rank_lists:
            for rank, doc_id in enumerate(rank_list):
                if doc_id not in rrf_map:
                    rrf_map[doc_id] = 0.0
                rrf_map[doc_id] += 1.0 / (k + rank + 1)
        return rrf_map

    def search(self, code_query: str, top_k: int = 5) -> List[KnowledgeBaseEntry]:
        """
        混合检索代码
        [改进] 统一压缩query以对齐嵌入空间
        """
        if not self.faiss_index or not self.embedding_model or not self.ids_map:
            return []

        # 新增：统一压缩query
        if len(code_query) > settings.MAX_CODE_TOKENS_INPUT:
            code_query = self.compressor.compress(code_query, settings.MAX_CODE_TOKENS_INPUT)

        candidate_k = top_k * settings.RETRIEVAL_VECTOR_CANDIDATE_MULTIPLIER

        # 1. Vector Search
        query_vec = self.embedding_model.encode(code_query).reshape(1, -1)

        # [修改点] D 是距离/相似度分数 (Inner Product), I 是索引
        D, I = self.faiss_index.search(query_vec, candidate_k)

        vector_ids = []
        vector_scores_map = {}  # [新增] 用于存储真实的向量相似度 (0.0~1.0)

        # FAISS可能返回-1表示不足
        if I.size > 0:
            for rank, idx in enumerate(I[0]):
                if idx != -1 and 0 <= idx < len(self.ids_map):
                    real_id = self.ids_map[idx]
                    vector_ids.append(real_id)
                    # D[0][rank] 即为 Cosine Similarity (假设向量已归一化)
                    vector_scores_map[real_id] = float(D[0][rank])

        # 2. Sparse Search
        tokens = code_query.split()
        if not tokens: tokens = ["void"]  # fallback

        bm25_ids = []
        if self.bm25_model:
            scores = self.bm25_model.get_scores(tokens)
            top_n_idx = np.argsort(scores)[::-1][:candidate_k]

            for idx in top_n_idx:
                if 0 <= idx < len(self.ids_map):
                    bm25_ids.append(self.ids_map[idx])

        # 3. Fusion (仅用于排序)
        fused = self._rrf_fusion([vector_ids, bm25_ids], settings.RETRIEVAL_RRF_K)
        sorted_ids = sorted(fused.keys(), key=lambda x: fused[x], reverse=True)[:top_k]

        results = []
        if sorted_ids:
            with get_db_session() as db:
                rows = db.query(KnowledgeBase).filter(KnowledgeBase.id.in_(sorted_ids)).all()
                row_map = {r.id: r for r in rows}

                for rid in sorted_ids:
                    if rid in row_map:
                        rec = row_map[rid]

                        # [核心修复] 优先使用真实的向量相似度
                        # 如果该文档仅由 BM25 召回（不在 vector map 中），则给一个保守的默认分 (如 0.5)
                        # 这样保证传给 LLM 的分数具有物理意义
                        real_sim = vector_scores_map.get(rid, 0.5)

                        entry = KnowledgeBaseEntry(
                            id=rec.id,
                            original_id=rec.original_id,
                            code=rec.code,
                            label=int(rec.label) if rec.label is not None else None,
                            cwe_id=rec.cwe_id if rec.cwe_id else "N/A",
                            similarity_score=real_sim  # 传递真实相似度，而非 RRF 分数
                        )
                        results.append(entry)
        return results