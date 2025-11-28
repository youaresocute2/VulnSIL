# --- START OF FILE vulnsil/core/rag/client.py ---

import faiss
import numpy as np
import logging
import os
import json
from typing import List, Dict, Any
from vulnsil.database import get_db_session
from vulnsil.models import KnowledgeBase
from vulnsil.core.retrieval.vector_db_manager import EmbeddingModel
from config import settings

logger = logging.getLogger("RAGClient")


class RAGClient:
    """
    向量检索客户端
    基于 CodeBERT Embedding + FAISS 检索相似历史漏洞。
    """

    def __init__(self):
        self.embedding_model = EmbeddingModel()
        self.index = None
        self.kb_meta_cache = {}
        self._load_resources()

    def _load_resources(self):
        try:
            # 1. 加载 FAISS 索引
            if settings.FAISS_INDEX_PATH and os.path.exists(settings.FAISS_INDEX_PATH):
                self.index = faiss.read_index(settings.FAISS_INDEX_PATH)
                logger.info(
                    f"[RAGClient] FAISS Index loaded: {settings.FAISS_INDEX_PATH}. Total vectors: {self.index.ntotal}")
            else:
                logger.warning(f"[RAGClient] FAISS Index missing at {settings.FAISS_INDEX_PATH}")

            # 2. 预加载 KB 元数据以提高检索速度
            # 注意：如果数据量过大 (>百万级)，请改为 Redis 或 SQL 实时查询
            logger.info("[RAGClient] Pre-loading KnowledgeBase metadata...")
            with get_db_session() as db:
                entries = db.query(
                    KnowledgeBase.id,
                    KnowledgeBase.label,
                    KnowledgeBase.cwe_id,
                    KnowledgeBase.original_id
                ).all()
                # 假设 FAISS ID 与 DB ID 一一对应
                self.kb_meta_cache = {e.id: e for e in entries}
            logger.info(f"[RAGClient] Loaded metadata for {len(self.kb_meta_cache)} entries.")

        except Exception as e:
            logger.error(f"[RAGClient] Resource Load Failed: {e}")

    def search(self, code: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        检索 Top-K 相似代码
        返回格式: List of dict
        [
          {'similarity': 0.85, 'label': 1, 'cwe': 'CWE-119', 'commit_id': 'abc...', 'code': '...'},
          ...
        ]
        """
        if not self.index or not self.embedding_model:
            return []

        if not code or not code.strip():
            return []

        try:
            # 1. 计算向量
            vec = self.embedding_model.encode(code).reshape(1, -1)

            # 2. FAISS 搜索
            scores, indices = self.index.search(vec, top_k)

            results = []
            if indices.size > 0:
                for rank, idx in enumerate(indices[0]):
                    if idx == -1:
                        continue

                    real_id = int(idx)
                    score = float(scores[0][rank])

                    # 获取缓存的元数据
                    meta = self.kb_meta_cache.get(real_id)
                    if not meta:
                        continue

                    label_int = int(meta.label) if (meta.label and str(meta.label).isdigit()) else 0

                    # 按需加载详细代码用于 Prompt (仅前 1-2 条，或根据需求)
                    # 为简单起见，这里演示去数据库查一遍 Text
                    code_snippet = ""
                    try:
                        with get_db_session() as db:
                            row = db.query(KnowledgeBase.code).filter(KnowledgeBase.id == real_id).first()
                            if row: code_snippet = row.code
                    except:
                        pass

                    entry = {
                        "similarity": score,
                        "label": label_int,
                        "cwe": meta.cwe_id or "N/A",
                        "project": "unknown",
                        "commit_id": meta.original_id,
                        "code": code_snippet
                    }
                    results.append(entry)

            return results

        except Exception as e:
            logger.error(f"[RAGClient] Search error: {e}")
            return []