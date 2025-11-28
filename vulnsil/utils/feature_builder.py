# --- START OF FILE vulnsil/utils/feature_builder.py ---

import numpy as np
import logging
from enum import Enum
from typing import Dict, List, Any, Tuple
from vulnsil.schemas import AnalysisResult
from config import settings

logger = logging.getLogger("FeatureBuilder")


class FeatureBuilder:
    """
    特征工程模块
    按照 config.py 定义的顺序构建 15 维特征向量，用于置信度模型。
    """

    def __init__(self, feature_order: List[str] = None):
        self.feature_order = feature_order or settings.DEFAULT_FEATURE_ORDER

    def build(self,
              llm_result: AnalysisResult,
              static_feats: Dict[str, Any],
              rag_results: List[Dict[str, Any]],
              code_len: int) -> Tuple[Dict[str, float], np.ndarray]:
        """
        :return: (Feature Dict, Numpy Feature Vector)
        """

        # --- 1. RAG 统计特征 ---
        sims = [float(r.get('similarity', 0.0)) for r in rag_results] if rag_results else [0.0]
        labels = [int(r.get('label', 0)) for r in rag_results] if rag_results else [0]

        rag_top1_sim = sims[0] if len(sims) > 0 else 0.0
        rag_mean_sim = float(np.mean(sims)) if len(sims) > 0 else 0.0
        rag_std_sim = float(np.std(sims)) if len(sims) > 0 else 0.0
        rag_pos_ratio = float(sum(labels)) / len(labels) if len(labels) > 0 else 0.0

        # RAG Support Agreement: 若 RAG Top-K 中超过 50% 是漏洞，视为 RAG 倾向 Vulnerable
        rag_support_agreement = 1.0 if rag_pos_ratio > 0.5 else 0.0

        # --- 2. LLM 特征 ---
        # 获取 LLM 是否判断为 Vuln (兼容大小写字符串和Enum)
        if hasattr(llm_result.decision, "value"):
            decision_val = llm_result.decision.value
        else:
            decision_val = llm_result.decision if not isinstance(llm_result.decision, Enum) else llm_result.decision.value

        decision_str = str(decision_val)
        llm_pred = 1.0 if decision_str.lower() in ["vulnerable", "1", "true"] else 0.0
        llm_conf = float(llm_result.confidence)

        # --- 3. 静态分析特征 ---
        static_has_flow = 1.0 if static_feats.get('has_flow') else 0.0
        complexity = float(static_feats.get('complexity', 0))
        apis = static_feats.get('apis', [])
        api_count = float(len(apis))
        source_type = float(static_feats.get('source_type', 0))

        risk_density = 0.0
        if code_len > 0:
            risk_density = api_count / float(code_len)

        graph_density = float(static_feats.get('graph_density', 0.0))

        # --- 4. 逻辑一致性特征 ---
        # LLM 判定与 RAG 支持倾向是否“不一致”
        conflict_disagree = 1.0 if llm_pred != rag_support_agreement else 0.0

        code_len_log = float(np.log1p(code_len))

        # 构建完整的特征字典
        feat_dict = {
            "llm_confidence": llm_conf,
            "llm_pred": llm_pred,
            "static_has_flow": static_has_flow,
            "static_complexity": complexity,
            "static_api_count": api_count,
            "static_risk_density": risk_density,
            "static_source_type": source_type,
            "rag_top1_similarity": rag_top1_sim,
            "rag_mean_similarity": rag_mean_sim,
            "rag_std_similarity": rag_std_sim,
            "rag_positive_ratio": rag_pos_ratio,
            "rag_support_agreement": rag_support_agreement,
            "conflict_disagree": conflict_disagree,
            "graph_density": graph_density,
            "code_len_log": code_len_log
        }

        # 按指定顺序转换为 Vector
        vector_list = []
        for name in self.feature_order:
            val = feat_dict.get(name, 0.0)
            vector_list.append(val)

        return feat_dict, np.array(vector_list, dtype=np.float32)