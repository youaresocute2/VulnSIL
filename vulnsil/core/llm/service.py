# --- START OF FILE vulnsil/core/llm/service.py ---

import logging
from typing import List, Dict, Any
from vulnsil.core.llm.vllm_client import VLLMClient
from vulnsil.core.llm.prompts import PromptManager
from vulnsil.schemas import AnalysisResult, DecisionEnum, KnowledgeBaseEntry

logger = logging.getLogger("LLMService")


class LLMService:
    """
    LLM 推理服务层
    对接 Pipeline 数据与 VLLMClient，负责构建 Prompt 并返回标准化的 AnalysisResult
    """

    def __init__(self):
        self.client = VLLMClient()

    def analyze(self,
                code: str,
                static_feats: Dict[str, Any],
                rag_results: List[Dict[str, Any]]) -> AnalysisResult:
        """
        执行完整推理流程
        :param code: 目标源代码
        :param static_feats: 静态分析结果字典
        :param rag_results: RAGClient 返回的结果列表
        """

        # 1. 转换 RAG 结果为 Schema 对象 (PromptManager 需要 KnowledgeBaseEntry 对象)
        kb_entries = []
        for r in rag_results:
            kb_entries.append(KnowledgeBaseEntry(
                code=r.get('code', '')[:600],  # 限制 Prompt 中单条 Context 长度
                cwe_id=r.get('cwe'),
                project=r.get('project'),
                commit_id=r.get('commit_id'),
                label=r.get('label'),
                similarity_score=r.get('similarity', 0.0),
                original_id=str(r.get('commit_id', 'unknown'))
            ))

        # 2. 提取静态特征
        complexity = int(static_feats.get('complexity', 0))
        apis = static_feats.get('apis', [])
        has_flow = bool(static_feats.get('has_flow', False))

        # 3. 构建 Prompt
        prompt = PromptManager.build_prompt(code, kb_entries, complexity, apis, has_flow)

        # 4. 调用底层 Client
        try:
            # generate 返回 (AnalysisResult, native_conf_float)
            result, _ = self.client.generate(prompt)
            return result
        except Exception as e:
            logger.error(f"LLM analyze error: {e}")
            # 返回默认安全结果作为兜底，防止管道中断
            return AnalysisResult(
                is_vulnerable=False,
                confidence=0.0,
                reasoning=f"System Error: {str(e)}",
                decision=DecisionEnum.unknown,
                cwe=None,
                kb_evidence=[]
            )