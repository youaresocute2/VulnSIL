# vulnsil/schemas.py
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class DecisionEnum(str, Enum):
    """
    高层决策标签：
    - vulnerable: 确认存在漏洞
    - safe: 确认不存在漏洞
    - unknown: 模型不确定 / 信息不足
    """
    vulnerable = "vulnerable"
    safe = "safe"
    unknown = "unknown"


class KnowledgeBaseEntry(BaseModel):
    """
    RAG 知识库条目，用于在 LLM 推理结果中记录“参考了哪些相似样本”。
    注意：这里是逻辑层结构，不直接等同于数据库 ORM 模型。
    """
    id: Optional[int] = Field(
        default=None,
        description="Optional internal identifier of the KB entry (DB primary key or similar).",
    )
    code: str = Field(
        ...,
        description="Code snippet of the KB entry.",
    )
    cwe: Optional[str] = Field(
        default=None,
        description="CWE ID associated with this entry, e.g., 'CWE-787'.",
    )
    project: Optional[str] = Field(
        default=None,
        description="Project name where this snippet comes from (e.g., 'qemu').",
    )
    commit_id: Optional[str] = Field(
        default=None,
        description="Commit hash of the source code, if applicable.",
    )
    label: Optional[int] = Field(
        default=None,
        description="Ground-truth label if known: 1 for vulnerable, 0 for safe.",
    )
    similarity_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Similarity score between the query and this entry (larger means more similar).",
    )


class AnalysisResult(BaseModel):
    """
    LLM 对单个函数的分析结果（这是项目中统一的核心 Pydantic 模型）。

    该模型同时用于：
    - vLLMClient 的结构化输出
    - run_pipeline 中的决策与特征提取
    - 后续置信度校准（native_confidence 来自其中的 confidence 字段）
    """
    is_vulnerable: bool = Field(
        ...,
        description="Whether the function contains a security vulnerability.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Model's self-reported confidence in [0, 1].",
    )
    reasoning: str = Field(
        ...,
        description="Natural-language explanation / step-by-step reasoning.",
    )
    decision: DecisionEnum = Field(
        ...,
        description="High-level decision label consistent with is_vulnerable.",
    )
    cwe: Optional[str] = Field(
        default=None,
        description="Predicted CWE ID for the vulnerability if applicable.",
    )
    kb_evidence: List[KnowledgeBaseEntry] = Field(
        default_factory=list,
        description="Optional list of KB entries that support the decision.",
    )


# 为了兼容旧代码，如果之前使用的是 VulnerabilityResponse 名称，
# 可以直接将其作为 AnalysisResult 的别名。
VulnerabilityResponse = AnalysisResult
