# vulnsil/schemas.py
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum

class DecisionEnum(str, Enum):
    VULNERABLE = "VULNERABLE"
    BENIGN = "BENIGN"

class KnowledgeBaseEntry(BaseModel):
    id: int
    original_id: str
    code: str
    label: str
    cwe_id: str = "N/A"
    similarity_score: float

class VulnerabilityResponse(BaseModel):
    """
    LLM 响应结构体
    [新增] thought_process 字段，用于提取不确定性特征
    """
    thought_process: str = Field(default="", description="Step-by-step analysis chain")
    evidence: Dict[str, Any] = Field(default_factory=dict)
    final_decision: DecisionEnum
    confidence: float
    cwe_id: Optional[str] = None