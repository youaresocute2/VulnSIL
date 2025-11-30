# vulnsil/schemas.py
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any
from enum import Enum


class DecisionEnum(str, Enum):
    VULNERABLE = "VULNERABLE"
    BENIGN = "BENIGN"


class StaticVerdictEnum(str, Enum):
    """
    LLM's structured review of the provided Static Analysis Evidence.
    Used for Chain-of-Thought validation and Agentic feedback loops.
    """
    AGREE = "AGREE"
    DISAGREE_LOGIC_FOUND = "DISAGREE_LOGIC_FOUND"  # Override due to non-flow bug
    DISAGREE_FALSE_POSITIVE = "DISAGREE_FALSE_POSITIVE"  # Override static alarm
    UNCERTAIN = "UNCERTAIN"


class KnowledgeBaseEntry(BaseModel):
    """
    Entry retrieved from RAG system
    """
    id: int
    original_id: str
    code: str
    label: str
    cwe_id: str = "N/A"  # [Audit] Unified: cwe_id
    similarity_score: float


class VulnerabilityResponse(BaseModel):
    """
    LLM Inference Output Schema
    Strictly enforced via JSON Mode guided decoding.
    [Enhanced] Robust types and validators (Fix 3).
    """
    # 1. Thinking Chain
    thought_process: str = Field(
        ...,
        description="Detailed step-by-step reasoning including flow tracing and logic constraints analysis."
    )

    # 2. Logic Interaction
    static_analysis_review: StaticVerdictEnum = Field(
        default=StaticVerdictEnum.AGREE,
        description="Does your conclusion agree with the Static Analysis evidence?"
    )

    # 3. Evidence Collection
    # [Fix 3] Force Dict[str, bool] to ensure mathematical consistency in pipeline features
    evidence: Dict[str, bool] = Field(
        default_factory=dict,
        description="Technical indicators (e.g. {'missing_bounds_check': true})"
    )

    # [Fix 3] Evidence sanitizer: handles "true", 1, True mixed types
    @field_validator('evidence', mode='before')
    @classmethod
    def sanitize_evidence_input(cls, v):
        if not v or not isinstance(v, dict):
            return {}

        cleaned = {}
        for key, val in v.items():
            k_str = str(key)
            if isinstance(val, bool):
                cleaned[k_str] = val
            elif isinstance(val, str):
                cleaned[k_str] = (val.lower() == "true")
            elif isinstance(val, int):
                cleaned[k_str] = bool(val)
            else:
                # discard complex or null types
                pass
        return cleaned

    # 4. Final Conclusion
    final_decision: DecisionEnum
    confidence: float = Field(..., description="0.0 to 1.0 confidence score")

    # [Audit] Unified: cwe_id
    cwe_id: Optional[str] = Field(default=None, description="Identified CWE ID (e.g. CWE-190) if Vulnerable")