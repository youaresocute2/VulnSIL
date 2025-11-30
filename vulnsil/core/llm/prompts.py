# vulnsil/core/llm/prompts.py
from typing import List
from collections import Counter
from vulnsil.schemas import KnowledgeBaseEntry
from config import settings
import logging

log = logging.getLogger("prompts")

class PromptManager:
    """
    Prompt Manager v8.0 (Academic Enhanced)
    - Integrates formal vulnerability definitions (CWE-aligned).
    - Enhances LLM knowledge recall with explicit CWE/SARD references.
    - Strengthens CoT with multi-level reasoning and evidence tracing.
    - Adds negative Few-shot to reduce hallucinations.
    """

    SYSTEM_PROMPT = """You are an Expert Security Auditor for C/C++ Kernels/Drivers, grounded in academic vulnerability detection principles (e.g., CWE, SARD datasets).

    **FORMAL DEFINITIONS** (Recall from your pre-trained knowledge):
    - Vulnerability Model: Define a vulnerability as \(\mathcal{V} = (S, T, P, M)\), where \(S\) is the Source (untrusted input), \(T\) is Taint propagation, \(P\) is the Path to Sink (sensitive operation), and \(M\) is Missing Mitigation (e.g., bounds check).
    - CWE Recall: Activate knowledge of CWE categories (e.g., CWE-787: Out-of-Bounds Write; CWE-416: Use-After-Free). Cross-reference with provided static evidence.
    - Burden of Proof: To classify VULNERABLE, MUST trace a concrete path \(P\) violating \(M\); otherwise, BENIGN.

    **AUDIT PROTOCOL** (Multi-level CoT for Rigorous Reasoning):
    1. **Knowledge Activation**: Recall relevant CWE patterns from your training (e.g., buffer overflow: unchecked memcpy with user-controlled size).
    2. **Static Baseline Review**: Evaluate provided Static Analysis (e.g., "CONFIRMED FLOW" implies potential \(T\), but verify independently).
    3. **Flow Tracing**: Explicitly trace data/control flow from \(S\) to Sink, listing variables and lines.
    4. **Mitigation Check**: Identify \(M\) (e.g., missing if(size < MAX)); if present, override to BENIGN.
    5. **Logic Flaw Detection**: If NO FLOW, check non-flow bugs (e.g., race conditions, signed-to-unsigned conversion).
    6. **Confidence Scoring**: Base on evidence strength; low if hallucinated.

    **OUTPUT**: Strict JSON. Avoid hallucinations—cite code lines/CWE explicitly."""

    # Enhanced Few-Shot: Positive + Negative for balanced reasoning
    FIXED_FEW_SHOT_BLOCK = """
    **METHODOLOGY EXAMPLES (Academic-Style Few-Shot)**:

    [Positive Case: CWE-787 Override]
    Static: "CONFIRMED FLOW".
    Code: `char buf[128]; int len = get_user_len(); memcpy(buf, user_data, len);`
    - Reasoning: Source \(S\): user_data (tainted). Taint \(T\): flows to memcpy size. Path \(P\): direct. Missing \(M\): no len < 128 check.
    - CWE: 787 (OOB Write).
    - Verdict: VULNERABLE (DISAGREE_FALSE_POSITIVE if static over-alarmed, but here confirmed).

    [Negative Case: Benign with Mitigation]
    Static: "CONFIRMED FLOW".
    Code: `char buf[128]; int len = get_user_len(); if(len > 128) return; memcpy(buf, user_data, len);`
    - Reasoning: \(S, T, P\) exist, but \(M\) absent due to bounds check.
    - Verdict: BENIGN (AGREE with Static if flow confirmed but mitigated).

    [Logic Flaw Case: No Flow but Vulnerable]
    Static: "NO FLOW".
    Code: `int idx = get_signed_idx(); array[idx] = val;`
    - Reasoning: No taint, but logic flaw: signed idx allows negative OOB.
    - CWE: 125 (OOB Read/Write).
    - Verdict: VULNERABLE (DISAGREE_LOGIC_FOUND).
    """

    MAIN_TEMPLATE = """
    **SEC 1: SYSTEM METRICS**
    - Complexity: {complexity_desc}
    - API Density: {risk_density:.4f}
    - **Static Data Flow**: **{has_flow}**
    {cwe_hint_block}

    **SEC 2: CONTEXTUAL RAG SAMPLES**
    {rag_block}

    **SEC 3: METHODOLOGY & CONSTRAINTS**
    {few_shot_block}
    {constraints_block}

    **SEC 4: TARGET CODE FOR AUDIT**
    {target_code}

    Apply the protocol step-by-step. Output JSON with traced evidence.
    """

    RAG_TEMPLATE = """[Ref:{original_id} | Sim:{similarity_int}%] {case_label}\n"""

    @staticmethod
    def _calculate_density(code_len: int, api_count: int) -> float:
        return api_count / (float(code_len) + 1e-9)

    @staticmethod
    def _generate_dynamic_constraints(has_flow_confirmed: bool, source_is_joern: bool, density: float) -> str:
        rules = []
        # Constraint Logic matches previous versions
        if source_is_joern and not has_flow_confirmed:
            rules.append("- [STRONG CONSTRAINT] Static says **NO FLOW**. Ignore taint bugs. Focus ONLY on Logic/Race.")
        if density < 0.3:
            rules.append("- [HEURISTIC] Low Density. Likely Benign Logic/Wrapper.")
        if not source_is_joern:
            rules.append("- [WARN] No Static Graph. Manually trace ALL vars.")
        return "\n    ".join(rules) if rules else "- Standard Audit."

    @staticmethod
    def build_prompt(target_code: str, rag_entries: List[KnowledgeBaseEntry], static_features: dict = None,
                     desc_text: str = "UNKNOWN") -> str:
        if static_features is None: static_features = {}
        complexity = static_features.get("complexity", 0)
        api_count = len(static_features.get("apis", []))
        code_len = len(target_code)
        risk_density = PromptManager._calculate_density(code_len, api_count)

        is_joern = ("Joern" in desc_text)
        flow_ok = ("CONFIRMED" in desc_text)

        const_str = PromptManager._generate_dynamic_constraints(flow_ok, is_joern, risk_density)

        # Token Management (Calculated precisely)
        INPUT_LIMIT = settings.LLM_MAX_MODEL_LEN - settings.LLM_MAX_TOKENS - 250
        budget_total = int(INPUT_LIMIT * 2.8)

        # Build RAG Text
        # [Fix VIII] Ensure meaningful default when empty
        rag_text = ""
        if rag_entries:
            # If hits found, format them. Note: MIN_RAG_SIMILARITY in HybridSearch prevents garbage here.
            snips = [PromptManager.RAG_TEMPLATE.format(
                original_id=e.original_id,
                similarity_int=int(e.similarity_score * 100),
                case_label=e.label
            ) for e in rag_entries]
            rag_text = "".join(snips)[:2000]  # Hard Cap

        # Handle explicit empty/whitespace state
        if not rag_text.strip():
             rag_text = "No similar vulnerable samples retrieved."

        # Truncate Target
        code_budget = int(budget_total * 0.5)
        trunc_code = target_code
        if len(target_code) > code_budget:
            trunc_code = target_code[:code_budget] + "\n/* ...TRUNCATED... */"

        return PromptManager.MAIN_TEMPLATE.format(
            complexity_desc=complexity,
            api_count=api_count,
            risk_density=risk_density,
            has_flow=desc_text,
            cwe_hint_block="",
            rag_block=rag_text,
            few_shot_block=PromptManager.FIXED_FEW_SHOT_BLOCK,
            constraints_block=const_str,
            target_code=trunc_code
        )