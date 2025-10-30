# vulnsil/prompts/sil_reasoner.py

import json
from typing import Dict, Any

INST_START = "[INST]"
INST_END = "[/INST]"

class SilThinkVerifyPrompt:
    """
    [修改] 在 SIL 上执行 Think & Verify 推理，聚焦于二分类 (YES/NO)。
    借鉴 VulnSage  的结构化推理，并移除 CWE 输出。
    """

    @staticmethod
    def format_prompt(sil_json: Dict[str, Any]) -> str:
        """
        格式化用于 SIL 推理 (二分类) 的 Think & Verify Prompt。

        Args:
            sil_json (Dict[str, Any]): 要分析的 SIL JSON 对象 (已增强)。

        Returns:
            str: 准备好发送给 LLM 的 Prompt 字符串。
        """

        system_prompt = (
            "You are a security expert performing **zero-shot vulnerability detection**. "
            "Your task is to determine if the provided Semantic Intermediate Language (SIL) JSON "
            "indicates the presence of a vulnerability (**YES**) or if it appears secure (**NO**), "
            "based *solely* on the SIL data. Follow the structured reasoning steps below and output *only* the XML."
            # "Reference: Inspired by VulnSage methodology." # 可以添加引用说明
        )

        # -----------------------------------------------------------
        # [核心修改] 采用 VulnSage  的 T&V 结构，并调整思考步骤以适应 SIL V1.2 和二分类目标
        # -----------------------------------------------------------
        tv_steps = """
**Reasoning Steps:**

1.  **Initial Analysis (Up to 3 Attempts):**
    * `<thinking>`:
        1.  **Understand Context:** Review `function_name`, `parameters`, `variables` (note types, sizes like 'UNKNOWN').
        2.  **Identify Potential Taint:** Use `enrichment_analysis.tainted_variables` and `enrichment_analysis.taint_sources` if available. If not, assume parameters and results of `EXTERNAL_CALL` are tainted. Track taint propagation through `ASSIGNMENT`, `BUFFER_WRITE` (if src or size tainted), `INTEGER_OPERATION` (if operands tainted, result is tainted).
        3.  **Scan for Vulnerability Patterns (Focus on YES/NO):**
            * **Memory Corruption:** Look for `BUFFER_WRITE` (e.g., `memcpy`, `strcpy`, `sprintf`, loop-based copy `data[i]=src[i]`) where destination buffer size (from `variables`) is potentially smaller than the source/size (`source_variable` tainted? `size_bytes_written` tainted or large constant?). Also check `INTEGER_OPERATION` for array indexing (`buf[idx]`) with tainted `index`.
            * **Injection:** Look for `COMMAND_EXECUTION` with a tainted `command_variable`, or `FUNCTION_CALL` marked `is_format_string_sink=true` with a tainted format string argument.
            * **Resource Issues:** Track `MEMORY_ALLOC`/`RESOURCE_ACQUIRE`. Is there a guaranteed `MEMORY_FREE`/`RESOURCE_RELEASE` on *all paths* before function end or reassignment? Check for `Double Free` or `Use After Free` patterns. Check `RESOURCE_RELEASE` uses the correct function type (e.g., `fopen` needs `fclose`).
            * **Pointer Issues:** Look for `ASSIGNMENT` of `NULL` to `ptr`, followed by `POINTER_ARITHMETIC` using `ptr` without checks.
            * **Integer Issues:** Look for `INTEGER_OPERATION` involving division/modulo by a potentially zero tainted variable. Check for potential overflows/underflows if operations involve tainted values and large constants (less emphasis unless clear).
        4.  **Check for Mitigations:** Find relevant `CONDITION_CHECK` operations (e.g., `NULL_CHECK` before dereference, `BOUNDS_CHECK` before array access, size check before `BUFFER_WRITE`) that *clearly negate* an identified pattern.
        5.  **Formulate Hypothesis (YES/NO):** Based on identified patterns and the presence/absence of clear mitigations. State the primary pattern found if hypothesizing YES.
        6.  **Document Uncertainties:** List factors preventing a high-confidence decision (e.g., 'UNKNOWN' sizes, complex control flow affecting resource leak analysis, unclear behavior of external `FUNCTION_CALL`).
    * `</thinking>`
    * `<findings>`: List the primary vulnerability pattern(s) identified (e.g., "Potential Buffer Overflow", "Possible NULL Pointer Dereference", "Command Injection Risk") or "No clear vulnerability patterns found". `</findings>`
    * `<confidence>`: Assign confidence score (0-100%) for the *presence* of *any* vulnerability based *only* on SIL evidence. High (90-100) = clear pattern, no/weak mitigation. Medium (50-80) = pattern exists but mitigation unclear or size 'UNKNOWN'. Low (0-40) = weak pattern or significant uncertainties. `</confidence>`
    * `<uncertainties>`: If confidence < 90, explain the ambiguities noted in thinking step 6. `</uncertainties>`

2.  **Verification (Only if confidence >= 90):**
    * `<verification>`: Briefly confirm the logic for the high-confidence finding. (e.g., "Verified: `strcpy` target 'buf' has size 50, source 'input' is tainted (parameter), no size check found before `BUFFER_WRITE`. Confirms overflow risk."). `</verification>`

3.  **Final Assessment:**
    * `<assessment>`:
        * `<vulnerability>`: **YES** (if a pattern was found with sufficient confidence after considering mitigations and uncertainties) or **NO** (otherwise).
        * `<explanation>`: Concisely explain the reasoning for the YES/NO decision, referencing specific SIL operations and findings from the `<thinking>` step. If NO, state why patterns were dismissed (e.g., "Mitigated by bounds check", "No tainted data reached sink", "High uncertainty due to unknown sizes").
    * `</assessment>`
"""

        sil_block = f"\n[SIL BLOCK TO ANALYZE]\n{json.dumps(sil_json, indent=2)}\n[/SIL BLOCK TO ANALYZE]"

        full_prompt = (
            f"{INST_START} {system_prompt}\n\n{tv_steps}\n\n{sil_block}\n\n[OUTPUT XML ONLY]\n{INST_END}"
        )
        return full_prompt
