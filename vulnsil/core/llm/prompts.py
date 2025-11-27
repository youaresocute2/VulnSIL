# vulnsil/core/llm/prompts.py
from typing import List
from vulnsil.schemas import KnowledgeBaseEntry
from config import settings
import logging

log = logging.getLogger("prompts")


class PromptManager:
    """
    Prompt Manager v3.3 (Neutral & RAG-Cautious)
    Refined to maintain a neutral tone and explicitly warn against over-reliance on RAG results.
    [改进] 添加Few-shot示例（3 vuln/benign）
    """

    # System Prompt: 调整为更加专业、客观的审计员语气
    SYSTEM_PROMPT = """You are a Security Analysis System specialized in auditing C/C++ system code (e.g., Linux Kernel, Drivers). 
            The objective is to objectively analyze the provided source code for critical security vulnerabilities (e.g., Buffer Overflows, Use-After-Free, Integer Overflows, Race Conditions).

            **ANALYSIS PROTOCOL**:
            1. **Data Flow Verification**: Trace the propagation of data from external inputs to sensitive sinks.
            2. **Boundary & Logic Check**: Rigorously verify the existence and correctness of sanitization logic (e.g., length checks, boundary limits).
            3. **Contextual Assumption**: Treat inputs from network, user space, or external files as potentially untrusted.
            4. **Evidence Interpretation**: 
               - Static Analysis results are technical indicators, not final verdicts. 
               - "No Flow" reports from deep analysis tools (like Joern) are strong indicators of safety regarding data flow, but logical errors may still exist.
               - Regex matches are preliminary and require manual verification.

            **RESPONSE FORMAT** (Valid JSON Only):
            {
                "thought_process": "Provide a neutral, step-by-step technical analysis...",
                "evidence": {"untrusted_source": bool, "dangerous_sink": bool, "data_flow": bool, "mitigation_absent": bool},
                "final_decision": "VULNERABLE" or "BENIGN",
                "confidence": float (0.0 to 1.0)
            }
            """

    # 新增：Few-shot示例（3个：1 vuln, 2 benign）
    FEW_SHOT_EXAMPLES = """
            Example 1 (VULNERABLE - Buffer Overflow):
            Code: char buf[10]; strcpy(buf, user_input);
            Analysis: No length check, data flow from untrusted to sink.
            Decision: VULNERABLE, Confidence: 0.9
        
            Example 2 (BENIGN - Safe Allocation):
            Code: char* buf = malloc(len); if (buf) memcpy(buf, data, len);
            Analysis: Mitigation present, no flow issue.
            Decision: BENIGN, Confidence: 0.8
        
            Example 3 (BENIGN - No Flow):
            Code: int x = 5; printf("%d", x);
            Analysis: No untrusted source to sink.
            Decision: BENIGN, Confidence: 0.95
            """

    RAG_TEMPLATE = """
            [REF ID: {original_id}]
            - Vulnerability Class: {case_label}
            - Similarity Score: {similarity_int}/100
            - Code Snippet:
            ```c
            {code}
            ```
            """

    # Main Template: 增加对 RAG 结果的警示和客观评估指南
    MAIN_TEMPLATE = """
            **SECTION 1: STATIC ANALYSIS EVIDENCE**
            - Complexity: {complexity_desc}
            - Sensitive APIs: {api_list}
            - Data Flow to Sink: {has_flow}
              {cwe_hint_block}
        
            **SECTION 2: RAG REFERENCES** (Do not over-rely; verify relevance independently)
            {rag_block}
            
            **SECTION 3: TARGET CODE**
            ```c
            {target_code}
            ```
            """

    def build_prompt(
            target_code: str,
            rag_entries: List[KnowledgeBaseEntry],
            static_complexity: int,
            static_apis: List[str],
            static_has_flow: bool,
    ) -> str:
        """
        构建完整Prompt
        [重新优化] 调整CHAR_BUDGET包含Few-shot长度；Few-shot置开头
        """
        # 预算调整：预留Few-shot空间
        few_shot_len = len(PromptManager.FEW_SHOT_EXAMPLES)
        CHAR_BUDGET_TOTAL = settings.LLM_MAX_MODEL_LEN - settings.LLM_MAX_TOKENS - 500 - few_shot_len  # 预留输出 + Few-shot

        complexity_desc = f"High ({static_complexity})" if static_complexity > 10 else f"Low ({static_complexity})"
        api_str = ", ".join(static_apis) if static_apis else "(None)"
        flow_status_desc = "Yes (Potential Risk)" if static_has_flow else "No (Likely Safe)"

        # 目标代码压缩 (预留 40% 预算)
        target_code_limit = int(CHAR_BUDGET_TOTAL * 0.45)
        if len(target_code) > target_code_limit:
            target_code_trunc = target_code[:target_code_limit] + "\n\n/* ... CODE TRUNCATED FOR LENGTH ... */"
        else:
            target_code_trunc = target_code

        # 3. RAG Budget Calculation
        # 计算模板和其他固定部分占用的字符
        cwe_hint_msg = ""
        if rag_entries and rag_entries[0].similarity_score > 0.015:
            top_cwe = rag_entries[0].cwe_id
            if top_cwe and str(top_cwe).upper() != "N/A":
                cwe_hint_msg = f"\n  - Hint: Similar to {top_cwe}."

        # 预估模板长度
        base_len = len(PromptManager.MAIN_TEMPLATE) + len(target_code_trunc) + len(api_str) + len(cwe_hint_msg) + 200
        rag_char_budget = CHAR_BUDGET_TOTAL - base_len

        # 4. RAG Assembly
        rag_block = ""
        if not rag_entries or rag_char_budget < 200:
            rag_block = "(No refs or context full)"
        else:
            snippets = []
            current_rag_len = 0
            for entry in rag_entries:
                c_lbl = entry.cwe_id if (entry.cwe_id and entry.cwe_id != "N/A") else "Unk"
                sim_int = int(min(99, max(1, entry.similarity_score * 100)))

                # 单个 RAG 片段也限制长度，防止一条占满
                entry_code_limit = 600
                entry_code = entry.code[:entry_code_limit] + "..." if len(entry.code) > entry_code_limit else entry.code

                snip = PromptManager.RAG_TEMPLATE.format(
                    original_id=entry.original_id,
                    similarity_int=sim_int,
                    case_label=c_lbl,
                    code=entry_code
                )

                if current_rag_len + len(snip) < rag_char_budget:
                    snippets.append(snip)
                    current_rag_len += len(snip)
                else:
                    break
            rag_block = "".join(snippets) if snippets else "(Refs omitted)"

        # 重新组装：Few-shot + System + Main
        return PromptManager.FEW_SHOT_EXAMPLES + "\n" + PromptManager.SYSTEM_PROMPT + PromptManager.MAIN_TEMPLATE.format(
            complexity_desc=complexity_desc,
            api_list=api_str,
            has_flow=flow_status_desc,
            cwe_hint_block=cwe_hint_msg,
            rag_block=rag_block,
            target_code=target_code_trunc
        )