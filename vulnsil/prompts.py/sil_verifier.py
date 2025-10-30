# vulnsil/prompts/sil_verifier.py

import json
from typing import Dict, Any

INST_START = "[INST]"
INST_END = "[/INST]"

class SilVerifierPrompt:
    """
    评估 SIL 质量的 Prompt。
    更侧重于 SIL 是否捕获了 Ground Truth 描述的 *核心安全相关的行为*（无论是有漏洞还是安全的），
    弱化对具体 CWE 的依赖。
    """

    @staticmethod
    def format_prompt(sil_json: Dict[str, Any], ground_truth_info: Dict[str, Any]) -> str:

        gt_label = ground_truth_info.get('label', 'Unknown')
        gt_reason = ground_truth_info.get('reason', 'N/A')

        system_prompt = (
            "You are a meticulous SIL Verifier. Your task is to evaluate if the "
            "[GENERATED SIL] correctly and completely captures the *core security-relevant semantics* "
            "described in the [GROUND TRUTH DESCRIPTION], focusing on whether the code is vulnerable or safe."
        )

        task_prompt = (
            "Analyze the following SIL and Ground Truth. Provide your assessment in the specified XML format.\n\n"
            "1. <confidence>: A score (0.0 to 1.0) of how well the [GENERATED SIL] *semantically matches* the "
            "   [GROUND TRUTH DESCRIPTION] regarding the presence or absence of a vulnerability.\n\n"
            "   **High Confidence (e.g., 0.8 - 1.0) means a SEMANTIC MATCH:**\n"
            "     - **Case A (Vulnerable Match):** The GT Label is '1' (vulnerable) and its Reason describes "
            "       a vulnerability (e.g., 'buffer overflow due to unsafe copy'). The [GENERATED SIL] "
            "       *accurately shows* the operations leading to this vulnerability (e.g., `MEMORY_ALLOC` "
            "       of size 50, followed by `BUFFER_WRITE` of size 100 via `memcpy`).\n"
            "     - **Case B (Secure Match):** The GT Label is '0' (secure) and its Reason describes why "
            "       (e.g., 'Proper bounds checking is performed'). The [GENERATED SIL] *accurately reflects* "
            "       this secure state (e.g., shows the `CONDITION_CHECK` before the `BUFFER_WRITE`, "
            "       or contains no security-critical operations at all).\n\n"
            "   **Low Confidence (e.g., 0.0 - 0.5) means a SEMANTIC MISMATCH:**\n"
            "     - **Case C (False Negative Mismatch):** The GT Label is '1' (vulnerable), but the "
            "       [GENERATED SIL] *fails* to represent the key unsafe operations described in the Reason.\n"
            "     - **Case D (False Positive Mismatch):** The GT Label is '0' (secure), but the "
            "       [GENERATED SIL] *incorrectly represents* operations as unsafe or misses crucial "
            "       mitigating operations (like checks) mentioned or implied by the Reason.\n\n"
            "2. <feedback>: If confidence is low (e.g., < 0.8), provide *actionable feedback* "
            "   for the SIL Generator to fix the SIL representation to better match the Ground Truth's "
            "   *security semantics*. Focus on missing or incorrect operations related to the vulnerability "
            "   (or lack thereof).\n"
            "   - (Example for Case C): 'The SIL is missing the `memcpy` BUFFER_WRITE operation which causes the overflow described.'\n"
            "   - (Example for Case D): 'The SIL failed to represent the `if (size < MAX_SIZE)` check; add a CONDITION_CHECK operation before the BUFFER_WRITE.'\n\n"
            "3. <reasoning>: Briefly explain your confidence score, referencing the cases (A, B, C, or D) and why the SIL matches or mismatches the GT description semantically."
        )

        gt_block = (
            f"[GROUND TRUTH DESCRIPTION]\n"
            f"- Ground Truth Label: {gt_label}\n"
            f"- Ground Truth Reason: {gt_reason}\n"
            f"[/GROUND TRUTH DESCRIPTION]"
        )

        sil_block = f"\n[GENERATED SIL TO VERIFY]\n{json.dumps(sil_json, indent=2)}\n[/GENERATED SIL TO VERIFY]"

        output_format = (
            "\n\n[ASSESSMENT FORMAT]\n"
            "<assessment>\n"
            "  <confidence>...</confidence>\n"
            "  <reasoning>...</reasoning>\n" # Reasoning is important for VAPA
            "  <feedback>...</feedback>\n" # Feedback drives VAPA
            "</assessment>"
        )

        full_prompt = (
            f"{INST_START} {system_prompt}\n\n{task_prompt}\n\n{gt_block}\n\n{sil_block}\n\n{output_format}\n{INST_END}"
        )
        return full_prompt

    @staticmethod
    def parse_response(response: str) -> Tuple[float, str]: # Return type hint added
        """
        解析 Verifier 响应。依赖 utils.response_parser。
        """
        try:
            # 导入移到函数内部以避免循环依赖问题（如果 response_parser 也导入此文件）
            from vulnsil.utils.response_parser import parse_sil_verifier_response
            return parse_sil_verifier_response(response)
        except ImportError:
            print("错误：无法导入 parse_sil_verifier_response。将使用基本解析。")
            # 基础备用解析（如果导入失败）
            import re
            confidence = 0.0
            feedback = "Error parsing response."
            try:
                confidence_match = re.search(r'<confidence>(.*?)</confidence>', response, re.DOTALL | re.IGNORECASE)
                if confidence_match:
                    confidence = float(confidence_match.group(1).strip())

                feedback_match = re.search(r'<feedback>(.*?)</feedback>', response, re.DOTALL | re.IGNORECASE)
                # 提供默认反馈，以防LLM在置信度高时不产生 feedback 标签
                if feedback_match and feedback_match.group(1).strip():
                     feedback = feedback_match.group(1).strip()
                elif confidence >= config.SIL_CONFIDENCE_THRESHOLD: # Use config threshold
                     feedback = "High confidence, no feedback needed."
                else:
                     feedback = "Low confidence, but feedback extraction failed."

            except Exception as e:
                print(f"解析 Verifier 响应时发生错误: {e}")
                # 保持默认错误值

            return confidence, feedback