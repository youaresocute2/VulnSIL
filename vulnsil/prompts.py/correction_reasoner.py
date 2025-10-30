import json

INST_START = "[INST]"
INST_END = "[/INST]"


class CorrectionReasonerPrompt:
    """
    使用检索到的源码片段，对 T&V 的初步推理进行修正。
    """

    @staticmethod
    def format_prompt(sil_json: Dict, initial_reasoning_xml: str, snippet: str) -> str:
        system_prompt = (
            "You are a vulnerability expert. Your previous reasoning (Initial Reasoning) "
            "was uncertain because it lacked context about an external call, "
            "as noted in the <uncertainties> tag."
        )

        task_prompt = (
            "A relevant source code snippet has been retrieved. "
            "Re-evaluate your entire reasoning process (Initial Reasoning) "
            "using the new information from the [RETRIEVED SNIPPET].\n"
            "Provide a *new, complete* Think & Verify XML output, "
            "resolving the previous uncertainties."
        )

        full_prompt = (
            f"{INST_START} {system_prompt} {task_prompt}\n\n"
            f"[ORIGINAL SIL]\n{json.dumps(sil_json, indent=2)}\n[/ORIGINAL SIL]\n\n"
            f"[INITIAL REASONING (WITH UNCERTAINTIES)]\n{initial_reasoning_xml}\n[/INITIAL REASONING]\n\n"
            f"[RETRIEVED SNIPPET]\n{snippet}\n[/RETRIEVED SNIPPET]\n\n"
            f"[PROVIDE NEW, COMPLETE T&V XML OUTPUT HERE]\n"
            f"{INST_END}"
        )
        return full_prompt


# `vulnsil/analysis/snippet_retriever.py` (续)
# 我们将修正推理函数也放在这里

def reason_with_snippet(sil_data: Dict, initial_reasoning: str, snippet: str) -> str:
    """
    (步骤 7)
    调用 LLM (T&V) 对 SIL 进行 *修正* 推理。

    Returns:
        新的 T&V XML 响应字符串。
    """
    from vulnsil import llm_client
    from vulnsil.prompts.correction_reasoner import CorrectionReasonerPrompt

    prompt = CorrectionReasonerPrompt.format_prompt(sil_data, initial_reasoning, snippet)

    # 修正推理需要更大的上下文和 token
    raw_response = llm_client.get_llm_response(prompt, temperature=0.1, max_tokens=4096)

    return raw_response