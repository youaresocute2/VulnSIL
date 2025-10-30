from vulnsil import llm_client
from vulnsil.prompts.sil_reasoner import SilThinkVerifyPrompt
from typing import Dict, Any


def reason_on_sil(sil_data: Dict[str, Any]) -> str:
    """
    调用 LLM (T&V) 对 SIL 进行推理。

    Returns:
        原始的 T&V XML 响应字符串。
    """
    prompt = SilThinkVerifyPrompt.format_prompt(sil_data)

    # 推理需要更高的 token 限制
    raw_response = llm_client.get_llm_response(prompt, temperature=0.1, max_tokens=4096)

    return raw_response