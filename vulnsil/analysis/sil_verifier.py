# vulnsil/analysis/sil_verifier.py

from vulnsil import llm_client
from vulnsil.prompts.sil_verifier import SilVerifierPrompt
from typing import Dict, Any, Tuple


def verify_sil(sil_data: Dict[str, Any], ground_truth_info: Dict[str, Any]) -> Tuple[float, str]:
    """
    调用 LLM 验证 SIL 并获取反馈。
    现在需要传入 ground_truth_info 来进行有监督的评估。
    Args:
        sil_data: LLM 生成的 (并已增强的) SIL JSON.
        ground_truth_info: 包含 'label', 'reason', 'source', 'sink' 的字典。

    Returns:
        (confidence, feedback)
    """
    # 1. 格式化 Prompt (现在传入了真值)
    prompt = SilVerifierPrompt.format_prompt(sil_data, ground_truth_info)

    # 2. 调用 LLM
    raw_response = llm_client.get_llm_response(prompt, temperature=0.1, max_tokens=2048)

    # 3. 解析响应
    confidence, feedback = SilVerifierPrompt.parse_response(raw_response)

    return confidence, feedback