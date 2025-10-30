from vulnsil import llm_client
from vulnsil.prompts.sil_generator import SilGeneratorPrompt


def generate_sil(code: str, vapa_feedback: str = None) -> str:
    """
    调用 LLM 生成 SIL。
    Args:
        code: 源代码。
        vapa_feedback: VAPA 反馈 (如果有)。

    Returns:
        LLM 返回的 SIL JSON 字符串 (未解析)。
    """
    # 1. 格式化 Prompt
    prompt = SilGeneratorPrompt.format_prompt(code, vapa_feedback)

    # 2. 调用 LLM
    # (使用低温度确保 SIL 生成的稳定性)
    raw_response = llm_client.get_llm_response(prompt, temperature=0.0, max_tokens=2048)

    # 3. 解析响应 (提取 JSON 块)
    sil_json_str = SilGeneratorPrompt.parse_response(raw_response)

    return sil_json_str