import httpx
from openai import OpenAI, HttpxClient
from tenacity import retry, stop_after_attempt, wait_exponential
from typing import List, Dict, Any

from . import config

# 初始化 vLLM 客户端
# 我们使用 HttpxClient 来设置较长的超时时间，vLLM 推理可能较慢
http_client = HttpxClient(
    base_url=config.VLLM_API_BASE,
    timeout=300.0,  # 默认 60s 可能不够，增加到 300s
)

# 确保我们使用的是 OpenAI v1.0+ 的 API
# 如果您的环境配置.md 中的 openai 版本较低，请升级
client = OpenAI(
    api_key=config.VLLM_API_KEY,
    base_url=config.VLLM_API_BASE,
    http_client=http_client,
)


@retry(wait=wait_exponential(multiplier=1, min=4, max=60), stop=stop_after_attempt(5))
def get_llm_response(prompt: str, temperature: float = 0.0, max_tokens: int = 4096) -> str:
    """
    从本地 vLLM 服务器获取响应。
    我们使用 CodeLlama-Instruct 的特定格式。

    Args:
        prompt: 完整的提示词内容。
        temperature: 温度参数，0.0 表示确定性输出。
        max_tokens: 最大生成 token 数。

    Returns:
        LLM 生成的文本响应。
    """
    try:
        # CodeLlama-Instruct-hf 使用 [INST] 和 [/INST] 标签
        # 确保您的 prompt 遵循这个格式 (我们将在 prompts 模块中处理)
        # 这里的 'prompt' 变量应该是已经格式化好的

        # vLLM 的 OpenAI API 使用 'chat.completions'
        response = client.chat.completions.create(
            model=config.VLLM_MODEL_NAME,
            messages=[
                {"role": "user", "content": prompt}
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            stop=None,  # 可以定义停止词，例如 "```"
        )

        # 提取响应内容
        content = response.choices[0].message.content
        return content.strip()

    except Exception as e:
        print(f"Error connecting to vLLM server: {e}")
        # 抛出异常以触发 tenacity 重试
        raise