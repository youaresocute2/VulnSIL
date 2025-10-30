# vulnsil/prompts/base_prompt.py

from abc import ABC, abstractmethod
from typing import Any, Dict


class BasePrompt(ABC):
    """
    所有 Prompt 策略的抽象基类。
    这强制所有子类实现两个关键方法：
    1. format_prompt: 构建发送给 LLM 的完整提示词。
    2. parse_response: 解析 LLM 返回的原始字符串。
    """

    def __init__(self, code: str, metadata: Dict[str, Any] = None):
        """
        初始化基类。
        Args:
            code (str): 要分析的源代码。
            metadata (Dict[str, Any], optional):
                其他元数据，例如 vapa_feedback, cwe_id 等。
        """
        self.code = code
        self.metadata = metadata if metadata is not None else {}

    @abstractmethod
    def format_prompt(self) -> str:
        """
        根据 self.code 和 self.metadata 构建最终的提示词字符串。
        """
        pass

    @abstractmethod
    def parse_response(self, response: str) -> Any:
        """
        解析 LLM 的原始响应字符串。
        Args:
            response (str): LLM 返回的原始文本。
        Returns:
            Any: 解析后的结构化数据 (例如 dict, str, tuple)。
        """
        pass