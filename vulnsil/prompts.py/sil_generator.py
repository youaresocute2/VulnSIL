# vulnsil/prompts/sil_generator.py

import os
import re # 保留 re 用于备用解析

# -----------------------------------------------------------
# [核心修改] 从新文件中导入 Schema 和 示例
# -----------------------------------------------------------
try:
    # 使用相对导入确保在包内正确工作
    from .sil_schema_definition import SIL_SCHEMA_DEFINITION
    from .sil_few_shot_examples import FEW_SHOT_EXAMPLES
except ImportError as e:
    print(f"错误：无法导入 SIL schema 或示例: {e}。请确保 "
          "'sil_schema_definition.py' 和 'sil_few_shot_examples.py' 文件存在于 prompts 目录下。")
    # 提供备用的空字符串以防止程序崩溃，但生成会失败
    SIL_SCHEMA_DEFINITION = "# 错误：未找到 SIL Schema 定义。"
    FEW_SHOT_EXAMPLES = "[错误：未找到 Few-Shot 示例。]"


# CodeLlama-Instruct 的模板标签
INST_START = "[INST]"
INST_END = "[/INST]"


class SilGeneratorPrompt:
    """
    [最终版本 V1.2 - 重构版]
    生成 SIL 的 Prompt 类。
    从此版本开始，Schema 定义和 Few-Shot 示例从外部文件导入。
    """

    @staticmethod
    def format_prompt(code: str, vapa_feedback: str = None) -> str:
        """
        构建用于 SIL 生成的完整提示词。

        Args:
            code (str): C/C++ 源代码。
            vapa_feedback (str, optional): 来自 SIL Verifier 的结构化反馈。 Defaults to None.

        Returns:
            str: 准备好发送给 LLM 的完整 Prompt 字符串。
        """
        system_prompt = (
            "You are an expert static analysis tool. Your task is to analyze the "
            "provided C/C++ code and convert it *strictly* into the Semantic Intermediate "
            "Language (SIL) JSON format defined below. Focus *only* on security-critical operations."
        )

        # 使用导入的 Schema
        schema_prompt = f"\n\n[SIL SPECIFICATION]\n{SIL_SCHEMA_DEFINITION}\n[/SIL SPECIFICATION]"

        feedback_prompt = ""
        if vapa_feedback:
            feedback_prompt = (
                f"\n\n[PREVIOUS ATTEMPT FEEDBACK]\n"
                f"Your previous SIL generation was analyzed. Please regenerate the SIL, "
                f"paying close attention to the following feedback:\n"
                f"'{vapa_feedback}'\n"
                f"Ensure your new output *strictly* follows the [SIL SPECIFICATION].\n"
                f"[END FEEDBACK]"
            )

        # 使用导入的示例
        examples = f"\n\nHere are examples of applying the specification:\n{FEW_SHOT_EXAMPLES}"

        task_prompt = (
            "\n\nNow, analyze the following code. Provide *only* the JSON output "
            "inside a single ```json ... ``` block. Do not add any other text or explanation."
        )
        code_block = f"\n\n[CODE]\n{code}\n[/CODE]\n\n[SIL]\n"

        # 组合 Prompt
        full_prompt = (
            f"{INST_START} {system_prompt} {schema_prompt} {feedback_prompt} {examples} "
            f"{task_prompt} {code_block} {INST_END}"
        )
        return full_prompt

    @staticmethod
    def parse_response(response: str) -> str:
        """
        解析 LLM 的原始响应，提取 JSON 块。

        Args:
            response (str): LLM 返回的原始文本。

        Returns:
            str: 提取出的 JSON 字符串，如果提取失败则返回原始响应。
        """
        try:
            # 优先使用我们 utils 中的解析器
            # 注意：这里的导入路径假设 response_parser 在 utils 目录下
            from vulnsil.utils.response_parser import parse_sil_generator_response
            return parse_sil_generator_response(response)
        except ImportError:
            # 如果导入失败，使用备用的基本正则解析
            print("警告：无法从 utils 导入 parse_sil_generator_response。将使用基本的正则表达式备用方案。")
            # 尝试匹配 ```json ... ``` 块
            json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
            if json_match: return json_match.group(1).strip()
            # 尝试匹配可能直接输出的 JSON 对象（覆盖整个响应）
            json_match_curly = re.search(r'^\s*({.*})\s*$', response, re.DOTALL)
            if json_match_curly: return json_match_curly.group(1).strip()
            # 如果都找不到，返回原始响应，让调用者处理可能的 JSON 解析错误
            print("警告：无法使用正则表达式提取 JSON 块。将返回原始响应。")
            return response.strip()