# vulnsil/analysis/snippet_retriever.py

import re
from typing import Dict, Any, Optional


def retrieve_code_snippet(uncertainties: str, full_code: str) -> Optional[str]:
    """
    [非 LLM]
    根据 T&V 推理中的 <uncertainties> 标签内容，从原始代码中检索相关片段。

    [限制] 鉴于数据集格式，此函数只能在 'full_code' (即当前函数体)
    内部进行搜索。它无法解析 #include 或查找项目中的其他文件。
    Args:
        uncertainties: T&V <uncertainties> 标签的文本内容。
        full_code: 原始的 C/C++ 完整代码。

    Returns:
        相关的代码片段 (例如，函数定义)，或 None。
    """
    print(f"Retrieving snippet based on uncertainty: '{uncertainties}'")

    # 模式 1：查找不确定的函数调用
    # "uncertainty about function call 'some_sink_func'"
    # "ambiguity in call to 'external_func'"
    match = re.search(r"call (to|about) (function|func)\s*'?\"?([a-zA-Z0-9_]+)'?\"?", uncertainties, re.IGNORECASE)

    if not match:
        # 模式 2：查找不确定的变量
        # "nature of variable 'data' is unclear"
        match = re.search(r"(variable|var)\s*'?\"?([a-zA-Z0-9_]+)'?\"?", uncertainties, re.IGNORECASE)

    if not match:
        print("  -> No clear function or variable name found in uncertainty text.")
        return None

    target_name = match.group(3)
    print(f"  -> Identified target name: '{target_name}'")

    # [限制] 我们只能在 full_code 字符串中搜索
    # 尝试 1: 查找目标 *函数定义* (如果它是一个本地定义的 static/inline 函数)
    # (这是一个简化的 C 函数 regex)
    func_pattern = re.compile(
        # e.g., "static void my_func ( char * arg ) {"
        r"(static|inline)?\s*\w+\s+" + re.escape(target_name) + r"\s*\(.*?\)\s*\{.*?\}",
        re.DOTALL | re.MULTILINE
    )

    snippet_match = func_pattern.search(full_code)
    if snippet_match:
        print(f"  -> Found definition for function '{target_name}' in code.")
        return snippet_match.group(0)

    # 尝试 2: 查找目标 *变量定义*
    # e.g., "char * data_buf [ 100 ] ;"
    var_pattern = re.compile(
        r".*?" + re.escape(target_name) + r"\s*\[.*?\]\s*;",
        re.IGNORECASE
    )
    snippet_match = var_pattern.search(full_code)
    if snippet_match:
        print(f"  -> Found definition for variable '{target_name}' in code.")
        return snippet_match.group(0).strip()

    print(f"  -> Could not find snippet for '{target_name}' within the provided code.")
    return None


# ----------------------------------------------
# (修正推理)
# ----------------------------------------------
from vulnsil import llm_client
from vulnsil.prompts.correction_reasoner import CorrectionReasonerPrompt


def reason_with_snippet(sil_data: Dict, initial_reasoning: str, snippet: str) -> str:
    """
    (步骤 7)
    调用 LLM (T&V) 对 SIL 进行 *修正* 推理。

    Returns:
        新的 T&V XML 响应字符串。
    """
    prompt = CorrectionReasonerPrompt.format_prompt(sil_data, initial_reasoning, snippet)

    # 修正推理需要更大的上下文和 token
    raw_response = llm_client.get_llm_response(prompt, temperature=0.1, max_tokens=4096)

    return raw_response