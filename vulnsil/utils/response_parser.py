# vulnsil/utils/response_parser.py

import xml.etree.ElementTree as ET
import re
import json
from typing import Dict, Any, Tuple


def parse_think_verify_response(response_xml: str) -> Tuple[float, str, str | None, str]:
    """
    解析 SIL Reasoner (T&V) 的 XML 输出。
    Returns:
        Tuple[float, str, str | None, str]:
        (confidence, final_decision, detected_cwe (now None), uncertainties)
    """
    if not response_xml:
        return 0.0, "Error: No Response", None, "" # 返回 None 表示无 CWE

    assessment_xml = extract_xml_content(response_xml, 'assessment')

    if assessment_xml:
        decision = extract_xml_content(assessment_xml, 'vulnerability') or "NO" # 默认 NO
        detected_cwe = None # 明确设置为 None
    else:
        decision = "Error: Parse Fail"
        detected_cwe = None

    confidence_str = extract_xml_content(response_xml, 'confidence')
    confidence = 0.0
    if confidence_str:
        match = re.search(r'(\d+(\.\d+)?)', confidence_str)
        if match:
            try:
                confidence = float(match.group(1)) / 100.0 # 归一化到 0.0 - 1.0
            except ValueError:
                confidence = 0.0

    uncertainties = extract_xml_content(response_xml, 'uncertainties') or ""

    final_decision = "YES" if "YES" in decision.upper() else "NO"
    # 如果 decision 是错误状态，也归为 "NO" 或专门的错误标记，这里简化为 "NO"
    if "Error" in decision:
        final_decision = "NO" # 或者可以返回一个特定的错误代码

    return confidence, final_decision, detected_cwe, uncertainties # 返回 None 作为 CWE
