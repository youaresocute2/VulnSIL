# vulnsil/analysis/vapa.py

import json
from typing import Tuple, List, Dict, Any
from .. import config
from .sil_generator import generate_sil  # 步骤 1
from .sil_enricher import enrich_sil  # 步骤 2
from .sil_verifier import verify_sil  # 步骤 3 (已更新)


def run_vapa_loop(code: str, ground_truth_info: Dict[str, Any]) -> Tuple[Dict[str, Any] | None, float, List[Dict]]:
    """
    执行完整的 VAPA (Verifier-Aware Prompt Adaptation) 迭代循环。
    现在接受 ground_truth_info 以便 Verifier 进行有监督的验证。

    Args:
        code (str): 要分析的 C/C++ 源代码。
        ground_truth_info (Dict): 包含 'label', 'reason' 等的真值字典。

    Returns:
        (final_sil_data, final_confidence, vapa_history)
    """

    vapa_history = []
    current_vapa_feedback = None
    final_sil_data = None
    final_confidence = 0.0

    for i in range(config.MAX_VAPA_ITERATIONS):
        print(f"--- VAPA Iteration {i + 1}/{config.MAX_VAPA_ITERATIONS} ---")

        # 步骤 1: 生成 SIL (VAPA 反馈在这里被注入)
        sil_json_str = generate_sil(code, current_vapa_feedback)

        # 步骤 2: SIL 增强 (静态分析)
        try:
            sil_data = json.loads(sil_json_str)
            enriched_sil_data = enrich_sil(sil_data, code)
            print("SIL enriched successfully.")
        except json.JSONDecodeError as e:
            print(f"Error: SIL Generator did not return valid JSON. {e}")
            vapa_history.append({
                "iter": i + 1,
                "raw_sil_str": sil_json_str,
                "feedback": "Invalid JSON output from Generator.",
                "confidence": 0.0
            })
            current_vapa_feedback = "The previous output was not valid JSON. Ensure correct JSON format."
            continue

            # -------------------------------------------------
        # 步骤 3: SIL 验证 (核心修改)
        # [已更新] 传入 ground_truth_info
        confidence, feedback = verify_sil(enriched_sil_data, ground_truth_info)
        # -------------------------------------------------

        print(f"SIL Confidence (vs Ground Truth): {confidence:.2f}")

        vapa_history.append({
            "iter": i + 1,
            "sil": enriched_sil_data,
            "feedback": feedback,
            "confidence": confidence
        })

        # 步骤 4: VAPA 决策
        if confidence >= config.SIL_CONFIDENCE_THRESHOLD:
            print("High confidence SIL achieved (aligned with GT). Exiting VAPA loop.")
            final_sil_data = enriched_sil_data
            final_confidence = confidence
            break
        else:
            print(f"Low confidence. Feedback: {feedback}")
            current_vapa_feedback = feedback

        final_sil_data = enriched_sil_data
        final_confidence = confidence

    return final_sil_data, final_confidence, vapa_history