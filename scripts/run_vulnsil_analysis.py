# scripts/run_vulnsil_analysis.py

import json
from sqlalchemy.orm import Session
from sqlalchemy import func
import sys
import os

# 将项目根目录添加到 sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnsil.database import get_db_session
from vulnsil.models import Vulnerability, VulnSILAnalysis
from vulnsil import config
from vulnsil.utils.response_parser import parse_think_verify_response
from vulnsil.analysis.vapa import run_vapa_loop  # (已更新)
from vulnsil.analysis.reasoner import reason_on_sil
from vulnsil.analysis.snippet_retriever import retrieve_code_snippet, reason_with_snippet


def process_vulnerability(db: Session, vuln: Vulnerability):
    """
    对单个漏洞代码执行完整的 VulnSIL 分析流水线。
    现在会将 ground_truth 传递给 VAPA 循环。
    """
    print(f"Processing vulnerability ID: {vuln.id} (Name: {vuln.name})")

    # 检查是否已分析
    existing_analysis = db.query(VulnSILAnalysis).filter(VulnSILAnalysis.vulnerability_id == vuln.id).first()
    if existing_analysis:
        print("Analysis already exists. Skipping.")
        return

    # -------------------------------------------------
    # [新增] 准备 Ground Truth 信息
    ground_truth_info = {
        "label": vuln.ground_truth_label,
        "cwe": vuln.ground_truth_cwe,
        "source": vuln.ground_truth_source,
        "sink": vuln.ground_truth_sink,
        "reason": vuln.ground_truth_reason
    }
    # -------------------------------------------------

    # -------- 1. SIL 生成 与 4. VAPA 迭代循环 --------
    # [已更新] 传入 ground_truth_info
    try:
        final_sil, final_confidence, vapa_history = run_vapa_loop(vuln.code, ground_truth_info)
    except Exception as e:
        print(f"Error during VAPA loop for {vuln.name}: {e}")
        return  # 跳过此样本

    if not final_sil:
        print(f"Failed to generate valid SIL for {vuln.name} after all iterations.")
        # (可选) 保存失败状态
        return

    # -------- 5. SIL 推理 (Think & Verify) --------
    print("--- Starting SIL Reasoning (Think & Verify) ---")
    try:
        # [注意] 推理器 (Reasoner) 不应该看到真值，以保证 Zero-Shot 的公平性
        raw_xml_response = reason_on_sil(final_sil)
    except Exception as e:
        print(f"Error during SIL Reasoning for {vuln.name}: {e}")
        return

    try:
        r_conf, r_decision, r_cwe, uncertainties = parse_think_verify_response(raw_xml_response)
        print(f"Reasoning Confidence: {r_conf}, Decision: {r_decision}")
    except Exception as e:
        print(f"Error parsing T&V response: {e}")
        # (保存错误结果并返回)
        return

    # -------- 6. & 7. 源码检索与修正推理 --------
    if r_conf < config.REASONING_CONFIDENCE_THRESHOLD and uncertainties:

        print(f"Low reasoning confidence ({r_conf}). Triggering Snippet Retrieval...")
        snippet = retrieve_code_snippet(uncertainties, vuln.code)

        if snippet:
            print("Snippet retrieved. Performing Correction Reasoning...")
            raw_xml_response = reason_with_snippet(final_sil, raw_xml_response, snippet)
            try:
                r_conf, r_decision, r_cwe, _ = parse_think_verify_response(raw_xml_response)
                print(f"Correction Reasoning Confidence: {r_conf}, Decision: {r_decision}")
            except Exception:
                print("Failed to parse correction reasoning response.")

    # -------- 8. 保存最终结果 --------
    analysis_entry = VulnSILAnalysis(
        vulnerability_id=vuln.id,
        final_sil_json=json.dumps(final_sil),  # 将 dict 转为 JSON 字符串
        vapa_iterations=json.dumps(vapa_history),  # 将 list 转为 JSON 字符串
        final_sil_confidence=final_confidence,
        reasoning_raw=raw_xml_response,
        reasoning_confidence=r_conf,
        final_decision=r_decision,
        detected_cwe=r_cwe,
        status="Success"  # 标记为成功
    )
    db.add(analysis_entry)
    db.commit()
    print(f"Analysis for {vuln.name} saved successfully.")


def main():
    db_gen = get_db_session()
    db = next(db_gen)
    try:
        # 遍历数据库中的漏洞
        all_vulns = db.query(Vulnerability).all()
        print(f"Found {len(all_vulns)} vulnerabilities in database.")

        # (可选) 计算已完成的数量
        completed_count = db.query(func.count(VulnSILAnalysis.id)).scalar()
        print(f"{completed_count} analyses already completed.")

        for vuln in all_Vulns:
            process_vulnerability(db, vuln)
    except Exception as e:
        print(f"An unexpected error occurred in main loop: {e}")
    finally:
        db.close()
        print("Database session closed.")


if __name__ == "__main__":
    main()