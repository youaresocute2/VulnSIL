# VulnSIL/scripts/tune_agent_threshold.py
import sys
import os
import numpy as np
import typer
import pandas as pd
from sqlalchemy import func

# 适配项目路径，确保能导入 vulnsil 模块
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
from vulnsil.database import get_db_session
from vulnsil.models import AnalysisResultRecord, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("tune_agent_threshold")


@app.command()
def calculate(
        split_name: str = typer.Option(..., help="验证集名称 (例如 'diversevul_val' 或 'confidence_test')"),
        percentile: int = typer.Option(10, help="分位数阈值 (默认10，即保留90%的真阳性样本)"),
        save_to_meta: bool = typer.Option(False, help="是否自动保存建议值到 model_meta.json")
):
    """
    [Agentic Tuning] 计算动态反思阈值
    原理：统计所有被 LLM 正确检出为“漏洞”的样本（True Positives），
    计算其原始置信度(native_confidence)的分布。
    建议阈值 = P(percentile)，意味着低于此置信度的 LLM 报警被视为“信心不足/瞎猜”，
    在 Agent 反思阶段如果不被逻辑证据支持，将被丢弃。
    """
    log.info(f"🔍 正在加载数据集: {split_name} ...")

    with get_db_session() as db:
        # 查询逻辑：
        # 1. 任务执行成功 (status='Success')
        # 2. 属于指定数据集 (name like split_name%)
        # 3. 真实标签是漏洞 (ground_truth_label=1)
        # 4. LLM 原始判定也是漏洞 (final_decision='VULNERABLE') -> 这就是 True Positive
        query = db.query(AnalysisResultRecord.native_confidence).join(Vulnerability).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status == "Success",
            Vulnerability.ground_truth_label == 1,
            AnalysisResultRecord.final_decision == "VULNERABLE"
        )

        results = query.all()

        # 提取置信度列表 (过滤掉 None)
        tp_confs = [r[0] for r in results if r[0] is not None]

    if not tp_confs:
        log.error(f"❌ 未找到任何 True Positive (TP) 样本！请先运行 Pipeline 推理，或者检查数据集名称。")
        return

    total_tp = len(tp_confs)
    log.info(f"📊 统计样本数 (TP): {total_tp}")

    # 计算统计量
    tp_confs = np.array(tp_confs)
    min_conf = np.min(tp_confs)
    max_conf = np.max(tp_confs)
    mean_conf = np.mean(tp_confs)
    median_conf = np.median(tp_confs)

    # 核心：计算分位数 (默认 P10)
    dynamic_threshold = np.percentile(tp_confs, percentile)

    print("\n" + "=" * 60)
    print(f" 📈 Agent 动态阈值分析报告 ({split_name})")
    print("=" * 60)
    print(f" TP 样本总量       : {total_tp}")
    print(f" 置信度范围        : [{min_conf:.4f}, {max_conf:.4f}]")
    print(f" 平均置信度 (Mean) : {mean_conf:.4f}")
    print(f" 中位数 (Median)   : {median_conf:.4f}")
    print("-" * 60)
    print(f" 🎯 建议阈值 (P{percentile})  : {dynamic_threshold:.4f}")
    print(f"    (含义: 只有 {percentile}% 的真实漏洞检出置信度低于此值)")
    print("=" * 60 + "\n")

    # 给出操作建议
    print(f"💡 建议操作: 请修改 config.py 中的 AGENT_MIN_CONFIDENCE_THRESHOLD = {dynamic_threshold:.4f}")

    # 自动保存逻辑 (可选)
    if save_to_meta and os.path.exists(settings.CONFIDENCE_META_PATH):
        try:
            import json
            with open(settings.CONFIDENCE_META_PATH, 'r') as f:
                meta = json.load(f)

            meta['agent_threshold_p10'] = float(dynamic_threshold)

            with open(settings.CONFIDENCE_META_PATH, 'w') as f:
                json.dump(meta, f, indent=2)
            log.info(f"✅ 已将建议值写入: {settings.CONFIDENCE_META_PATH}")
        except Exception as e:
            log.error(f"写入 meta 文件失败: {e}")


if __name__ == "__main__":
    app()