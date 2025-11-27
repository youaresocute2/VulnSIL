# data_process/split_diversevul.py
import json
import os
import hashlib
import pandas as pd
import numpy as np
import sys
from collections import Counter
from config import settings  # 新增：统一参数

# === 路径配置 ===
# 请确认这是您本地的原始数据集路径
INPUT_FILE = "data/diversevul.json"
# 输出目录
OUTPUT_DIR = "data/dataset_final"

# 随机种子，保证每次运行结果一致
SEED = 42

os.makedirs(OUTPUT_DIR, exist_ok=True)


def get_hash_split_label(commit_id, ratio=0.8):
    """
    Commit-level 物理隔离 (Hash取模)
    """
    if not commit_id: return "train"
    # 使用 sha256 避免 MD5 碰撞风险，虽然在取模100的情况下区别不大
    h = int(hashlib.sha256(str(commit_id).encode('utf-8')).hexdigest(), 16)
    return "train" if (h % 100) < (ratio * 100) else "test"


def clean_cwe_for_stats(raw_val):
    """
    仅用于Pandas统计和分层抽样计算，不修改原始数据结构
    """
    if isinstance(raw_val, list) and len(raw_val) > 0:
        val = str(raw_val[0])
    elif isinstance(raw_val, str):
        val = raw_val
    else:
        val = "Other"

    val = val.strip().upper()
    if val in ["NON", "N/A", "NONE", "NULL", "", "[]"]: return "Other"
    return val


def print_detailed_report(df, name):
    """
    详细的数据统计面板
    """
    total = len(df)
    if total == 0:
        print(f"\n❌ [{name}] is Empty!")
        return

    n_vuln = len(df[df['target'] == 1])
    n_safe = len(df[df['target'] == 0])

    vuln_rate = (n_vuln / total) * 100
    safe_rate = (n_safe / total) * 100

    ratio_str = f"1 : {n_safe / n_vuln:.2f}" if n_vuln > 0 else "N/A"

    print("\n" + "=" * 60)
    print(f" 📊 DATASET REPORT: {name}")
    print("=" * 60)
    print(f" 📦 Total Rows : {total}")
    print(f" 🔴 Vuln (1)   : {n_vuln:<8} ({vuln_rate:.2f}%)")
    print(f" 🟢 Safe (0)   : {n_safe:<8} ({safe_rate:.2f}%)")
    print(f" ⚖️ Ratio      : {ratio_str}")
    print("=" * 60 + "\n")


def main():
    """
    主函数：切分数据集 [改进] 加时间切分（假设有'date'）
    """
    with open(INPUT_FILE, 'r') as f:
        raw_data = [json.loads(line) for line in f if line.strip()]

    # [改进] 时间切分（假设有'date'，否则用commit_id代理时间顺序）
    # 排序date (假设格式'YYYY-MM-DD')
    raw_data.sort(key=lambda x: x.get('date', '0000-00-00'))

    time_split_idx = int(len(raw_data) * settings.TIME_SPLIT_RATIO)
    time_train = raw_data[:time_split_idx]
    time_test = raw_data[time_split_idx:]

    # 哈希切分结合
    train_full = [d for d in time_train if get_hash_split_label(d.get('commit_id', '')) == "train"]
    test_full = [d for d in time_test if get_hash_split_label(d.get('commit_id', '')) == "test"]

    # 原版平衡采样 (calibration)
    df_train = pd.DataFrame(train_full)
    pool_pos = df_train[df_train['target'] == 1]
    pool_neg = df_train[df_train['target'] == 0]

    target_pos = int(0.4 * len(df_train))
    target_neg = int(0.6 * len(df_train))

    # 正样本处理
    if len(pool_pos) < target_pos:
        print("⚠️ [Warning] Not enough positives for 40%. Taking ALL available positives.")
        final_pos = pool_pos
        target_neg = int(len(final_pos) * 1.5)
        print(f"   -> Adjusted Negative Target: {target_neg}")
    else:
        # 构造抽样权重
        temp_cwe_col = pool_pos['cwe'].apply(clean_cwe_for_stats)
        counts = temp_cwe_col.value_counts()
        # 平滑处理：权重 = sqrt(count)
        weights_map = counts ** 0.5
        weights_map = weights_map / weights_map.sum()

        # 映射回每一行
        row_weights = temp_cwe_col.map(weights_map)

        final_pos = pool_pos.sample(n=target_pos, weights=row_weights, random_state=SEED)

    # 负样本处理 (纯随机，模拟真实噪音分布)
    final_neg = pool_neg.sample(n=target_neg, random_state=SEED)

    # 合并 + Shuffle
    df_calibration = pd.concat([final_pos, final_neg]).sample(frac=1, random_state=SEED)

    # 保存
    file_train_full = os.path.join(OUTPUT_DIR, "diversevul_train.jsonl")
    df_train.to_json(file_train_full, orient='records', lines=True, force_ascii=False)

    file_test_full = os.path.join(OUTPUT_DIR, "diversevul_test.jsonl")
    pd.DataFrame(test_full).to_json(file_test_full, orient='records', lines=True, force_ascii=False)

    file_calibration = os.path.join(OUTPUT_DIR, "confidence_train.jsonl")
    df_calibration.to_json(file_calibration, orient='records', lines=True, force_ascii=False)

    print_detailed_report(df_train, "Final Train Set")
    print_detailed_report(pd.DataFrame(test_full), "Final Test Set")
    print_detailed_report(df_calibration, "Final Calibration Train Set")

    print(f"\n✅ All artifacts generated in '{OUTPUT_DIR}':")
    print(f"   1. {file_train_full} (Use for RAG - Build logic handles filtering)")
    print(f"   2. {file_test_full} (Use for Evaluation)")
    print(f"   3. {file_calibration} (Use for Offline Static Analysis -> Calibration Training)")


if __name__ == "__main__":
    main()