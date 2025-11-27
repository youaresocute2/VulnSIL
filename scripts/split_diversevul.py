# scripts/split_diversevul.py
import json
import os
import hashlib
import pandas as pd
import numpy as np
import sys
from collections import Counter

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
    print(f" ⚖️  Real Ratio : {ratio_str} (Vuln:Safe)")

    # CWE 分布展示 (只在有漏洞时展示)
    if n_vuln > 0:
        # 为了统计，临时清洗一列
        cwe_series = df[df['target'] == 1]['cwe'].apply(clean_cwe_for_stats)
        counts = cwe_series.value_counts()
        print("-" * 60)
        print(f" 🔍 Top 10 CWE Breakdown (Positive Samples Only)")
        print("-" * 60)
        for cwe, count in counts.head(10).items():
            pct = (count / n_vuln) * 100
            print(f"   - {cwe:<20} : {count:<6} ({pct:.2f}%)")
    print("=" * 60)


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Error: Input file not found: {INPUT_FILE}")
        sys.exit(1)

    print(f"🚀 Loading raw data from {INPUT_FILE}...")

    train_buffer = []
    test_buffer = []

    # 1. 读取 + Commit 级哈希隔离
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                obj = json.loads(line)

                # 关键字段完整性校验
                if 'target' not in obj:
                    obj['target'] = int(obj.get('label', 0))  # 兼容 label 字段
                else:
                    obj['target'] = int(obj['target'])

                commit_id = obj.get('commit_id', "")

                # Hash 判断 Split
                label = get_hash_split_label(commit_id)

                if label == "train":
                    train_buffer.append(obj)
                else:
                    test_buffer.append(obj)
            except Exception as e:
                continue

    # 转 DataFrame 方便操作，但存储时还是写 JSONL
    df_train = pd.DataFrame(train_buffer)
    df_test = pd.DataFrame(test_buffer)

    print("\n✅ Strict Isolation Split Completed.")

    # 2. 保存 Full Splits (符合 manage_database 要求的 jsonl)
    # [Train Full] -> 用作 RAG 知识库源 (RAG Builder 会自动提取其中的 1)
    file_train_full = os.path.join(OUTPUT_DIR, "train_full.jsonl")
    df_train.to_json(file_train_full, orient='records', lines=True, force_ascii=False)

    # [Test Full] -> 用作 泛化测试源
    file_test_full = os.path.join(OUTPUT_DIR, "test_full.jsonl")
    df_test.to_json(file_test_full, orient='records', lines=True, force_ascii=False)

    # 打印全量统计
    print_detailed_report(df_train, "Train Full Source (Used for RAG filtering)")
    print_detailed_report(df_test, "Test Full Source (Unseen Generalization)")

    # 3. 抽样逻辑 (生成用于训练 LightGBM 校准器的数据集)
    # 逻辑: 取 Train 的 1/8 -> 按 2:3 正负比例重组 -> 正样本按 CWE 加权

    print("\n🏗️  Constructing Calibration Dataset (Sub-sampling Train)...")

    total_train = len(df_train)
    target_subset_size = total_train // 8

    # 2:3 比例 => 40% Vuln, 60% Safe
    target_pos = int(target_subset_size * 0.40)
    target_neg = target_subset_size - target_pos

    pool_pos = df_train[df_train['target'] == 1]
    pool_neg = df_train[df_train['target'] == 0]

    print(f"   -> Target Total Size : {target_subset_size}")
    print(f"   -> Target Positive   : {target_pos} (40%)")
    print(f"   -> Target Negative   : {target_neg} (60%)")

    # 正样本处理
    if len(pool_pos) < target_pos:
        print("⚠️ [Warning] Not enough positives for 40%. Taking ALL available positives.")
        final_pos = pool_pos
        # 维持 2:3 比例调整负样本 => Neg = Pos * (3/2) = Pos * 1.5
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

    # 保存校准数据集
    file_calibration = os.path.join(OUTPUT_DIR, "confidence_train.jsonl")
    df_calibration.to_json(file_calibration, orient='records', lines=True, force_ascii=False)

    print_detailed_report(df_calibration, "Final Calibration Train Set")

    print(f"\n✅ All artifacts generated in '{OUTPUT_DIR}':")
    print(f"   1. {file_train_full} (Use for RAG - Build logic handles filtering)")
    print(f"   2. {file_test_full} (Use for Evaluation)")
    print(f"   3. {file_calibration} (Use for Offline Static Analysis -> Calibration Training)")


if __name__ == "__main__":
    main()