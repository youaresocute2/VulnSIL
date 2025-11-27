# data_process/sample_test_subset.py
import pandas as pd
import os
import sys
import json
import numpy as np

# 路径适配
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# === 配置部分 ===
# 注意：根据你的报错，你的文件似乎在 data/eval/ 目录下
# 如果你的文件在 data/dataset_final/ 下，请修改这里
INPUT_TEST_FILE = "data/eval/test_full.jsonl"
# 如果你的实际路径是 data/eval/test_full.jsonl，请取消下面这行的注释并注释上面那行
# INPUT_TEST_FILE = "data/eval/test_full.jsonl"

OUTPUT_FILE = "data/eval/diversevul_test_5k.jsonl"
SAMPLE_SIZE = 5000
SEED = 42


def clean_cwe_for_stats(raw_val):
    """清洗 CWE 字段用于统计"""
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
    """打印详细的分布统计"""
    total = len(df)
    if total == 0:
        print(f"\n❌ [{name}] is Empty!")
        return

    # 兼容 target 或 label 字段
    if 'target' in df.columns:
        target_col = 'target'
    else:
        target_col = 'label'

    n_vuln = len(df[df[target_col] == 1])
    n_safe = len(df[df[target_col] == 0])

    vuln_rate = (n_vuln / total) * 100
    safe_rate = (n_safe / total) * 100

    print("\n" + "=" * 60)
    print(f" 📊 DATASET SUBSET REPORT: {name}")
    print("=" * 60)
    print(f" 📦 Total Samples : {total}")
    print(f" 🔴 Vuln (1)      : {n_vuln:<8} ({vuln_rate:.2f}%)")
    print(f" 🟢 Safe (0)      : {n_safe:<8} ({safe_rate:.2f}%)")

    if n_vuln > 0 and 'cwe' in df.columns:
        cwe_series = df[df[target_col] == 1]['cwe'].apply(clean_cwe_for_stats)
        counts = cwe_series.value_counts()
        print("-" * 60)
        print(f" 🔍 CWE Distribution Breakdown (Top 20)")
        print("-" * 60)
        print(f" {'CWE ID':<25} | {'Count':<8} | {'Ratio':<10}")
        print("-" * 60)
        for cwe, count in counts.head(20).items():
            pct = (count / n_vuln) * 100
            print(f" {cwe:<25} | {count:<8} | {pct:.2f}%")
    print("=" * 60 + "\n")


def main():
    if not os.path.exists(INPUT_TEST_FILE):
        print(f"❌ Error: Input file not found: {INPUT_TEST_FILE}")
        print("   Please check the path or run 'python scripts/split_diversevul.py' first.")
        sys.exit(1)

    print(f"🚀 Loading full test set from {INPUT_TEST_FILE}...")

    # [核心修复] 使用原生 json 逐行读取，避免 Pandas 的 int64 溢出问题
    data = []
    try:
        with open(INPUT_TEST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    data.append(json.loads(line))

        # 将 list 转为 DataFrame
        df = pd.DataFrame(data)

    except Exception as e:
        print(f"❌ Load error: {e}")
        sys.exit(1)

    total_records = len(df)
    print(f"ℹ️  Full test set size: {total_records}")

    if total_records < SAMPLE_SIZE:
        print(f"⚠️ Warning: Total records ({total_records}) < Requested Sample ({SAMPLE_SIZE}).")
        print("   Taking all available records.")
        sample_df = df
    else:
        print(f"🎲 Randomly sampling {SAMPLE_SIZE} records (Seed={SEED})...")
        sample_df = df.sample(n=SAMPLE_SIZE, random_state=SEED)

    print_detailed_report(sample_df, f"Test Subset (5k)")

    os.makedirs(os.path.dirname(os.path.abspath(OUTPUT_FILE)), exist_ok=True)

    print(f"💾 Saving subset to: {OUTPUT_FILE}")
    sample_df.to_json(OUTPUT_FILE, orient='records', lines=True, force_ascii=False)

    print("✅ Done! You can now import this file into the database.")
    print(
        f"   Command: python scripts/manage_database.py --import_file \"{OUTPUT_FILE}\" --split_name diversevul_test_5k")


if __name__ == "__main__":
    main()