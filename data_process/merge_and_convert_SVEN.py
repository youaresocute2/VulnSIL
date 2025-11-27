# data_process/merge_and_convert_SVEN.py
import os
import json
import argparse
from tqdm import tqdm


def extract_commit_id(link):
    """从 URL 中提取 commit hash"""
    if not link:
        return "unknown"
    try:
        # 常见格式: .../commit/e34bcbb...
        if 'commit/' in link:
            return link.split('commit/')[-1].split('/')[0]
        return link.split('/')[-1]
    except:
        return "unknown"


def normalize_cwe(raw_cwe):
    """
    标准化 CWE ID:
    1. 强制大写 (cwe-787 -> CWE-787)
    2. 移除列表格式 (['CWE-787'] -> CWE-787)
    3. 处理空值
    """
    if not raw_cwe:
        return "N/A"

    # 如果是列表，取第一个
    if isinstance(raw_cwe, list):
        if len(raw_cwe) > 0:
            raw_cwe = str(raw_cwe[0])
        else:
            return "N/A"

    val = str(raw_cwe).strip().upper()

    # 简单清洗：移除可能存在的引号或括号（针对之前的 dirty 数据）
    val = val.replace("['", "").replace("']", "").replace('["', "").replace('"]', "")

    if val in ["", "NON", "NONE", "NULL", "N/A"]:
        return "N/A"

    return val


def process_and_merge(input_root, output_file):
    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    total_files = 0
    all_jsonl_files = []

    # 1. 扫描所有文件
    print(f"🔍 Scanning directory: {input_root}")
    for root, dirs, files in os.walk(input_root):
        for file in files:
            if file.endswith(".jsonl"):
                all_jsonl_files.append(os.path.join(root, file))
                total_files += 1

    print(f"📄 Found {total_files} JSONL files. Starting merge & conversion...")

    count = 0
    skipped = 0

    # 2. 处理并写入
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for file_path in tqdm(all_jsonl_files, desc="Merging"):
            with open(file_path, 'r', encoding='utf-8') as infile:
                for line in infile:
                    line = line.strip()
                    if not line: continue
                    try:
                        raw = json.loads(line)

                        # --- 提取基础信息 ---
                        cid = extract_commit_id(raw.get('commit_link', ''))

                        # [修改点] 统一 CWE 格式
                        raw_cwe = raw.get('vul_type', 'N/A')
                        cwe = normalize_cwe(raw_cwe)

                        func_name = raw.get('func_name', '')

                        # --- 生成样本 1: 漏洞代码 (Before) ---
                        if raw.get('func_src_before'):
                            entry_vuln = {
                                "commit_id": cid,
                                "func": raw['func_src_before'],
                                "target": 1,  # 标记为漏洞
                                "cwe": cwe,  # 使用标准化后的 CWE
                                "func_name": func_name,
                                "origin_source": "before"
                            }
                            outfile.write(json.dumps(entry_vuln) + "\n")
                            count += 1

                        # --- 生成样本 2: 修复代码 (After) ---
                        if raw.get('func_src_after'):
                            entry_safe = {
                                "commit_id": cid,
                                "func": raw['func_src_after'],
                                "target": 0,  # 标记为安全
                                "cwe": cwe,  # 同样标记 CWE (表示这是该 CWE 的修复样本)
                                "func_name": func_name,
                                "origin_source": "after"
                            }
                            outfile.write(json.dumps(entry_safe) + "\n")
                            count += 1

                    except Exception as e:
                        skipped += 1
                        continue

    print("\n" + "=" * 50)
    print(f"✅ Merge Complete!")
    print(f"📂 Output File: {output_file}")
    print(f"📊 Total Samples Generated: {count}")
    print(f"⚠️ Skipped Lines (Errors): {skipped}")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge and convert raw vulnerability datasets to VulnSIL format.")
    parser.add_argument("--input_dir", default="data/data_train_val", help="Root directory of source JSONL files")
    parser.add_argument("--output_file", default="data/eval/SVEN.jsonl",
                        help="Path to the output merged JSONL")

    args = parser.parse_args()

    process_and_merge(args.input_dir, args.output_file)