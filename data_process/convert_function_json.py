# data_process/convert_function_json.py
import json
import os
import sys
from tqdm import tqdm

# === 配置部分 ===
# 假设你的原始文件名为 function.json，位于 data 目录下
INPUT_FILE = "data/eval/function.json"
# 输出的 JSONL 文件路径
OUTPUT_FILE = "data/eval/devign.jsonl"


def convert_format():
    # 1. 检查输入文件
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Error: Input file not found: {INPUT_FILE}")
        print("   Please place your 'function.json' in the 'data/' directory.")
        sys.exit(1)

    # 确保输出目录存在
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    print(f"🚀 Loading raw dataset from {INPUT_FILE}...")

    # 2. 读取原始 JSON (通常是一个巨大的 List)
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            # 针对大文件，如果是标准 JSON 格式（即整个文件是一个 [...] 列表），
            # 直接 load 可能会消耗较多内存。但如果文件在几百兆以内通常没问题。
            raw_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ JSON Decode Error: {e}")
        sys.exit(1)

    if not isinstance(raw_data, list):
        print("❌ Error: Expected a JSON list (array) of objects.")
        sys.exit(1)

    print(f"ℹ️  Found {len(raw_data)} records. Converting to VulnSIL schema...")

    # 3. 转换并写入 JSONL
    success_count = 0
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f_out:
        for item in tqdm(raw_data, unit="task"):
            try:
                # --- 字段映射逻辑 ---
                # 1. code: 原始是 'func'，映射为 'code' 以匹配 models.py
                code_content = item.get('func', "")
                if not code_content:
                    continue  # 跳过空代码

                # 2. commit_id: 保持不变，如果没有则设为 "unknown"
                cid = item.get('commit_id', "unknown")

                # 3. target: 保持不变
                target = int(item.get('target', 0))

                # 4. cwe: 原始数据没有，补全为 "N/A"
                cwe = "N/A"

                # 5. project: 保留作为元数据（虽然 DB 可能不直接存，但排查问题有用）
                project = item.get('project', "unknown")

                # 构造新对象
                new_obj = {
                    "commit_id": cid,
                    "code": code_content,
                    "target": target,
                    "cwe": cwe,
                    "project": project
                }

                # 写入一行
                f_out.write(json.dumps(new_obj, ensure_ascii=False) + "\n")
                success_count += 1
            except Exception as e:
                # 忽略单行错误，继续处理
                continue

    print("\n" + "=" * 60)
    print(f" ✅ Conversion Complete!")
    print(f" 📂 Output File: {OUTPUT_FILE}")
    print(f" 📊 Total Converted: {success_count} / {len(raw_data)}")
    print("=" * 60)

    # 打印导入提示
    split_name = "function_eval"  # 你可以自定义这个名字
    print(f"\n🚀 To import this into the database, run:")
    print(f"   python scripts/manage_database.py --import_file \"{OUTPUT_FILE}\" --split_name \"{split_name}\"")


if __name__ == "__main__":
    convert_format()