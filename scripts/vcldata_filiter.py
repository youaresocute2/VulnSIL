# vcldata_filiter.py
import json
import argparse
import os
from collections import Counter
import logging
import random # 导入 random 模块

# --- 配置日志 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# --- ★★★ 筛选配置 ★★★ ---
# 1. 目标 CWE 编号集合 (限定脆弱和相关安全样本的范围)
TARGET_CWES = {
    # 缓冲区溢出 / 内存越界 (VulnSIL Targets)
    "CWE-120", "CWE-121", "CWE-122", "CWE-787",
    # 空指针引用 (VulnSIL Target)
    "CWE-476",
    # 格式化字符串 (VulnSIL Target)
    "CWE-134",
    # 资源泄露 (VulnSIL Targets)
    "CWE-772", "CWE-401", "CWE-404",
    # 输入验证缺陷 (部分相关 CWE 来自数据集.md)
    "CWE-22", "CWE-129", "CWE-369",
    # 命令注入 (VulnSIL Target)
    "CWE-78",
    # --- 根据需要添加/删除 CWE ---
}
logging.info(f"初始化目标 CWE 集合，包含 {len(TARGET_CWES)} 个 CWE。")
logging.info(f"目标 CWEs: {', '.join(sorted(list(TARGET_CWES)))}")

# --- 脚本主要逻辑 ---

def load_data(filepath: str) -> list:
    """从JSON文件加载数据集 (优先尝试 JSON Lines)。"""
    # (加载逻辑与 filter_vcldata_revised.py 相同，此处省略以简洁)
    if not os.path.exists(filepath):
        logging.error(f"输入文件未找到: {filepath}")
        return []
    try:
        data = []
        lines_processed = 0
        jsonl_mode = True # 假设是 JSON Lines
        with open(filepath, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                lines_processed += 1
                try:
                    if line.strip():
                        data.append(json.loads(line))
                except json.JSONDecodeError as line_err:
                    if i == 0:
                        logging.warning(f"第一行解析失败，尝试按 JSON 列表格式加载... 错误: {line_err}")
                        jsonl_mode = False
                        break
                    else:
                        logging.warning(f"跳过无法解析的行 {i+1}: {line_err}. 内容: {line.strip()}")

            if not jsonl_mode:
                f.seek(0)
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        logging.info(f"成功加载 {len(data)} 条记录 (JSON 列表格式)。")
                        return data
                    else:
                        logging.error(f"文件 {filepath} 不是有效的 JSON 列表或 JSON Lines 格式。")
                        return []
                except json.JSONDecodeError as list_err:
                     logging.error(f"无法将 {filepath} 作为 JSON 列表或 JSON Lines 加载: {list_err}")
                     return []
            elif data:
                 logging.info(f"成功加载 {len(data)} 条记录 (JSON Lines 格式)。")
                 return data
            else:
                 logging.warning(f"文件 {filepath} 为空或所有行都无法解析。")
                 return []

    except Exception as e:
        logging.error(f"加载文件 {filepath} 时发生未知错误: {e}")
        return []


def filter_and_count_data(data: list) -> (list, Counter):
    """
    筛选数据：保留 label='1' 且 CWE 在 TARGET_CWES 中的样本，
    以及 label='0' 且 CWE 也在 TARGET_CWES 中的样本。
    """
    filtered_data = []
    # 统计: 'secure_relevant' 用于相关的安全样本, CWE-ID 用于脆弱样本
    stats = Counter()

    logging.info(f"开始筛选 {len(data)} 条记录，仅保留与目标 CWE 相关的样本...")

    processed_count = 0
    skipped_invalid_structure = 0
    skipped_unrelated = 0 # 统计所有因与目标CWE无关而被跳过的样本

    for sample in data:
        processed_count += 1
        label = sample.get('label')
        func_code = sample.get('func')

        # 基本结构检查
        if label is None or func_code is None or not isinstance(func_code, str) or not func_code.strip():
            logging.warning(f"记录缺少 'label' 或有效的 'func' 字段，已跳过。记录内容 (开头): {str(sample)[:100]}...")
            skipped_invalid_structure += 1
            continue

        # 标准化 cwe_id 字段
        cwe_field = sample.get('cwe_id')
        cwe_ids_in_sample = set()
        raw_cwe_list = []
        if isinstance(cwe_field, str) and cwe_field.strip().lower() not in ['none', '']:
            raw_cwe_list = [cwe_field.strip()]
        elif isinstance(cwe_field, list):
            raw_cwe_list = [str(item).strip() for item in cwe_field if isinstance(item, (str, int)) and str(item).strip().lower() not in ['none', '']]

        is_target_related = False
        matched_cwe_for_vuln = None # 用于记录脆弱样本匹配到的第一个目标CWE
        for raw_cwe in raw_cwe_list:
            cwe_num_only = raw_cwe.replace("CWE-", "")
            if cwe_num_only.isdigit():
                standardized_cwe = f"CWE-{cwe_num_only}"
                cwe_ids_in_sample.add(standardized_cwe) # 添加到集合中供后续检查
                if standardized_cwe in TARGET_CWES:
                    is_target_related = True
                    if label == "1" and matched_cwe_for_vuln is None:
                        matched_cwe_for_vuln = standardized_cwe
                    # 对于 label="0", 只要有一个相关就行，不需要记录具体哪个CWE

        # --- 根据标签和相关性进行筛选 ---
        keep_sample = False
        if label == "1" and is_target_related:
            keep_sample = True
            stats[matched_cwe_for_vuln] += 1 # 按匹配到的目标CWE统计脆弱样本
        elif label == "0" and is_target_related:
            keep_sample = True
            stats['secure_relevant'] += 1 # 统计相关的安全样本
        else:
            # label="0" 但不相关，或 label="1" 但不相关，或 label 非 0/1
            skipped_unrelated += 1

        if keep_sample:
            filtered_data.append(sample)

    logging.info(f"筛选完成。")
    logging.info(f"共处理记录数: {processed_count}")
    logging.info(f"因结构无效/字段缺失跳过: {skipped_invalid_structure}")
    logging.info(f"因与目标 CWE 无关跳过 (包括安全和非目标脆弱样本): {skipped_unrelated}")
    logging.info(f"筛选后保留的总记录数: {len(filtered_data)}")

    return filtered_data, stats

def save_data(data: list, filepath: str):
    """将筛选后的数据保存到JSON文件或JSON Lines文件。"""
    # (保存逻辑与 filter_vcldata_revised.py 相同，此处省略以简洁)
    if not data:
        logging.warning("Filtered data is empty. No output file will be created.")
        return
    try:
        output_dir = os.path.dirname(filepath)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            logging.info(f"Created output directory: {output_dir}")

        if filepath.lower().endswith('.jsonl'):
            with open(filepath, 'w', encoding='utf-8') as f:
                for item in data:
                    f.write(json.dumps(item, ensure_ascii=False) + '\n')
            logging.info(f"Saved {len(data)} filtered records as JSON Lines to: {filepath}")
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logging.info(f"Saved {len(data)} filtered records as JSON List to: {filepath}")

    except Exception as e:
        logging.error(f"Error saving file {filepath}: {e}")

def print_statistics(raw_data_count: int, stats: Counter):
    """在控制台打印统计信息。"""
    logging.info("\n--- 数据统计 ---")
    logging.info(f"原始数据集总记录数: {raw_data_count}")

    total_filtered_samples = sum(stats.values())
    logging.info(f"筛选后数据集总记录数 (仅含与目标CWE相关的样本): {total_filtered_samples}")

    if total_filtered_samples == 0:
        logging.warning("未筛选出任何与目标 CWE 相关的样本。")
        logging.info("----------------------\n")
        return

    # 提取并打印相关的安全样本计数
    secure_relevant_count = stats.pop('secure_relevant', 0) # 使用 pop 移除 'secure_relevant'
    secure_percentage = (secure_relevant_count / total_filtered_samples * 100) if total_filtered_samples > 0 else 0
    logging.info(f"  - 相关的安全样本 (label='0' and CWE in Targets): {secure_relevant_count} ({secure_percentage:.2f}%)")

    # 打印筛选出的目标脆弱性样本计数
    logging.info("匹配目标 CWE 的脆弱样本 (label='1'):")
    vulnerable_count_total = sum(stats.values()) # 剩余的是脆弱样本总数
    if vulnerable_count_total == 0:
        logging.info("  (未找到匹配目标 CWE 的脆弱样本)")
    else:
        sorted_target_cwes_found = sorted(stats.keys())
        for cwe in sorted_target_cwes_found:
            count = stats[cwe]
            percentage_of_filtered = (count / total_filtered_samples * 100) if total_filtered_samples > 0 else 0
            percentage_of_vulnerable = (count / vulnerable_count_total * 100) if vulnerable_count_total > 0 else 0
            logging.info(f"  - {cwe}: {count} (占筛选后 {percentage_of_filtered:.2f}%, 占脆弱样本 {percentage_of_vulnerable:.2f}%)")
        logging.info(f"  --- 匹配目标的脆弱样本总计: {vulnerable_count_total} ---")

    logging.info("----------------------\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="筛选 VCLData (JSON/JSONL)，仅保留 label='1' 且 CWE 在目标列表中的样本，以及 label='0' 且 CWE 也在目标列表中的样本，并对结果进行随机排序。"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="data/vcldata.jsonl",
        help="输入的 VCLData JSON 或 JSON Lines 文件路径。"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/vcldata_focused.jsonl", # 更改默认输出文件名
        help="筛选后的数据保存路径 (推荐 .jsonl 后缀)。"
    )
    parser.add_argument(
        '--target_cwes',
        nargs='+',
        default=None,
        help='可选：覆盖脚本内定义的目标 CWE 列表 (例如 --target_cwes CWE-120 CWE-134)。'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=None,
        help='可选：设置随机数种子以确保随机结果可复现 (例如 --seed 42)。'
    )

    args = parser.parse_args()

    # 设置随机数种子 (如果提供)
    if args.seed is not None:
        random.seed(args.seed)
        logging.info(f"已设置随机数种子为: {args.seed}")

    # 处理命令行覆盖 TARGET_CWES
    if args.target_cwes:
        TARGET_CWES = set()
        for cwe_arg in args.target_cwes:
            cwe_num_only = cwe_arg.strip().replace("CWE-", "")
            if cwe_num_only.isdigit():
                 TARGET_CWES.add(f"CWE-{cwe_num_only}")
            else:
                 logging.warning(f"忽略命令行提供的无效 CWE 参数: {cwe_arg}")
        logging.info(f"已使用命令行参数覆盖目标 CWE 集合，当前目标 CWEs: {', '.join(sorted(list(TARGET_CWES)))}")
    else:
        logging.info("使用脚本内定义的目标 CWE 集合。")

    # --- 主执行流程 ---
    logging.info("脚本启动。")
    raw_data = load_data(args.input)

    if raw_data:
        raw_count = len(raw_data)
        filtered_data, statistics = filter_and_count_data(raw_data)

        # --- 在保存前对筛选后的数据进行随机打乱 ---
        logging.info(f"对筛选后的 {len(filtered_data)} 条记录进行随机排序...")
        random.shuffle(filtered_data)
        logging.info("随机排序完成。")

        save_data(filtered_data, args.output)
        print_statistics(raw_count, statistics)
    else:
        logging.error("未能加载数据。脚本终止。")

    logging.info("脚本执行完毕。")