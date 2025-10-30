# scripts/split_data.py

import json
import os
import random
import argparse
import logging
import sys
from collections import Counter
import pandas as pd
from sklearn.model_selection import train_test_split
# from typing import Dict, Any, List, Tuple # 保持兼容性
from typing import List, Tuple, Dict, Any


# 添加项目根目录到 sys.path (如果需要从 vulnsil 导入)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)
# from vulnsil import config # 如果需要 config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_stratify_key(item: Dict[str, Any]) -> str: # 添加类型提示
    """
    [修正] 创建用于分层抽样的键。
    使用实际的数据字段名 'label' 和 'cwe_id'。
    """
    label = item.get('label', '0') # 使用 'label' 字段，默认为 '0'
    cwe = item.get('cwe_id', 'Unknown') # 使用 'cwe_id' 字段，默认为 'Unknown'

    # 标准化 CWE 缺失值
    if cwe is None or str(cwe).strip() == '' or str(cwe).upper() == 'N/A':
        cwe = 'Unknown'
    else:
        cwe = str(cwe) # 确保是字符串

    # 确保 label 是字符串 '0' 或 '1'
    label_str = str(label)
    if label_str not in ['0', '1']:
        logging.warning(f"发现意外的 label 值: '{label_str}'，将视为 '0' (安全)。请检查数据。")
        label_str = '0'


    if label_str == '1':
        # 漏洞样本：结合 CWE 进行分层
        return f"label_{label_str}_cwe_{cwe}"
    else:
        # 安全样本：仅按标签分层
        return f"label_{label_str}"

def print_statistics(data: List[Dict[str, Any]], name: str): # 添加类型提示
    """
    [修正] 打印数据集的统计信息。
    使用实际的数据字段名 'label' 和 'cwe_id'。
    """
    if not data:
        logging.warning(f"{name} 数据集为空。")
        return

    df = pd.DataFrame(data)
    total_count = len(df)
    logging.info(f"\n--- {name} 数据集统计 ---")
    logging.info(f"总数: {total_count}")

    # --- 使用正确的字段名 'label' 和 'cwe_id' ---
    label_col = 'label'
    cwe_col = 'cwe_id'

    # 确保列存在且填充缺失值以便分组
    if label_col not in df.columns:
        logging.warning(f"警告: 数据集中缺少 '{label_col}' 列，将假设所有样本为安全。")
        df[label_col] = '0' # 假设缺失标签为安全
    else:
        # 强制转换为字符串 '0' 或 '1'，并填充缺失值
        df[label_col] = df[label_col].astype(str).fillna('0')
        # 验证 label 值是否只有 '0' 和 '1'
        unexpected_labels = df[~df[label_col].isin(['0', '1'])][label_col].unique()
        if len(unexpected_labels) > 0:
            logging.warning(f"在 '{name}' 数据集中发现非预期的 label 值: {unexpected_labels}，统计时将视为 '0'。")
            df[label_col] = df[label_col].apply(lambda x: x if x in ['0', '1'] else '0')


    if cwe_col not in df.columns:
        logging.warning(f"警告: 数据集中缺少 '{cwe_col}' 列，将假设所有 CWE 为 'Unknown'。")
        df[cwe_col] = 'Unknown'
    else:
        # 标准化 CWE
        df[cwe_col] = df[cwe_col].apply(
            lambda x: 'Unknown' if pd.isna(x) or str(x).strip() == '' or str(x).upper() == 'N/A' else str(x)
        )
    # -----------------------------------------------

    # 按 CWE 和 Label 分组计数
    try:
        counts = df.groupby([cwe_col, label_col]).size().unstack(fill_value=0)
    except Exception as e:
        logging.error(f"在为 '{name}' 数据集生成统计信息时分组出错: {e}")
        logging.error("请检查数据文件中 'label' 和 'cwe_id' 列的内容和格式。")
        return # 无法继续统计

    logging.info("按 CWE 类型统计 (漏洞/安全):")
    # 打印格式化的表格
    all_cwe_types = sorted(df[cwe_col].unique()) # 获取所有实际存在的 CWE 类型
    for cwe_type in all_cwe_types:
        # 确保 counts DataFrame 中有这个 cwe_type
        if cwe_type in counts.index:
             vuln_count = counts.loc[cwe_type].get('1', 0)
             safe_count = counts.loc[cwe_type].get('0', 0)
             # 只打印包含样本的 CWE
             if vuln_count > 0 or safe_count > 0:
                 logging.info(f"  {cwe_type}: 漏洞={vuln_count}, 安全={safe_count}")
        # else: # 如果某个 CWE 只出现在例如 label='?' 的数据中，它可能不在 counts.index 里
        #     logging.info(f"  {cwe_type}: 漏洞=0, 安全=0 (或仅包含非 0/1 标签)")


    # 打印总的漏洞和安全样本数 (确保 '1' 和 '0' 列存在)
    total_vuln = counts['1'].sum() if '1' in counts.columns else 0
    total_safe = counts['0'].sum() if '0' in counts.columns else 0
    logging.info(f"总计: 漏洞={total_vuln}, 安全={total_safe}")


def split_data(input_file: str, output_dir: str, train_ratio: float = 0.5, val_ratio: float = 0.25, test_ratio: float = 0.25, seed: int = 42):
    """
    [修正] 将 JSON Lines 数据集按比例 (默认 0.5:0.25:0.25) 进行分层抽样划分。
    使用 'label' 和 'cwe_id' 字段进行分层。
    """
    logging.info("开始执行分层数据划分...")
    logging.info(f"划分比例: 训练={train_ratio}, 验证={val_ratio}, 测试={test_ratio}")

    if not abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-9:
        logging.error("错误：训练、验证和测试集的比例之和必须为 1.0。")
        return

    if not os.path.exists(input_file):
        logging.error(f"错误：输入文件未找到 '{input_file}'。")
        return

    os.makedirs(output_dir, exist_ok=True)
    logging.info(f"输出目录: '{output_dir}'")

    # 读取数据并创建分层键
    data = []
    stratify_keys = []
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                if line.strip():
                    try:
                        item = json.loads(line)
                        # --- [修正] 检查必须的键是否存在 ---
                        if 'label' not in item or 'cwe_id' not in item:
                             logging.warning(f"第 {line_num} 行缺少 'label' 或 'cwe_id' 字段，将跳过此行。")
                             continue # 跳过缺少关键字段的行
                        # -----------------------------------
                        data.append(item)
                        stratify_keys.append(create_stratify_key(item)) # 生成分层键
                    except json.JSONDecodeError:
                        logging.warning(f"第 {line_num} 行 JSON 解析失败，将跳过此行: {line.strip()}")
                    except Exception as inner_e:
                        logging.warning(f"处理第 {line_num} 行时发生错误: {inner_e}，将跳过此行。")

        logging.info(f"从 '{input_file}' 加载了 {len(data)} 条有效记录。")
    except Exception as e:
        logging.error(f"加载或处理数据时出错: {e}")
        return

    if not data:
        logging.warning("数据文件为空或无有效记录，无法进行划分。")
        return

    # 检查分层键的多样性
    key_counts = Counter(stratify_keys)
    min_samples_per_group = 0
    if key_counts: # 确保 key_counts 不为空
        min_samples_per_group = min(key_counts.values())
    else:
        logging.error("未能生成任何分层键，无法划分。请检查数据格式。")
        return

    # train_test_split 至少需要 n_splits=2 个样本才能划分
    # 由于我们进行两次划分，最保险的是每组至少有 2 个样本
    required_samples = 2
    underrepresented_groups = {k: v for k, v in key_counts.items() if v < required_samples}
    if underrepresented_groups:
        logging.warning(f"警告: 存在样本数少于 {required_samples} 的分层组: {underrepresented_groups}。分层效果可能受影响或失败。")
        # 可以选择强制继续，或者停止
        # return

    # --- 执行分层划分 ---
    try:
        remaining_ratio = val_ratio + test_ratio
        if remaining_ratio == 0: # 处理只划分训练集的情况
             train_data = data
             temp_data, temp_keys = [], []
        elif train_ratio == 0: # 处理只划分验证和测试集的情况
             train_data = []
             temp_data, temp_keys = data, stratify_keys
        else:
             train_data, temp_data, _, temp_keys = train_test_split(
                 data, stratify_keys, test_size=remaining_ratio, random_state=seed, stratify=stratify_keys
             )

        if not temp_data: # 如果只有训练集
            val_data, test_data = [], []
        elif val_ratio == 0: # 如果只有训练和测试集
            val_data = []
            test_data = temp_data
        elif test_ratio == 0: # 如果只有训练和验证集
            val_data = temp_data
            test_data = []
        else: # 标准情况：划分验证和测试
            test_ratio_in_temp = test_ratio / remaining_ratio
            val_data, test_data, _, _ = train_test_split(
                temp_data, temp_keys, test_size=test_ratio_in_temp, random_state=seed, stratify=temp_keys
            )

    except ValueError as e:
         logging.error(f"分层划分失败: {e}. 可能因为某些组的样本数过少。请检查数据或调整划分比例。")
         return
    except Exception as e:
         logging.error(f"划分过程中发生未知错误: {e}")
         return

    logging.info(f"划分结果: 训练集={len(train_data)}, 验证集={len(val_data)}, 测试集={len(test_data)}")

    # 保存数据
    def save_split(split_data, filename):
        if not split_data: # 如果数据集为空，不创建文件
             logging.info(f"跳过保存空的 '{filename}' 数据集。")
             return
        filepath = os.path.join(output_dir, filename)
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for item in split_data:
                    f.write(json.dumps(item, ensure_ascii=False) + '\n')
            logging.info(f"已保存 {len(split_data)} 条记录到 '{filepath}'。")
        except Exception as e:
            logging.error(f"保存文件 '{filepath}' 时出错: {e}")

    save_split(train_data, "train.jsonl")
    save_split(val_data, "validation.jsonl")
    save_split(test_data, "test.jsonl")

    # --- 打印统计信息 ---
    print_statistics(train_data, "训练集")
    print_statistics(val_data, "验证集")
    print_statistics(test_data, "测试集")

    logging.info("数据划分和统计完成。")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="按比例分层划分 JSON Lines 数据集 (基于 'label' 和 'cwe_id')。")
    # input 文件硬编码
    parser.add_argument("--output_dir", type=str, default="data/splits", help="保存划分后文件的目录 (默认 data/splits)。")
    parser.add_argument("--train_ratio", type=float, default=0.5, help="训练集比例 (默认 0.5)。")
    parser.add_argument("--val_ratio", type=float, default=0.25, help="验证集比例 (默认 0.25)。")
    parser.add_argument("--test_ratio", type=float, default=0.25, help="测试集比例 (默认 0.25)。")
    parser.add_argument("--seed", type=int, default=42, help="随机种子 (默认 42)。")

    args = parser.parse_args()

    input_file_path = os.path.join(PROJECT_ROOT, 'data', 'vcldata_focused.jsonl')

    split_data(input_file_path, args.output_dir, args.train_ratio, args.val_ratio, args.test_ratio, args.seed)