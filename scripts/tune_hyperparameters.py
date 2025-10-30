# scripts/tune_hyperparameters.py

import os
import subprocess
import json
import logging
from typing import Dict, Any, List, Tuple
from sklearn.metrics import f1_score # 直接从评估结果解析 F1 可能更简单
import itertools # 用于生成参数组合
import re # 用于从评估输出中提取 F1 分数

# --- 配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义要调整的超参数及其候选值
PARAM_GRID = {
    # 转换为 0-100 整数，以便更容易处理和显示
    'SIL_CONFIDENCE_THRESHOLD_PERCENT': [70, 80, 90],
     # 转换为 0-100 整数
    'REASONING_CONFIDENCE_THRESHOLD_PERCENT': [70, 80, 90, 95],
    'MAX_VAPA_ITERATIONS': [1, 2, 3]
}

# Python 脚本的路径 (相对于项目根目录)
SETUP_SCRIPT = "scripts/setup_database.py"
ANALYSIS_SCRIPT = "scripts/run_vulnsil_analysis.py"
EVALUATE_SCRIPT = "scripts/evaluate_results.py"

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 配置文件路径
CONFIG_FILE_PATH = os.path.join(PROJECT_ROOT, "vulnsil", "config.py")

# --- 辅助函数 ---

def update_config_file(params: Dict[str, Any]):
    """临时修改 config.py 文件中的阈值。注意：这不是线程安全的！"""
    try:
        with open(CONFIG_FILE_PATH, 'r') as f:
            lines = f.readlines()

        new_lines = []
        updated = set()
        for line in lines:
            new_line = line.strip()
            # 更新 SIL 置信度阈值 (转换回 0.0-1.0)
            if new_line.startswith("SIL_CONFIDENCE_THRESHOLD =") and 'SIL_CONFIDENCE_THRESHOLD_PERCENT' in params:
                threshold_float = params['SIL_CONFIDENCE_THRESHOLD_PERCENT'] / 100.0
                new_lines.append(f"SIL_CONFIDENCE_THRESHOLD = {threshold_float:.2f} # Updated by tune_hyperparameters.py\n")
                updated.add('SIL_CONFIDENCE_THRESHOLD_PERCENT')
            # 更新 Reasoning 置信度阈值 (转换回 0.0-1.0)
            elif new_line.startswith("REASONING_CONFIDENCE_THRESHOLD =") and 'REASONING_CONFIDENCE_THRESHOLD_PERCENT' in params:
                 threshold_float = params['REASONING_CONFIDENCE_THRESHOLD_PERCENT'] / 100.0
                 new_lines.append(f"REASONING_CONFIDENCE_THRESHOLD = {threshold_float:.2f} # Updated by tune_hyperparameters.py\n")
                 updated.add('REASONING_CONFIDENCE_THRESHOLD_PERCENT')
            # 更新 VAPA 最大迭代次数
            elif new_line.startswith("MAX_VAPA_ITERATIONS =") and 'MAX_VAPA_ITERATIONS' in params:
                new_lines.append(f"MAX_VAPA_ITERATIONS = {params['MAX_VAPA_ITERATIONS']} # Updated by tune_hyperparameters.py\n")
                updated.add('MAX_VAPA_ITERATIONS')
            else:
                new_lines.append(line) # 保留原行

        if len(updated) != len(params):
             logging.warning(f"配置文件更新可能不完整。找到的参数: {updated}, 期望的参数: {params.keys()}")

        with open(CONFIG_FILE_PATH, 'w') as f:
            f.writelines(new_lines)
        # logging.info(f"配置文件已更新: {params}")
        return True
    except Exception as e:
        logging.error(f"更新配置文件 '{CONFIG_FILE_PATH}' 时出错: {e}")
        return False

def run_command(command: List[str]) -> Tuple[bool, str]:
    """执行命令行命令并返回成功状态和输出。"""
    try:
        # 使用 python 执行脚本，确保使用正确的环境
        full_command = ['python'] + command
        logging.info(f"执行命令: {' '.join(full_command)}")
        result = subprocess.run(full_command, cwd=PROJECT_ROOT, capture_output=True, text=True, check=True, encoding='utf-8')
        # logging.debug(f"命令输出:\n{result.stdout}")
        return True, result.stdout
    except FileNotFoundError:
        logging.error(f"错误: Python 解释器或脚本 '{command[0]}' 未找到。请确保在正确的环境中运行。")
        return False, f"错误: Python 或脚本 '{command[0]}' 未找到。"
    except subprocess.CalledProcessError as e:
        logging.error(f"命令 {' '.join(full_command)} 执行失败。返回码: {e.returncode}")
        logging.error(f"错误输出:\n{e.stderr}")
        return False, e.stderr
    except Exception as e:
        logging.error(f"执行命令时发生未知错误: {e}")
        return False, str(e)

def extract_f1_score(evaluate_output: str) -> float:
    """从 evaluate_results.py 的输出中提取 F1 分数 (假设是针对 Vulnerable 类别的)。"""
    # 查找 'Vulnerable (1)' 行
    match_line = re.search(r'Vulnerable \(1\)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)', evaluate_output)
    if match_line:
        try:
            # F1 分数是第三个浮点数
            f1 = float(match_line.group(3))
            logging.info(f"从评估输出中提取到 F1 (Vulnerable): {f1:.4f}")
            return f1
        except (IndexError, ValueError):
            logging.warning("无法从 'Vulnerable (1)' 行解析 F1 分数。")

    # 备选：查找 'weighted avg' 行的 F1 分数 (可能是第四个浮点数)
    match_weighted = re.search(r'weighted avg\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)', evaluate_output)
    if match_weighted:
        try:
            f1_weighted = float(match_weighted.group(3))
            logging.info(f"从评估输出中提取到 F1 (Weighted Avg): {f1_weighted:.4f}. 将使用此值。")
            return f1_weighted
        except (IndexError, ValueError):
             logging.warning("无法从 'weighted avg' 行解析 F1 分数。")

    logging.error("无法从评估输出中提取任何 F1 分数。")
    return 0.0 # 返回 0.0 表示失败

# --- 主调优逻辑 ---

def tune():
    """执行超参数调优过程。"""
    logging.info("开始超参数调优...")
    best_f1 = -1.0
    best_params = None
    results_history = []

    # 生成所有参数组合
    keys, values = zip(*PARAM_GRID.items())
    param_combinations = [dict(zip(keys, v)) for v in itertools.product(*values)]
    total_combinations = len(param_combinations)
    logging.info(f"将测试 {total_combinations} 种参数组合。")

    original_config_content = ""
    try:
        # 备份原始配置
        with open(CONFIG_FILE_PATH, 'r') as f:
            original_config_content = f.read()

        for i, params in enumerate(param_combinations):
            logging.info(f"\n--- 测试组合 {i + 1}/{total_combinations}: {params} ---")

            # 1. 更新配置文件
            if not update_config_file(params):
                logging.error("无法更新配置文件，跳过此组合。")
                continue

            # 2. 加载验证数据 (并清空之前的分析结果)
            success, output = run_command([SETUP_SCRIPT, "--split", "validation", "--clear_analysis"])
            if not success:
                logging.error("加载验证数据失败，跳过此组合。")
                continue

            # 3. 运行分析脚本
            success, output = run_command([ANALYSIS_SCRIPT])
            if not success:
                # 分析失败也记录下来，F1 记为 0
                logging.error("分析脚本执行失败。")
                current_f1 = 0.0
            else:
                # 4. 运行评估脚本
                success, eval_output = run_command([EVALUATE_SCRIPT])
                if not success:
                    logging.error("评估脚本执行失败。")
                    current_f1 = 0.0
                else:
                    # 5. 提取 F1 分数
                    current_f1 = extract_f1_score(eval_output)

            logging.info(f"组合 {params} 的 F1 分数 (验证集): {current_f1:.4f}")
            results_history.append({"params": params, "f1_score": current_f1})

            # 6. 更新最佳参数
            if current_f1 > best_f1:
                best_f1 = current_f1
                best_params = params
                logging.info(f"*** 新的最佳 F1 分数: {best_f1:.4f}，参数: {best_params} ***")

    except KeyboardInterrupt:
        logging.warning("调优过程被用户中断。")
    except Exception as e:
        logging.error(f"调优过程中发生意外错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 恢复原始配置文件
        if original_config_content:
            try:
                with open(CONFIG_FILE_PATH, 'w') as f:
                    f.write(original_config_content)
                logging.info("原始配置文件已恢复。")
            except Exception as e:
                logging.error(f"恢复原始配置文件时出错: {e}")
        else:
             logging.warning("无法恢复原始配置文件 (未备份或备份失败)。")


    logging.info("\n--- 调优完成 ---")
    if best_params:
        logging.info(f"最佳 F1 分数 (验证集): {best_f1:.4f}")
        logging.info(f"对应的最佳参数组合: {best_params}")

    else:
        logging.info("未能找到有效的参数组合或调优未完成。")

if __name__ == "__main__":
    tune()