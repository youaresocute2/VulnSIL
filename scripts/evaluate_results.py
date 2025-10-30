# scripts/evaluate_results.py

import json
from sqlalchemy.orm import Session
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score, accuracy_score, confusion_matrix
import pandas as pd
import sys
import os

# 将项目根目录添加到 sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnsil.database import get_db_session
from vulnsil.models import Vulnerability, VulnSILAnalysis


def evaluate():
    """
    连接数据库，拉取所有分析结果，并计算评估指标。
    [修改] 移除/弱化 CWE 评估。
    """
    print("Starting evaluation...")
    db_gen = get_db_session()
    db = next(db_gen)

    try:
        # 查询保持不变，但 ground_truth_cwe 和 detected_cwe 的使用将减少
        results = db.query(
            Vulnerability.ground_truth_label,
            # Vulnerability.ground_truth_cwe, # 不需要用于核心评估
            Vulnerability.name,
            VulnSILAnalysis.final_decision,
            # VulnSILAnalysis.detected_cwe, # 不需要用于核心评估
            VulnSILAnalysis.reasoning_confidence,
            VulnSILAnalysis.vapa_iterations
        ).join(
            VulnSILAnalysis, Vulnerability.id == VulnSILAnalysis.vulnerability_id
        ).all()

        if not results:
            print("No analysis results found in the database. Run 'run_vulnsil_analysis.py' first.")
            return

        print(f"Loaded {len(results)} completed analysis results.")

        y_true = []
        y_pred = []
        data_for_df = [] # 仍然可以收集 VAPA 迭代次数等信息

        for res in results:
            # 真值标签 (来自 data_loader)
            # 1 = Vulnerable, 0 = Safe
            true_label = 1 if res.ground_truth_label == "1" else 0

            # 预测标签 (来自 T&V Parser)
            # "YES" = Vulnerable, "NO" = Safe
            # [重要] 确保 final_decision 被正确解析和处理，即使有错误状态
            pred_label = 0 # 默认安全
            if res.final_decision:
                 pred_label = 1 if "YES" in res.final_decision.upper() else 0
            # else: # 可以选择处理解析失败或无决策的情况
            #     print(f"Warning: No valid final_decision found for {res.name}. Assuming 'NO'.")


            y_true.append(true_label)
            y_pred.append(pred_label)

            data_for_df.append({
                "name": res.name,
                "true_label": true_label,
                "pred_label": pred_label,
                "confidence": res.reasoning_confidence,
                 # 注意 json.loads 的健壮性
                "vapa_iters": len(json.loads(res.vapa_iterations)) if res.vapa_iterations and res.vapa_iterations != 'null' else 0
            })

        print("\n--- Overall Performance (Binary Classification) ---")
        target_names = ['Safe (0)', 'Vulnerable (1)']
        # [核心评估] 使用 classification_report 和 confusion_matrix
        # 增加 zero_division=0 来处理某个类别没有样本的情况
        report = classification_report(y_true, y_pred, target_names=target_names, digits=4, zero_division=0)
        print(report)

        print("\n--- Confusion Matrix ---")
        cm = confusion_matrix(y_true, y_pred)
        print(cm)

        # 仅保留与二分类性能相关的分析
        df = pd.DataFrame(data_for_df)

        print("\n--- Analysis: VAPA Statistics ---") # 重命名 RQ -> Analysis
        # 过滤掉 VAPA 迭代次数为 0 (可能表示 VAPA 失败或未运行) 的情况再计算平均值，如果需要的话
        valid_vapa_iters = df[df['vapa_iters'] > 0]['vapa_iters']
        if not valid_vapa_iters.empty:
            avg_iters = valid_vapa_iters.mean()
            max_iters = valid_vapa_iters.max()
            # 计算需要多轮迭代的比例时，基数应为成功完成 VAPA 的样本
            pct_multi_iter = (valid_vapa_iters > 1).mean() * 100
            print(f"Average VAPA Iterations (for completed VAPA): {avg_iters:.2f}")
            print(f"Max VAPA Iterations observed: {max_iters}")
            print(f"Percentage requiring >1 iteration (for completed VAPA): {pct_multi_iter:.2f}%")
        else:
            print("No valid VAPA iteration data found to calculate statistics.")


    except Exception as e:
        print(f"An error occurred during evaluation: {e}")
        # 可以在这里添加更详细的错误追踪
        import traceback
        traceback.print_exc()
    finally:
        if db:
            db.close()
        print("Evaluation finished.")

if __name__ == "__main__":
    evaluate()