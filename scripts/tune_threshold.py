# scripts/tune_threshold.py
import sys
import os
import numpy as np
import typer
from tqdm import tqdm
from sklearn.metrics import precision_recall_curve, f1_score, precision_score, recall_score, confusion_matrix
from sklearn.utils import resample

# 适配路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnsil.database import get_db_session
from vulnsil.models import AnalysisResultRecord, Vulnerability
from vulnsil.utils_log import setup_logging

app = typer.Typer()
log = setup_logging("tune_threshold_bootstrap")


def find_optimal_threshold(y_true, y_scores):
    """
    Given a set of labels and scores, mathematically determine the threshold
    that yields the absolute maximum F1 score using Vectorized operations.
    """
    # Precision-Recall Curve 自动计算每个独特score点的阈值
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_scores)

    # 避免分母为0
    denominator = precisions + recalls
    with np.errstate(divide='ignore', invalid='ignore'):
        f1_scores = 2 * (precisions * recalls) / denominator
        f1_scores = np.nan_to_num(f1_scores)  # 替换 nan

    # 找到最大 F1 的索引
    best_idx = np.argmax(f1_scores)

    # thresholds 的长度比 precisions/recalls 少 1（最后一个点通常对应 th=1.0）
    if best_idx < len(thresholds):
        best_th = thresholds[best_idx]
    else:
        best_th = 0.5  # Fallback

    return best_th, f1_scores[best_idx]


@app.command()
def tune(
        split_name: str = typer.Option(..., help="Target dataset split (e.g., 'diversevul_test')"),
        n_bootstraps: int = 100,
        random_state: int = 42
):
    """
    [Improved] Determine Robust Decision Threshold using Bootstrap Aggregation.
    Formula: th_hat = E[arg max F1(y_b, probs_b)] over 100 resamples.
    Helps avoid overfitting to sparse positive samples in imbalanced datasets.
    """
    log.info(f"🔍 Loading data for split: {split_name} ...")

    # 1. 从数据库读取数据
    with get_db_session() as db:
        results = db.query(
            Vulnerability.ground_truth_label,
            AnalysisResultRecord.calibrated_confidence
        ).join(AnalysisResultRecord).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status == "Success"
        ).all()

    if not results:
        log.error("❌ No records found.")
        return

    # 数据准备
    y_true_full = np.array([r[0] for r in results])
    # 填充 None 值，确保 shape 一致
    y_scores_full = np.array([r[1] if r[1] is not None else 0.0 for r in results])

    total = len(y_true_full)
    pos_count = np.sum(y_true_full)
    pos_ratio = pos_count / total

    print("\n" + "=" * 60)
    print(f" 📊 BOOTSTRAP THRESHOLD TUNING")
    print("=" * 60)
    print(f" Dataset         : {split_name}")
    print(f" Samples         : {total}")
    print(f" Vuln Count      : {pos_count} ({pos_ratio:.2%})")
    print(f" Bootstrap Rounds: {n_bootstraps}")
    print("-" * 60)

    # 2. Bootstrap Loop
    bootstrap_thresholds = []

    # 确保随机性可复现
    rng = np.random.RandomState(random_state)

    log.info("🔄 Running Bootstrap Resampling...")

    with tqdm(total=n_bootstraps, unit="round") as pbar:
        for i in range(n_bootstraps):
            # Resample (有放回采样)，必须使用 stratify 以防稀疏偏差导致某些批次无正样本
            # 如果正样本极少，resample 可能会采到全是 0 的样本，stratify 能缓解
            try:
                # 注：如果总样本过少，stratify 可能会报错，这里加个简单判断
                stratify_param = y_true_full if pos_count > 5 else None

                y_b, probs_b = resample(
                    y_true_full,
                    y_scores_full,
                    n_samples=len(y_true_full),
                    replace=True,
                    stratify=stratify_param,
                    random_state=rng.randint(0, 100000)
                )

                # 在该 Boot 子集上寻找最佳 F1 对应的阈值
                th, _ = find_optimal_threshold(y_b, probs_b)
                bootstrap_thresholds.append(th)

            except Exception as e:
                # 极端情况容错
                pass

            pbar.update(1)

    if not bootstrap_thresholds:
        log.error("Bootstrap failed to find valid thresholds.")
        return

    # 3. 统计聚合
    # E[arg max F1]
    final_robust_th = np.mean(bootstrap_thresholds)
    th_std = np.std(bootstrap_thresholds)

    # 计算置信区间 (95% CI)
    ci_lower = np.percentile(bootstrap_thresholds, 2.5)
    ci_upper = np.percentile(bootstrap_thresholds, 97.5)

    print("\n" + "-" * 60)
    print(" 📈 BOOTSTRAP RESULTS")
    print("-" * 60)
    print(f" Mean Optimal Threshold (Robust): {final_robust_th:.4f}")
    print(f" Threshold Std Dev              : {th_std:.4f}")
    print(f" 95% Confidence Interval        : [{ci_lower:.4f}, {ci_upper:.4f}]")
    print("=" * 60 + "\n")

    # 4. 验证环节：将 Robust Threshold 应用回全量数据，查看预期表现
    # 应用最终计算出的均值阈值
    y_pred_robust = (y_scores_full >= final_robust_th).astype(int)

    f1 = f1_score(y_true_full, y_pred_robust, zero_division=0)
    prec = precision_score(y_true_full, y_pred_robust, zero_division=0)
    rec = recall_score(y_true_full, y_pred_robust, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true_full, y_pred_robust).ravel()

    print(f"🏆 EXPECTED PERFORMANCE ON FULL DATASET (Using TH = {final_robust_th:.4f})")
    print(f"   F1-Score  : {f1:.4f}")
    print(f"   Precision : {prec:.4f}")
    print(f"   Recall    : {rec:.4f}")
    print(f"   Matrix    : TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print(f"\n💡 Recommendation: update 'CALIBRATION_THRESHOLD' in config.py to {final_robust_th:.4f}")


if __name__ == "__main__":
    app()