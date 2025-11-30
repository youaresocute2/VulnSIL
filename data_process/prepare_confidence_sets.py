#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Prepare calibration training/validation sets for confidence model from DiverseVul-Train.

输入： 已归一化的 diversevul_train.jsonl，每行示例：
{
  "func": "...",
  "target": 1,
  "cwe": "CWE-787",
  "project": "qemu",
  "commit_id": "...",
  ...
}

输出：
- d_cal_train.jsonl : 10000 条，pos:neg = 2:3 => 4000 vuln, 6000 safe
- d_cal_val.jsonl   :  2000 条，pos:neg = 2:3 =>  800 vuln, 1200 safe

采样策略：
- [新增] 预先筛选：去除代码为空或无效的样本，防止静态分析失效
- 先按照 (cwe, project) 进行近似分层采样，按原始分布分配配额
- 若某个分层不足，则取全部，剩余配额在其他分层中随机补齐（fallback）
- train 与 val 两个集合互斥
"""

import argparse
import json
import random
import sys
from collections import defaultdict
from typing import Any, Dict, List, Tuple

Record = Dict[str, Any]


def read_jsonl(path: str) -> List[Record]:
    data: List[Record] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                data.append(obj)
            except json.JSONDecodeError as e:
                print(f"[WARN] JSON decode error at line {line_no} in {path}: {e}", file=sys.stderr)
    return data


def write_jsonl(path: str, records: List[Record]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def filter_invalid_records(records: List[Record]) -> List[Record]:
    """
    [新增功能] 筛选无效记录：
    1. 代码内容为空 (func 或 code 字段)
    2. 只有空白字符
    """
    valid_records = []
    filtered_count = 0

    for rec in records:
        # 兼容 func 和 code 字段名
        code = rec.get("func", "") or rec.get("code", "")

        # 检查是否为空或仅含空格
        if not code or not str(code).strip():
            filtered_count += 1
            # 可选：打印被过滤的 ID 方便调试
            # commit = rec.get("commit_id", "unk")
            # print(f"[DEBUG] Filtered invalid record: commit_id={commit}")
            continue

        valid_records.append(rec)

    print(f"[INFO] Filtered out {filtered_count} invalid records (empty code).")
    return valid_records


def get_stratum_key(rec: Record) -> Tuple[str, str]:
    """
    分层键： (cwe, project)
    若缺失则回退到 'None' / 'unknown'
    """
    cwe = rec.get("cwe") or "None"
    project = rec.get("project") or "unknown"
    return str(cwe), str(project)


def group_by_stratum(records: List[Record]) -> Dict[Tuple[str, str], List[Record]]:
    groups: Dict[Tuple[str, str], List[Record]] = defaultdict(list)
    for rec in records:
        key = get_stratum_key(rec)
        groups[key].append(rec)
    return groups


def stratified_sample(
        records: List[Record],
        target_n: int,
        rng: random.Random,
        label_name: str,
) -> List[Record]:
    """
    对 records 做近似分层采样，分层依据 (cwe, project)。

    步骤：
    1) 按分层统计数量，按比例计算每层的目标个数 quota
    2) 每层先取 min(len(group), quota) 个
    3) 统计总不足部分 remaining = target_n - sum(collected)
    4) 将所有还有剩余样本的分层合并成池子，再随机补足 remaining

    若整个 records 数量不足 target_n，则返回全部记录并打印警告。
    """
    n_total = len(records)
    if n_total == 0:
        return []

    if n_total <= target_n:
        print(
            f"[WARN] label={label_name}: only {n_total} samples available, "
            f"less than requested {target_n}, returning all.",
            file=sys.stderr,
        )
        # 打乱一下，避免原始顺序偏置
        shuffled = records[:]
        rng.shuffle(shuffled)
        return shuffled

    groups = group_by_stratum(records)
    # 1) 计算每层 quota（按比例分配）
    quotas: Dict[Tuple[str, str], int] = {}
    for key, group in groups.items():
        frac = len(group) / n_total
        quotas[key] = int(round(frac * target_n))

    # 调整 quotas 的总和为 target_n（防止四舍五入误差）
    quota_sum = sum(quotas.values())
    delta = target_n - quota_sum
    if delta != 0:
        # 按 group size 大小排序，逐个加/减 1
        sorted_keys = sorted(groups.keys(), key=lambda k: len(groups[k]), reverse=(delta > 0))
        idx = 0
        step = 1 if delta > 0 else -1
        for _ in range(abs(delta)):
            k = sorted_keys[idx % len(sorted_keys)]
            quotas[k] = max(0, quotas[k] + step)
            idx += 1

    # 2) 先按每层 quota 采样
    selected: List[Record] = []
    remaining_pool: List[Record] = []
    for key, group in groups.items():
        group_size = len(group)
        quota = min(group_size, quotas.get(key, 0))
        if quota > 0:
            chosen = rng.sample(group, quota)
            selected.extend(chosen)
            # 剩余样本进入备用池
            remaining = [x for x in group if x not in chosen]
            remaining_pool.extend(remaining)
        else:
            remaining_pool.extend(group)

    # 3) 若总采样数不足 target_n，则从剩余池中补
    current_n = len(selected)
    if current_n < target_n and remaining_pool:
        need = target_n - current_n
        if need > len(remaining_pool):
            print(
                f"[WARN] label={label_name}: cannot fully meet target_n={target_n}, "
                f"only {current_n + len(remaining_pool)} available.",
                file=sys.stderr,
            )
            need = len(remaining_pool)
        extra = rng.sample(remaining_pool, need)
        selected.extend(extra)

    # 打乱最终结果
    rng.shuffle(selected)
    if len(selected) > target_n:
        selected = selected[:target_n]
    return selected


def prepare_calibration_sets(
        records: List[Record],
        train_pos: int,
        train_neg: int,
        val_pos: int,
        val_neg: int,
        seed: int = 42,
) -> Tuple[List[Record], List[Record]]:
    """
    根据给定的正负数量，构造 D_cal_train 和 D_cal_val。
    - train: train_pos + train_neg
    - val:   val_pos + val_neg
    两者互斥。

    使用近似分层采样，并在样本不足时 fallback。
    """
    rng = random.Random(seed)

    # 按 label 分割
    pos_all = [r for r in records if int(r.get("target", 0)) == 1]
    neg_all = [r for r in records if int(r.get("target", 0)) == 0]

    print(f"[INFO] Total pos in filtered pool: {len(pos_all)}")
    print(f"[INFO] Total neg in filtered pool: {len(neg_all)}")

    # 1) 构建 D_cal_train
    train_pos_records = stratified_sample(pos_all, train_pos, rng, label_name="pos_train")
    # 从 pos_all 中移除已经选中的
    pos_remaining = [r for r in pos_all if r not in train_pos_records]

    train_neg_records = stratified_sample(neg_all, train_neg, rng, label_name="neg_train")
    neg_remaining = [r for r in neg_all if r not in train_neg_records]

    d_cal_train = train_pos_records + train_neg_records
    rng.shuffle(d_cal_train)
    print(f"[INFO] D_cal_train size: {len(d_cal_train)} (pos={len(train_pos_records)}, neg={len(train_neg_records)})")

    # 2) 构建 D_cal_val（从剩余样本中再采）
    val_pos_records = stratified_sample(pos_remaining, val_pos, rng, label_name="pos_val")
    val_neg_records = stratified_sample(neg_remaining, val_neg, rng, label_name="neg_val")

    d_cal_val = val_pos_records + val_neg_records
    rng.shuffle(d_cal_val)
    print(f"[INFO] D_cal_val size: {len(d_cal_val)} (pos={len(val_pos_records)}, neg={len(val_neg_records)})")

    return d_cal_train, d_cal_val


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare calibration train/val sets from normalized DiverseVul-Train JSONL."
    )
    parser.add_argument("--input", required=True, help="Path to normalized diversevul_train.jsonl")
    parser.add_argument("--train-output", required=True, help="Output path for D_cal_train JSONL")
    parser.add_argument("--val-output", required=True, help="Output path for D_cal_val JSONL")

    parser.add_argument("--train-pos", type=int, default=4000,
                        help="Number of positive samples for train (default 4000)")
    parser.add_argument("--train-neg", type=int, default=6000,
                        help="Number of negative samples for train (default 6000)")
    parser.add_argument("--val-pos", type=int, default=800, help="Number of positive samples for val (default 800)")
    parser.add_argument("--val-neg", type=int, default=1200, help="Number of negative samples for val (default 1200)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")

    args = parser.parse_args()

    # 1. 读取原始数据
    records = read_jsonl(args.input)
    print(f"[INFO] Loaded {len(records)} records from {args.input}")

    # 2. [关键] 过滤不合法数据
    records = filter_invalid_records(records)
    print(f"[INFO] Records available for sampling: {len(records)}")

    # 3. 分层采样
    d_cal_train, d_cal_val = prepare_calibration_sets(
        records,
        train_pos=args.train_pos,
        train_neg=args.train_neg,
        val_pos=args.val_pos,
        val_neg=args.val_neg,
        seed=args.seed,
    )

    # 4. 写入结果
    write_jsonl(args.train_output, d_cal_train)
    print(f"[INFO] Wrote D_cal_train to {args.train_output}")

    write_jsonl(args.val_output, d_cal_val)
    print(f"[INFO] Wrote D_cal_val to {args.val_output}")


if __name__ == "__main__":
    main()