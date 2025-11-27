#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Prepare evaluation subset D_eval from DiverseVul-Test.

输入： 已归一化的 diversevul_test.jsonl，每行示例：
{
  "func": "...",
  "target": 1 or 0,
  "cwe": "CWE-787",
  "project": "qemu",
  ...
}

输出：
- d_eval.jsonl : 约 target_size 条（默认 10000）
  - 包含测试集中所有 target=1 的样本
  - 再从 target=0 中按 (cwe, project) 分层采样若干条，使总数尽量接近 target_size

若正样本总数 >= target_size，则 D_eval 将只包含打乱后的所有正样本（这一情况在 DiverseVul 上基本不会发生）。
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


def get_stratum_key(rec: Record) -> Tuple[str, str]:
    cwe = rec.get("cwe") or "None"
    project = rec.get("project") or "unknown"
    return str(cwe), str(project)


def group_by_stratum(records: List[Record]) -> Dict[Tuple[str, str], List[Record]]:
    groups: Dict[Tuple[str, str], List[Record]] = defaultdict(list)
    for rec in records:
        key = get_stratum_key(rec)
        groups[key].append(rec)
    return groups


def stratified_sample_negatives(
    negatives: List[Record],
    target_n: int,
    rng: random.Random,
) -> List[Record]:
    """
    对负样本进行近似分层采样，分层依据 (cwe, project)。
    若 negatives 数量不足 target_n，则返回全部负样本并告警。
    """
    n_total = len(negatives)
    if n_total == 0 or target_n <= 0:
        return []

    if n_total <= target_n:
        print(
            f"[WARN] Only {n_total} negative samples available, "
            f"less than requested {target_n}, returning all negatives.",
            file=sys.stderr,
        )
        shuffled = negatives[:]
        rng.shuffle(shuffled)
        return shuffled

    groups = group_by_stratum(negatives)
    quotas = {}
    for key, group in groups.items():
        frac = len(group) / n_total
        quotas[key] = int(round(frac * target_n))

    # 调整 quotas 总和到 target_n
    quota_sum = sum(quotas.values())
    delta = target_n - quota_sum
    if delta != 0:
        sorted_keys = sorted(groups.keys(), key=lambda k: len(groups[k]), reverse=(delta > 0))
        idx = 0
        step = 1 if delta > 0 else -1
        for _ in range(abs(delta)):
            k = sorted_keys[idx % len(sorted_keys)]
            quotas[k] = max(0, quotas[k] + step)
            idx += 1

    selected: List[Record] = []
    remaining_pool: List[Record] = []
    for key, group in groups.items():
        group_size = len(group)
        quota = min(group_size, quotas.get(key, 0))
        if quota > 0:
            chosen = rng.sample(group, quota)
            selected.extend(chosen)
            remaining = [x for x in group if x not in chosen]
            remaining_pool.extend(remaining)
        else:
            remaining_pool.extend(group)

    current_n = len(selected)
    if current_n < target_n and remaining_pool:
        need = target_n - current_n
        if need > len(remaining_pool):
            print(
                f"[WARN] Cannot fully meet negative target_n={target_n}, "
                f"only {current_n + len(remaining_pool)} available.",
                file=sys.stderr,
            )
            need = len(remaining_pool)
        extra = rng.sample(remaining_pool, need)
        selected.extend(extra)

    rng.shuffle(selected)
    if len(selected) > target_n:
        selected = selected[:target_n]
    return selected


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare evaluation subset D_eval from normalized DiverseVul-Test JSONL."
    )
    parser.add_argument("--input", required=True, help="Path to normalized diversevul_test.jsonl")
    parser.add_argument("--output", required=True, help="Output path for D_eval JSONL")
    parser.add_argument(
        "--target-size", type=int, default=10000,
        help="Approximate total size of D_eval (default: 10000)."
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling")

    args = parser.parse_args()

    records = read_jsonl(args.input)
    print(f"[INFO] Loaded {len(records)} records from {args.input}")

    positives = [r for r in records if int(r.get("target", 0)) == 1]
    negatives = [r for r in records if int(r.get("target", 0)) == 0]

    print(f"[INFO] Positives in test_full: {len(positives)}")
    print(f"[INFO] Negatives in test_full: {len(negatives)}")

    rng = random.Random(args.seed)

    if len(positives) >= args.target_size:
        print(
            f"[WARN] Positives ({len(positives)}) >= target_size ({args.target_size}), "
            f"using all positives only.",
            file=sys.stderr,
        )
        d_eval = positives[:]
        rng.shuffle(d_eval)
    else:
        remaining_capacity = args.target_size - len(positives)
        neg_selected = stratified_sample_negatives(negatives, remaining_capacity, rng)
        d_eval = positives + neg_selected
        rng.shuffle(d_eval)

    print(f"[INFO] D_eval size: {len(d_eval)} (pos={len([r for r in d_eval if int(r.get('target',0))==1])}, "
          f"neg={len([r for r in d_eval if int(r.get('target',0))==0])})")

    write_jsonl(args.output, d_eval)
    print(f"[INFO] Wrote D_eval to {args.output}")


if __name__ == "__main__":
    main()
