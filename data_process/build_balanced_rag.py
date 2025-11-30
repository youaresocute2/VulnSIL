#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Build a balanced RAG knowledge base from DiverseVul-Train and VCLData.

输入：
- diversevul_train.jsonl (normalized, dataset="diversevul")
- vcldata_norm.jsonl     (normalized, dataset="vcldata")

输出：
- rag_kb.jsonl : 共 40000 条记录
  - From DiverseVul-Train: 10000 vuln + 10000 safe
  - From VCLData:          10000 vuln + 10000 safe
  - pos:neg = 20000 : 20000
  - real:syn = 20000 : 20000

采样策略：
- [新增] 预先筛选：去除代码为空或无效的样本，防止静态分析失效
- 对每个数据源、每个标签（0/1）分别进行近似分层采样（按 (cwe, project)）
- 样本不足时打印警告并返回全部可用记录
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


def filter_invalid_records(records: List[Record], source_name: str = "dataset") -> List[Record]:
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
            continue

        valid_records.append(rec)

    print(
        f"[INFO] [{source_name}] Filtered out {filtered_count} invalid records (empty code). Remaining: {len(valid_records)}")
    return valid_records


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


def stratified_sample(
        records: List[Record],
        target_n: int,
        rng: random.Random,
        label_desc: str,
) -> List[Record]:
    """
    与前面脚本类似的近似分层采样，用于构造 RAG KB 中某个子集。
    """
    n_total = len(records)
    if n_total == 0 or target_n <= 0:
        return []

    if n_total <= target_n:
        print(
            f"[WARN] {label_desc}: only {n_total} samples available, "
            f"less than requested {target_n}, returning all.",
            file=sys.stderr,
        )
        shuffled = records[:]
        rng.shuffle(shuffled)
        return shuffled

    groups = group_by_stratum(records)
    quotas: Dict[Tuple[str, str], int] = {}
    for key, group in groups.items():
        frac = len(group) / n_total
        quotas[key] = int(round(frac * target_n))

    # 调整 quotas 总和为 target_n
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
                f"[WARN] {label_desc}: cannot fully meet target_n={target_n}, "
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


def build_kb_for_source(
        records: List[Record],
        pos_target: int,
        neg_target: int,
        rng: random.Random,
        source_name: str,
) -> List[Record]:
    """
    为一个数据源（diversevul/vcldata）构建 pos/neg 平衡子集。
    """
    pos = [r for r in records if int(r.get("target", 0)) == 1]
    neg = [r for r in records if int(r.get("target", 0)) == 0]

    print(f"[INFO] Source={source_name}: filtered total={len(records)}, pos={len(pos)}, neg={len(neg)}")

    pos_selected = stratified_sample(pos, pos_target, rng, label_desc=f"{source_name}_pos")
    neg_selected = stratified_sample(neg, neg_target, rng, label_desc=f"{source_name}_neg")

    subset = pos_selected + neg_selected
    rng.shuffle(subset)

    print(
        f"[INFO] Source={source_name}: KB subset size={len(subset)} "
        f"(pos={len(pos_selected)}, neg={len(neg_selected)})"
    )
    return subset


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a balanced RAG KB from DiverseVul-Train and VCLData."
    )
    parser.add_argument("--diversevul-train", required=True, help="Path to diversevul_train.jsonl (normalized)")
    parser.add_argument("--vcldata", required=True, help="Path to vcldata_norm.jsonl (normalized)")
    parser.add_argument("--output", required=True, help="Output path for rag_kb.jsonl")

    parser.add_argument("--real-pos", type=int, default=10000,
                        help="# of positive samples from DiverseVul (default 10000)")
    parser.add_argument("--real-neg", type=int, default=10000,
                        help="# of negative samples from DiverseVul (default 10000)")
    parser.add_argument("--syn-pos", type=int, default=10000, help="# of positive samples from VCLData (default 10000)")
    parser.add_argument("--syn-neg", type=int, default=10000, help="# of negative samples from VCLData (default 10000)")

    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling")

    args = parser.parse_args()

    rng = random.Random(args.seed)

    diverse_records = read_jsonl(args.diversevul_train)
    vcl_records = read_jsonl(args.vcldata)

    print(f"[INFO] Loaded {len(diverse_records)} records from {args.diversevul_train}")
    print(f"[INFO] Loaded {len(vcl_records)} records from {args.vcldata}")

    # [新增] 过滤无效数据
    diverse_records = filter_invalid_records(diverse_records, source_name="DiverseVul")
    vcl_records = filter_invalid_records(vcl_records, source_name="VCLData")

    kb_real = build_kb_for_source(
        diverse_records,
        pos_target=args.real_pos,
        neg_target=args.real_neg,
        rng=rng,
        source_name="diversevul",
    )

    kb_syn = build_kb_for_source(
        vcl_records,
        pos_target=args.syn_pos,
        neg_target=args.syn_neg,
        rng=rng,
        source_name="vcldata",
    )

    kb_all = kb_real + kb_syn
    rng.shuffle(kb_all)

    print(
        f"[INFO] Final KB size={len(kb_all)} "
        f"(pos={len([r for r in kb_all if int(r.get('target', 0)) == 1])}, "
        f"neg={len([r for r in kb_all if int(r.get('target', 0)) == 0])})"
    )

    write_jsonl(args.output, kb_all)
    print(f"[INFO] Wrote RAG KB to {args.output}")


if __name__ == "__main__":
    main()