#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Generic dataset splitter for VulnSIL normalized JSONL.

要求输入数据至少包含：
- "func": str
- 推荐包含 "commit_id": str，便于 commit 级划分

示例用法：

1) 按 commit_id 8:2 划分：
   python split_dataset.py --input diversevul_norm.jsonl \
       --train_output diversevul_train.jsonl \
       --test_output diversevul_test.jsonl \
       --train_ratio 0.8

2) 不存在 commit_id 时，也可以直接用 func 内容做 hash 划分。
"""

import argparse
import json
import sys
import hashlib
from collections import defaultdict
from typing import Dict, Any, List, Tuple, Optional


def stable_ratio_from_key(key: str) -> float:
    """
    将任意字符串稳定映射到 [0, 1) 区间，用于可复现划分。
    """
    h = hashlib.md5(key.encode("utf-8")).hexdigest()[:8]
    v = int(h, 16)
    return v / float(16 ** 8)


def read_jsonl(path: str) -> List[Dict[str, Any]]:
    data: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                data.append(obj)
            except json.JSONDecodeError as e:
                print(f"[WARN] JSON decode error at line {line_no}: {e}", file=sys.stderr)
    return data


def write_jsonl(path: str, records: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def get_group_key(rec: Dict[str, Any], group_field: str) -> Optional[str]:
    """
    根据 group_field 返回用于分组的 key。
    - "commit_id": 直接用 commit_id
    - "project_commit": project + "::" + commit_id
    - 其他字段：直接转字符串
    """
    if group_field == "commit_id":
        v = rec.get("commit_id")
        return str(v) if v else None
    if group_field == "project_commit":
        proj = rec.get("project")
        cid = rec.get("commit_id")
        if proj and cid:
            return f"{proj}::{cid}"
        elif cid:
            return str(cid)
        else:
            return None

    # 通用字段名
    if group_field in rec and rec[group_field] is not None:
        return str(rec[group_field])

    return None


def split_records(
    records: List[Dict[str, Any]],
    train_ratio: float,
    group_field: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    with_key: List[Dict[str, Any]] = []
    without_key: List[Dict[str, Any]] = []

    for rec in records:
        key = get_group_key(rec, group_field)
        if key is not None:
            rec["_group_key"] = key  # 用于调试
            with_key.append(rec)
        else:
            without_key.append(rec)

    # 按 group_key 分组
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for rec in with_key:
        groups[rec["_group_key"]].append(rec)

    train: List[Dict[str, Any]] = []
    test: List[Dict[str, Any]] = []

    for key, group in groups.items():
        ratio = stable_ratio_from_key(key)
        if ratio < train_ratio:
            train.extend(group)
        else:
            test.extend(group)

    # 对于没有 group key 的记录，按 func 内容 hash 分配
    for rec in without_key:
        func = rec.get("func", "") or ""
        key = str(func)[:128]
        ratio = stable_ratio_from_key(key)
        if ratio < train_ratio:
            train.append(rec)
        else:
            test.append(rec)

    # 清理中间字段
    for rec in train + test:
        rec.pop("_group_key", None)

    return train, test


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Split normalized JSONL dataset into train/test with stable hash-based grouping."
    )
    parser.add_argument("--input", required=True, help="Path to normalized JSONL.")
    parser.add_argument("--train_output", required=True, help="Output path for train JSONL.")
    parser.add_argument("--test_output", required=True, help="Output path for test JSONL.")
    parser.add_argument(
        "--train_ratio",
        type=float,
        default=0.8,
        help="Train ratio (default: 0.8).",
    )
    parser.add_argument(
        "--group_field",
        type=str,
        default="commit_id",
        help="Grouping field for split. Options: 'commit_id', 'project_commit', or any field name.",
    )

    args = parser.parse_args()

    records = read_jsonl(args.input)
    print(f"[INFO] Loaded {len(records)} records from {args.input}")

    train, test = split_records(records, train_ratio=args.train_ratio, group_field=args.group_field)
    print(f"[INFO] Split into {len(train)} train and {len(test)} test records "
          f"(train_ratio={args.train_ratio}, group_field={args.group_field})")

    write_jsonl(args.train_output, train)
    write_jsonl(args.test_output, test)

    print(f"[INFO] Wrote train JSONL to {args.train_output}")
    print(f"[INFO] Wrote test JSONL to {args.test_output}")


if __name__ == "__main__":
    main()
