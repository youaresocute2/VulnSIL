#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Normalize DiverseVul JSONL to unified schema for VulnSIL.

输入：原始 DiverseVul JSONL，每行类似：
{
  "func": "...",
  "target": 1,
  "cwe": ["CWE-787"],
  "project": "qemu",
  "commit_id": "...",
  "hash": 2769...,
  "size": 18,
  "message": "..."
}

输出：归一化 JSONL：
{
  "func": "...",
  "target": 1,
  "cwe": "CWE-787",
  "project": "qemu",
  "commit_id": "...",
  "hash": 2769...,
  "size": 18,
  "message": "...",
  "dataset": "diversevul"
}
"""

import argparse
import json
import sys
import hashlib
from collections import defaultdict
from typing import Dict, Any, List, Tuple


def stable_ratio_from_key(key: str) -> float:
    """
    使用 commit_id 等字符串做稳定 hash，映射到 [0, 1) 作为划分依据。
    """
    h = hashlib.md5(key.encode("utf-8")).hexdigest()[:8]
    v = int(h, 16)
    return v / float(16 ** 8)


def normalize_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    将一条 DiverseVul 记录归一化为统一 schema。
    """
    func = raw.get("func", "") or ""
    if not isinstance(func, str):
        func = str(func)

    # target: 1/0
    target = raw.get("target", 0)
    if isinstance(target, str):
        target = 1 if target.strip() in {"1", "true", "True"} else 0
    else:
        target = int(target)

    # cwe: 取第一个元素，如果是数组；否则直接转字符串
    cwe_raw = raw.get("cwe", None)
    if isinstance(cwe_raw, list) and cwe_raw:
        cwe = str(cwe_raw[0])
    elif cwe_raw is None:
        cwe = "None"
    else:
        cwe = str(cwe_raw)

    project = raw.get("project", None)
    if project is not None:
        project = str(project)

    commit_id = raw.get("commit_id", None)
    if commit_id is not None:
        commit_id = str(commit_id)

    norm = {
        "func": func,
        "target": target,
        "cwe": cwe,
        "project": project,
        "commit_id": commit_id,
        "dataset": "diversevul",
    }

    # 把其他字段原样带上，避免信息丢失
    for key in ["hash", "size", "message"]:
        if key in raw:
            norm[key] = raw[key]

    # 额外保留原始字段，避免后面想对比/调试
    norm["_raw"] = raw
    return norm


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


def split_by_commit(
    records: List[Dict[str, Any]],
    train_ratio: float,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    按 commit 粒度进行稳定 8:2 划分。
    没有 commit_id 的样本按记录级别划分。
    """
    has_commit = [r for r in records if r.get("commit_id")]
    no_commit = [r for r in records if not r.get("commit_id")]

    # 先对有 commit_id 的按 commit 分组
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in has_commit:
        groups[r["commit_id"]].append(r)

    train: List[Dict[str, Any]] = []
    test: List[Dict[str, Any]] = []

    for commit_id, group in groups.items():
        ratio = stable_ratio_from_key(commit_id)
        if ratio < train_ratio:
            train.extend(group)
        else:
            test.extend(group)

    # 对没有 commit_id 的记录，直接按 func hash 分配
    for r in no_commit:
        key = r.get("func", "")[:128]  # 截断一下避免太长
        ratio = stable_ratio_from_key(key)
        if ratio < train_ratio:
            train.append(r)
        else:
            test.append(r)

    return train, test


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize DiverseVul JSONL to unified schema, optionally split into train/test."
    )
    parser.add_argument("--input", required=True, help="Path to raw DiverseVul JSONL.")
    parser.add_argument(
        "--output",
        help="Path to write normalized JSONL. If not set and train/test provided, only split outputs.",
    )
    parser.add_argument(
        "--train_output",
        help="If set, will also write train split JSONL (from normalized records).",
    )
    parser.add_argument(
        "--test_output",
        help="If set, will also write test split JSONL (from normalized records).",
    )
    parser.add_argument(
        "--train_ratio",
        type=float,
        default=0.8,
        help="Train ratio for commit-level split (default: 0.8).",
    )

    args = parser.parse_args()

    raw_records = read_jsonl(args.input)
    print(f"[INFO] Loaded {len(raw_records)} raw records from {args.input}")

    normalized = [normalize_record(r) for r in raw_records]
    print(f"[INFO] Normalized {len(normalized)} records.")

    if args.output:
        write_jsonl(args.output, normalized)
        print(f"[INFO] Wrote normalized JSONL to {args.output}")

    # 如果指定了 train/test 输出，则基于归一化数据做 commit 级划分
    if args.train_output or args.test_output:
        train, test = split_by_commit(normalized, train_ratio=args.train_ratio)
        if args.train_output:
            write_jsonl(args.train_output, train)
            print(f"[INFO] Wrote {len(train)} train records to {args.train_output}")
        if args.test_output:
            write_jsonl(args.test_output, test)
            print(f"[INFO] Wrote {len(test)} test records to {args.test_output}")


if __name__ == "__main__":
    main()
