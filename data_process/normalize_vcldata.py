#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Normalize VCLData JSONL to unified schema for VulnSIL.

输入示例：
{
  "func": "...",
  "name": "good2",
  "label": "0",
  "cwe_id": "None",
  "source": "...",
  "sink": "...",
  "reason": "..."
}

输出：
{
  "func": "...",
  "target": 0,
  "cwe": "None",
  "name": "good2",
  "source": "...",
  "sink": "...",
  "reason": "...",
  "dataset": "vcldata"
}
"""

import argparse
import json
import sys
from typing import Dict, Any, List


def normalize_cwe(cwe_id: Any) -> str:
    """
    将 vcldata 的 cwe_id 规范成统一字符串。
    - 如果是 "398" -> "CWE-398"
    - 如果是 "None"/None -> "None"
    - 否则直接转成 str
    """
    if cwe_id is None:
        return "None"
    s = str(cwe_id).strip()
    if s.lower() in {"none", "null", ""}:
        return "None"
    # 如果是纯数字，则加 CWE- 前缀
    if s.isdigit():
        return f"CWE-{s}"
    return s


def normalize_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    func = raw.get("func", "") or ""
    if not isinstance(func, str):
        func = str(func)

    label = raw.get("label", 0)
    if isinstance(label, str):
        target = 1 if label.strip() in {"1", "true", "True"} else 0
    else:
        target = int(label)

    cwe = normalize_cwe(raw.get("cwe_id"))

    norm = {
        "func": func,
        "target": target,
        "cwe": cwe,
        "dataset": "vcldata",
    }

    # 直接保留 vcldata 的其他有用字段
    for key in ["name", "source", "sink", "reason"]:
        if key in raw:
            norm[key] = raw[key]

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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize VCLData JSONL to unified schema."
    )
    parser.add_argument("--input", required=True, help="Path to raw VCLData JSONL.")
    parser.add_argument("--output", required=True, help="Path to write normalized JSONL.")
    args = parser.parse_args()

    raw_records = read_jsonl(args.input)
    print(f"[INFO] Loaded {len(raw_records)} raw VCLData records from {args.input}")

    normalized = [normalize_record(r) for r in raw_records]
    print(f"[INFO] Normalized {len(normalized)} records.")

    write_jsonl(args.output, normalized)
    print(f"[INFO] Wrote normalized JSONL to {args.output}")


if __name__ == "__main__":
    main()
