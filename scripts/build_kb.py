"""Build RAG knowledge base for VulnSIL.

This script loads normalized DiverseVul and VCLData datasets, performs balanced
stratified sampling, and exports a JSONL knowledge base suitable for RAG
pipelines.
"""
from __future__ import annotations

import json
import logging
import random
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import typer

logger = logging.getLogger(__name__)


@dataclass
class Record:
    """Container for a single input record."""

    code: str | None
    label: int | None
    cwe: str | None
    project: str | None
    commit_id: str | None
    source: str

    @classmethod
    def from_raw(cls, data: Dict, source: str) -> "Record":
        return cls(
            code=data.get("func"),
            label=data.get("target"),
            cwe=data.get("cwe"),
            project=data.get("project"),
            commit_id=data.get("commit_id"),
            source=source,
        )


@dataclass
class SampledRecord:
    """Output record with assigned identifier."""

    id: int
    code: str | None
    label: int | None
    cwe: str | None
    project: str | None
    commit_id: str | None
    source: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "id": self.id,
                "code": self.code,
                "label": self.label,
                "cwe": self.cwe,
                "project": self.project,
                "commit_id": self.commit_id,
                "source": self.source,
            },
            ensure_ascii=False,
        )


def load_jsonl(path: Path, source: str) -> List[Record]:
    """Load records from a JSONL file, skipping malformed lines."""

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    records: List[Record] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
                records.append(Record.from_raw(data, source))
            except json.JSONDecodeError:
                logger.warning("[WARN] JSON decode error at %s:%d; skipping line", path, line_no)
                continue
    logger.info("[INFO] Loaded %d records from %s", len(records), source.capitalize())
    return records


def group_by_layer(records: Iterable[Record]) -> Dict[Tuple[str | None, str | None], List[Record]]:
    """Group records by (cwe, project) layer."""

    layers: Dict[Tuple[str | None, str | None], List[Record]] = defaultdict(list)
    for rec in records:
        key = (rec.cwe, rec.project)
        layers[key].append(rec)
    return layers


def allocate_quotas(layer_counts: Dict[Tuple[str | None, str | None], int], target: int) -> Dict[Tuple[str | None, str | None], int]:
    """Allocate quotas per layer using the largest remainder method."""

    if target <= 0 or not layer_counts:
        return {layer: 0 for layer in layer_counts}

    total = sum(layer_counts.values())
    quotas: Dict[Tuple[str | None, str | None], int] = {}
    remainders: List[Tuple[float, Tuple[str | None, str | None]]] = []

    allocated = 0
    for layer, count in layer_counts.items():
        proportion = (count / total) * target
        base = int(proportion)
        quotas[layer] = base
        allocated += base
        remainders.append((proportion - base, layer))

    remaining = max(target - allocated, 0)
    for _, layer in sorted(remainders, key=lambda x: x[0], reverse=True):
        if remaining <= 0:
            break
        quotas[layer] += 1
        remaining -= 1

    return quotas


def stratified_sample(records: List[Record], target: int, rng: random.Random, desc: str) -> List[Record]:
    """Perform approximate stratified sampling with fallback."""

    if target <= 0 or not records:
        return []

    layers = group_by_layer(records)
    layer_counts = {layer: len(items) for layer, items in layers.items()}
    quotas = allocate_quotas(layer_counts, target)

    sampled: List[Record] = []
    remaining_pool: List[Record] = []

    for layer, items in layers.items():
        quota = quotas.get(layer, 0)
        if quota <= 0:
            remaining_pool.extend(items)
            continue

        if len(items) <= quota:
            sampled.extend(items)
        else:
            chosen = rng.sample(items, quota)
            sampled.extend(chosen)
            remaining_pool.extend([rec for rec in items if rec not in chosen])

    if len(sampled) < target and remaining_pool:
        needed = target - len(sampled)
        fallback_count = min(len(remaining_pool), needed)
        sampled.extend(rng.sample(remaining_pool, fallback_count))

    if len(sampled) < target:
        logger.warning(
            "[WARN] Unable to reach target=%d for %s; sampled %d records.", target, desc, len(sampled)
        )

    rng.shuffle(sampled)
    return sampled[:target]


def build_kb(
    diversevul_path: Path,
    vcldata_path: Path,
    output_path: Path,
    real_pos: int,
    real_neg: int,
    syn_pos: int,
    syn_neg: int,
    seed: int,
) -> None:
    rng = random.Random(seed)

    diversevul_records = load_jsonl(diversevul_path, "diversevul")
    vcldata_records = load_jsonl(vcldata_path, "vcldata")

    real_records = diversevul_records
    syn_records = vcldata_records

    real_pos_pool = [r for r in real_records if r.label == 1]
    real_neg_pool = [r for r in real_records if r.label == 0]
    syn_pos_pool = [r for r in syn_records if r.label == 1]
    syn_neg_pool = [r for r in syn_records if r.label == 0]

    logger.info(
        "[INFO] Source=diversevul: pos=%d neg=%d", len(real_pos_pool), len(real_neg_pool)
    )
    logger.info("[INFO] Source=vcldata: pos=%d neg=%d", len(syn_pos_pool), len(syn_neg_pool))

    logger.info("[INFO] Building real KB: pos=%d neg=%d", real_pos, real_neg)
    real_pos_sample = stratified_sample(real_pos_pool, real_pos, rng, "real-positive")
    real_neg_sample = stratified_sample(real_neg_pool, real_neg, rng, "real-negative")

    logger.info("[INFO] Building synthetic KB: pos=%d neg=%d", syn_pos, syn_neg)
    syn_pos_sample = stratified_sample(syn_pos_pool, syn_pos, rng, "synthetic-positive")
    syn_neg_sample = stratified_sample(syn_neg_pool, syn_neg, rng, "synthetic-negative")

    all_samples: List[SampledRecord] = []
    next_id = 1

    def add_records(records: Iterable[Record]):
        nonlocal next_id
        for rec in records:
            all_samples.append(
                SampledRecord(
                    id=next_id,
                    code=rec.code,
                    label=rec.label,
                    cwe=rec.cwe,
                    project=rec.project,
                    commit_id=rec.commit_id,
                    source=rec.source,
                )
            )
            next_id += 1

    for subset in (real_pos_sample, real_neg_sample, syn_pos_sample, syn_neg_sample):
        rng.shuffle(subset)
        add_records(subset)

    final_count = len(all_samples)
    logger.info("[INFO] Final KB size = %d", final_count)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for record in all_samples:
            f.write(record.to_json() + "\n")


def build(
    diversevul: Path = typer.Option(..., exists=True, readable=True, help="Path to normalized DiverseVul train JSONL"),
    vcldata: Path = typer.Option(..., exists=True, readable=True, help="Path to normalized VCLData JSONL"),
    output: Path = typer.Option(..., help="Path to output rag_kb.jsonl"),
    real_pos: int = typer.Option(20000, help="Number of positive samples from real data"),
    real_neg: int = typer.Option(20000, help="Number of negative samples from real data"),
    syn_pos: int = typer.Option(20000, help="Number of positive samples from synthetic data"),
    syn_neg: int = typer.Option(20000, help="Number of negative samples from synthetic data"),
    seed: int = typer.Option(42, help="Random seed"),
) -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    build_kb(diversevul, vcldata, output, real_pos, real_neg, syn_pos, syn_neg, seed)


app = typer.Typer(help="Build VulnSIL RAG knowledge base")
app.command()(build)


if __name__ == "__main__":
    app()
