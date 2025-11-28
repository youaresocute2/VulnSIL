from __future__ import annotations

from config import settings, init_runtime
init_runtime()

import json
import os
import pickle
from pathlib import Path
from typing import Dict, List

import faiss
import numpy as np
from rank_bm25 import BM25Okapi

from vulnsil.database import Base, engine, get_db_session
from vulnsil.models import KnowledgeBase
from vulnsil.core.retrieval.vector_db_manager import EmbeddingModel
from vulnsil.utils_log import setup_logging

logger = setup_logging("build_kb")


def scan_rag_folder(base_dir: Path) -> List[Dict]:
    logger.info("🔍 Scanning RAG folder...")
    records: List[Dict] = []

    for path in base_dir.rglob("*.jsonl"):
        try:
            with path.open("r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("[WARN] JSON decode error at %s:%d; skipping line", path, line_no)
                        continue

                    code = data.get("func", "") or ""
                    raw_label = data.get("target")
                    try:
                        label = int(raw_label) if raw_label is not None else None
                    except Exception:
                        label = None

                    record = {
                        "original_id": f"{path.relative_to(base_dir)}:{line_no}",
                        "code": code,
                        "label": label,
                        "cwe_id": data.get("cwe") or "N/A",
                        "source_dataset": data.get("project") or path.stem,
                    }
                    records.append(record)
        except Exception as exc:
            logger.error("Failed to read %s: %s", path, exc)
    logger.info("📥 Loaded %d records.", len(records))
    return records


def write_to_database(records: List[Dict]) -> None:
    logger.info("💾 Writing to database...")
    Base.metadata.create_all(bind=engine)

    with get_db_session() as db:
        db.query(KnowledgeBase).delete()
        batch_size = settings.KB_BUILD_BATCH_INSERT_SIZE
        buffer: List[KnowledgeBase] = []
        for rec in records:
            obj = KnowledgeBase(
                original_id=rec["original_id"],
                code=rec["code"],
                label=rec["label"],
                cwe_id=rec["cwe_id"],
                source_dataset=rec["source_dataset"],
            )
            buffer.append(obj)
            if len(buffer) >= batch_size:
                db.bulk_save_objects(buffer)
                db.commit()
                buffer.clear()
        if buffer:
            db.bulk_save_objects(buffer)
            db.commit()


def load_kb_entries() -> List[KnowledgeBase]:
    with get_db_session() as db:
        rows = db.query(KnowledgeBase).order_by(KnowledgeBase.id).all()
        return rows


def build_faiss_index(entries: List[KnowledgeBase]) -> Dict[str, int]:
    logger.info("🔧 Building FAISS index...")

    embedding_model = EmbeddingModel()
    vectors: List[np.ndarray] = []
    ids_map: Dict[str, int] = {}

    for idx, entry in enumerate(entries):
        embedding = embedding_model.encode(entry.code or "")
        vectors.append(embedding)
        ids_map[str(idx)] = entry.id

    if not vectors:
        logger.warning("No vectors to index. Skipping FAISS build.")
        return ids_map

    matrix = np.stack(vectors, axis=0).astype("float32")
    faiss.normalize_L2(matrix)

    index = faiss.IndexFlatIP(matrix.shape[1])
    index.add(matrix)

    os.makedirs(Path(settings.FAISS_INDEX_PATH).parent, exist_ok=True)
    faiss.write_index(index, settings.FAISS_INDEX_PATH)

    with open(settings.FAISS_IDS_MAP_PATH, "w", encoding="utf-8") as f:
        json.dump(ids_map, f, ensure_ascii=False, indent=2)

    return ids_map


def build_bm25_index(entries: List[KnowledgeBase], ids_map: Dict[str, int]) -> None:
    logger.info("🔧 Building BM25 index...")
    corpus_tokens: List[List[str]] = []

    for entry in entries:
        tokens = (entry.code or "").split()
        if not tokens:
            tokens = ["void"]
        corpus_tokens.append(tokens)

    bm25_model = BM25Okapi(corpus_tokens)

    payload = {"model": bm25_model, "ids": [ids_map[str(i)] for i in range(len(ids_map))]}
    os.makedirs(Path(settings.BM25_INDEX_PATH).parent, exist_ok=True)
    with open(settings.BM25_INDEX_PATH, "wb") as f:
        pickle.dump(payload, f)


def main():
    data_dir = Path(settings.DATA_DIR) / "data_RAG"
    records = scan_rag_folder(data_dir)
    if not records:
        logger.warning("No records found. Exiting.")
        return

    write_to_database(records)

    entries = load_kb_entries()
    if not entries:
        logger.warning("No entries available after DB write. Exiting.")
        return

    ids_map = build_faiss_index(entries)
    if not ids_map:
        logger.warning("No FAISS ids map generated. Exiting.")
        return

    build_bm25_index(entries, ids_map)

    logger.info("🎉 Completed!")


if __name__ == "__main__":
    main()
