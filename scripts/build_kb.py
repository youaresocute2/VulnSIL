# scripts/build_kb.py
import sys
import os
import json
import glob
import pickle
import logging
import hashlib
import numpy as np
import faiss
from tqdm import tqdm
from rank_bm25 import BM25Okapi

# 路径适配
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
from vulnsil.database import get_db_session, engine, Base
from vulnsil.models import KnowledgeBase
from vulnsil.core.retrieval.vector_db_manager import EmbeddingModel
# [关键] 引入压缩器以实现数据对齐
from vulnsil.core.static_analysis.compressor import SemanticCompressor
from vulnsil.utils_log import setup_logging

setup_logging("build_kb")
log = logging.getLogger(__name__)


def parse_json_file(filepath: str):
    """解析 JSON 或 JSONL 文件"""
    records = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content.startswith('['):
                try:
                    records = json.loads(content)
                except json.JSONDecodeError:
                    pass
            else:
                lines = content.split('\n')
                for line in lines:
                    if line.strip():
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
    except Exception as e:
        log.error(f"Read Error: {filepath} - {e}")
    return records


def print_summary_table(stats: dict):
    """打印统计报表"""
    print("\n" + "=" * 65)
    print(f" RAG IMPORT SUMMARY REPORT")
    print("=" * 65)
    print(f"{'DATASET FILE':<30} | {'IMPORTED (VULN)':<15} | {'SKIPPED':<15}")
    print("-" * 65)
    total_ok, total_skip = 0, 0
    for fname, info in stats.items():
        print(f"{fname:<30} | {info['added']:<15} | {info['skipped']:<15}")
        total_ok += info['added']
        total_skip += info['skipped']
    print("-" * 65)
    print(f"{'TOTAL':<30} | {total_ok:<15} | {total_skip:<15}")
    print("=" * 65 + "\n")


def import_rag_data_scan(db):
    """
    步骤 1: 扫描 RAG 目录并入库
    """
    rag_dir = os.path.join(settings.DATA_DIR, "data_RAG")
    if not os.path.exists(rag_dir):
        log.critical(f"RAG dir missing: {rag_dir}")
        return 0

    files = glob.glob(os.path.join(rag_dir, "*.json")) + glob.glob(os.path.join(rag_dir, "*.jsonl"))
    stats_report = {}

    log.info(f"Scanning {len(files)} files in {rag_dir}...")

    for filepath in files:
        filename = os.path.basename(filepath)
        records = parse_json_file(filepath)

        batch_buffer = []
        file_added_count = 0

        # 先获取当前文件已有的所有 OID，用于增量去重
        existing_oids = {r[0] for r in db.query(KnowledgeBase.original_id).filter(
            KnowledgeBase.source_dataset == filename).all()}

        for idx, item in enumerate(records):
            try:
                code = item.get('func') or item.get('code') or item.get('function')
                if not code: continue

                # Robust Label Processing (Support full ingest)
                raw_label = item.get('target') if item.get('target') is not None else item.get('label')
                if raw_label is None: raw_label = item.get('vuln')

                if raw_label is None: continue

                try:
                    int_label = int(raw_label)
                    final_label = "VULNERABLE" if int_label == 1 else "BENIGN"
                except:
                    continue

                raw_cwe = item.get('cwe_id') or item.get('cwe')
                if isinstance(raw_cwe, list):
                    cwe_val = raw_cwe[0] if raw_cwe else "N/A"
                else:
                    cwe_val = str(raw_cwe) if raw_cwe and str(raw_cwe).lower() not in ['nan', 'null', 'none'] else "N/A"

                cid = item.get('commit_id') or item.get('id') or "unk"
                oid = f"{filename}_{idx}_{str(cid)[:32]}"

                if oid in existing_oids:
                    continue

                kb = KnowledgeBase(
                    original_id=oid,
                    code=code,
                    label=final_label,
                    cwe_id=cwe_val,
                    source_dataset=filename
                )
                batch_buffer.append(kb)
                existing_oids.add(oid)

            except Exception:
                continue

        if batch_buffer:
            try:
                batch_size = settings.KB_BUILD_BATCH_INSERT_SIZE
                for i in range(0, len(batch_buffer), batch_size):
                    chunk = batch_buffer[i:i + batch_size]
                    db.bulk_save_objects(chunk)
                    db.commit()

                file_added_count = len(batch_buffer)
                log.info(f"Processed {filename}: Added {file_added_count}")
            except Exception as e:
                db.rollback()
                log.error(f"Batch Insert Failed for {filename}: {e}")
                file_added_count = 0
        else:
            log.info(f"Processed {filename}: No new unique entries found.")

        stats_report[filename] = {"added": file_added_count, "skipped": len(records) - file_added_count}

    print_summary_table(stats_report)
    return sum(s['added'] for s in stats_report.values())


def build_indices(db):
    """
    步骤 2: 构建索引
    [Core Fix]: 数据原子性和一致性预处理。
    """
    count = db.query(KnowledgeBase).count()
    if count == 0:
        log.warning("KnowledgeBase empty. Skipping index build.")
        return

    log.info(f"Building indices for {count} entries...")
    log.info("Loading Models (Encoder & Compressor)...")

    encoder = EmbeddingModel()  # Auto-device & normalization

    try:
        compressor = SemanticCompressor()
        log.info("✅ Semantic Compressor loaded for alignment.")
    except Exception as e:
        log.error(f"Compressor init failed ({e}). Indexing will proceed in RAW mode (Latency Warning).")
        compressor = None

    # 分页查询避免内存爆炸
    total_entries = db.query(KnowledgeBase.id).count()
    chunk_size = settings.KB_BUILD_CHUNK_SIZE

    vectors_list = []
    tokenized_corpus = []
    db_ids_list = []

    log.info("Generating Embeddings (Batched)...")

    for offset in range(0, total_entries, chunk_size):
        # [Fix II/IV] Enforce Deterministic Order to prevent index drift
        entries = db.query(KnowledgeBase).order_by(KnowledgeBase.id).offset(offset).limit(chunk_size).all()
        if not entries: break

        for item in tqdm(entries, desc=f"Chunk {offset // chunk_size + 1}", leave=False):

            raw_code = item.code
            processed_code = raw_code

            # [Core Alignment Logic]
            if compressor and len(raw_code) > settings.COMPRESSION_TRIGGER_LEN:
                try:
                    processed_code = compressor.compress(raw_code, settings.MAX_CODE_TOKENS_INPUT)
                except:
                    pass

            # 2. Vector
            vec = encoder.encode(processed_code)

            # 3. [Atomic Append]
            vectors_list.append(vec)
            tokenized_corpus.append(processed_code.split())
            db_ids_list.append(item.id)

    if not vectors_list:
        log.error("No vectors generated. Check data source.")
        return

    # [Fix IV] Validation & Integrity
    if len(vectors_list) != len(db_ids_list):
        log.critical(f"FATAL: Vector count {len(vectors_list)} != ID count {len(db_ids_list)}. Aborting save.")
        return

    # Compute integrity hash
    id_list_str = "".join(str(x) for x in db_ids_list)
    integrity_hash = hashlib.md5(id_list_str.encode('utf-8')).hexdigest()
    log.info(f"Integrity Hash Generated: {integrity_hash}")

    # FAISS Save
    log.info("Creating FAISS Index...")
    vectors_np = np.vstack(vectors_list).astype('float32')
    index = faiss.IndexFlatIP(vectors_np.shape[1])
    index.add(vectors_np)

    os.makedirs(os.path.dirname(settings.FAISS_INDEX_PATH), exist_ok=True)
    faiss.write_index(index, settings.FAISS_INDEX_PATH)
    log.info(f"Saved FAISS -> {settings.FAISS_INDEX_PATH}")

    # BM25 Save with integrity meta
    log.info("Creating BM25 Index...")
    bm25 = BM25Okapi(tokenized_corpus)
    with open(settings.BM25_INDEX_PATH, 'wb') as f:
        # [Fix 2] Saving hash for runtime check
        pickle.dump({'model': bm25, 'ids': db_ids_list, 'integrity_hash': integrity_hash}, f)
    log.info(f"Saved BM25 -> {settings.BM25_INDEX_PATH}")

    log.info("✅ Indexing Successfully Completed.")


if __name__ == "__main__":
    try:
        Base.metadata.create_all(bind=engine)
        with get_db_session() as sess:
            # Step 1
            if sess.query(KnowledgeBase).count() == 0:
                import_rag_data_scan(sess)
            else:
                log.info("DB not empty, skipping scan (Force re-scan using manage_database.py --recreate)")
            # Step 2
            build_indices(sess)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log.critical(f"Fatal: {e}", exc_info=True)