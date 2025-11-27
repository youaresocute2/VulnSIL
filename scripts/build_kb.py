# scripts/build_kb.py
import sys
import os
import json
import glob
import pickle
import logging
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
    """步骤 1: 扫描 RAG 目录并入库 (原始数据)"""
    rag_dir = os.path.join(settings.DATA_DIR, "data_RAG")
    if not os.path.exists(rag_dir):
        log.critical(f"RAG dir missing: {rag_dir}")
        return {}

    patterns = ["*.json", "*.jsonl"]
    files = [f for pat in patterns for f in glob.glob(os.path.join(rag_dir, pat))]

    stats = {}
    batch_size = settings.KB_BUILD_BATCH_INSERT_SIZE
    buffer = []

    for filepath in files:
        fname = os.path.basename(filepath)
        stats[fname] = {'added': 0, 'skipped': 0}
        records = parse_json_file(filepath)
        for rec in records:
            if 'code' not in rec or 'label' not in rec:
                stats[fname]['skipped'] += 1
                continue
            if rec['label'] != 1:  # 只导入漏洞数据（原逻辑）
                stats[fname]['skipped'] += 1
                continue
            original_id = rec.get('commit_id', '') + '_' + rec.get('func_id', '')
            obj = KnowledgeBase(
                original_id=original_id,
                code=rec['code'],
                label=rec['label'],
                cwe_id=rec.get('cwe_id', 'N/A'),
                source_dataset=fname
            )
            buffer.append(obj)
            if len(buffer) >= batch_size:
                try:
                    db.bulk_save_objects(buffer)
                    db.commit()
                    stats[fname]['added'] += len(buffer)
                    buffer = []
                except Exception as e:
                    db.rollback()
                    log.error(f"Batch Insert Failed: {e}")
                    stats[fname]['skipped'] += len(buffer)
                    buffer = []

    if buffer:
        try:
            db.bulk_save_objects(buffer)
            db.commit()
            for b in buffer:
                fname = b.source_dataset
                stats[fname]['added'] += 1
        except Exception as e:
            db.rollback()
            log.error(f"Final Batch Failed: {e}")

    # 新增：导入负样本（安全代码）
    neg_path = settings.RAG_NEGATIVE_DATA_PATH
    if os.path.exists(neg_path):
        log.info("导入负样本...")
        neg_records = parse_json_file(neg_path)
        neg_buffer = []
        for rec in neg_records[:10000]:  # 抽样10k，控制时间
            if 'code' not in rec or rec['label'] != 0:  # 只安全
                continue
            original_id = rec.get('commit_id', '') + '_' + rec.get('func_id', '')
            obj = KnowledgeBase(
                original_id=original_id,
                code=rec['code'],
                label=rec['label'],
                cwe_id='N/A',  # 安全无CWE
                source_dataset='negative_safe'
            )
            neg_buffer.append(obj)
        if neg_buffer:
            db.bulk_save_objects(neg_buffer)
            db.commit()
            log.info(f"添加 {len(neg_buffer)} 负样本")

    print_summary_table(stats)
    return stats


def build_indices(db):
    """步骤 2: 构建向量与稀疏索引"""
    total_entries = db.query(KnowledgeBase).count()
    if total_entries == 0:
        log.error("No entries in KB. Skipping index build.")
        return

    try:
        encoder = EmbeddingModel()
        compressor = SemanticCompressor()
    except Exception as e:
        log.critical(f"Init Failed: {e}")
        return

    chunk_size = settings.KB_BUILD_CHUNK_SIZE

    vectors_list = []
    tokenized_corpus = []
    db_ids_list = []

    log.info("Generating Embeddings (Batched)...")

    for offset in range(0, total_entries, chunk_size):
        entries = db.query(KnowledgeBase).offset(offset).limit(chunk_size).all()
        if not entries: break

        for item in tqdm(entries, desc=f"Chunk {offset // chunk_size + 1}", leave=False):
            # 1. 语义压缩 (与 Inference 对齐)
            if compressor:
                try:
                    processed_code = compressor.compress(item.code, settings.MAX_CODE_TOKENS_INPUT)
                except:
                    processed_code = item.code
            else:
                processed_code = item.code

            # 2. Vector
            vec = encoder.encode(processed_code)
            vectors_list.append(vec)

            # 3. BM25 Tokenize (简单按空字符分割)
            tokenized_corpus.append(processed_code.split())

            # 4. Mapping
            db_ids_list.append(item.id)

    if not vectors_list:
        log.error("No vectors generated. Check data source.")
        return

    # FAISS Save (Inner Product + Normalized Vectors = Cosine Sim)
    log.info("Creating FAISS Index...")
    vectors_np = np.vstack(vectors_list).astype('float32')
    index = faiss.IndexFlatIP(vectors_np.shape[1])
    index.add(vectors_np)

    os.makedirs(os.path.dirname(settings.FAISS_INDEX_PATH), exist_ok=True)
    faiss.write_index(index, settings.FAISS_INDEX_PATH)
    log.info(f"Saved FAISS -> {settings.FAISS_INDEX_PATH}")

    # BM25 Save
    log.info("Creating BM25 Index...")
    bm25 = BM25Okapi(tokenized_corpus)
    with open(settings.BM25_INDEX_PATH, 'wb') as f:
        pickle.dump({'model': bm25, 'ids': db_ids_list}, f)
    log.info(f"Saved BM25 -> {settings.BM25_INDEX_PATH}")

    log.info("✅ Indexing Successfully Completed.")


if __name__ == "__main__":
    try:
        Base.metadata.create_all(bind=engine)
        with get_db_session() as sess:
            # Step 1
            import_rag_data_scan(sess)
            # Step 2
            build_indices(sess)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log.critical(f"Fatal: {e}", exc_info=True)