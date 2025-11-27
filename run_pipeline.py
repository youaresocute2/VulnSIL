# VulnSIL/run_pipeline.py
import typer
import joblib
import os
import gc
import json
import threading
import time
import numpy as np
import pandas as pd
import queue
import signal
import sys
import re

try:
    import pynvml

    pynvml.nvmlInit()
except:
    pass

from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from vulnsil.database import SessionLocal
from vulnsil.models import Vulnerability, AnalysisResultRecord, StaticAnalysisCache
from vulnsil.core.retrieval.hybrid_search import HybridRetriever
from vulnsil.core.llm.vllm_client import VLLMClient
from vulnsil.core.llm.prompts import PromptManager
from vulnsil.utils_log import setup_logging
from vulnsil.core.static_analysis.compressor import SemanticCompressor
from config import settings

app = typer.Typer()
logger = setup_logging("pipeline")

# [更新] 15维特征列表
FEATURE_NAMES = [
    "llm_native_conf",
    "static_has_flow",
    "static_complexity",
    "static_apis_count",
    "static_risk_density",
    "source_type",
    "code_len_log",
    "is_compressed",
    "rag_sim_avg",
    "rag_top1_sim",
    "rag_var",
    "conflict_disagree",
    "conflict_static_yes_llm_no",
    "llm_uncertainty",
    "graph_density"  # 新增
]

# 信号控制
STOP_EVENT = threading.Event()
INTERRUPT_COUNT = 0


def signal_handler(signum, frame):
    global INTERRUPT_COUNT
    INTERRUPT_COUNT += 1
    if INTERRUPT_COUNT >= 2:
        print("\n💀 Force killing process (User request)...")
        os._exit(1)
    else:
        logger.warning("\n🛑 Received Stop Signal. Cancelling pending tasks... (Press Ctrl+C again to FORCE KILL)")
        STOP_EVENT.set()


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# 全局统计
STATS = {
    'total_processed': 0,
    'llm_success': 0,
    'llm_failed': 0,
    'static_source_joern': 0,
    'static_source_fallback': 0,
    'static_source_none': 0
}

# DB Writer Thread
DB_QUEUE = queue.Queue(maxsize=100)  # 新增：有限队列
DB_WRITER = None


def db_writer_thread():
    """
    DB写线程：batch写（每50条commit）
    """
    sess = SessionLocal()
    batch = []
    while not STOP_EVENT.is_set():
        try:
            item = DB_QUEUE.get(timeout=1)
            if item is None: break  # 停止信号
            batch.append(item)
            if len(batch) >= 50:
                sess.bulk_save_objects(batch)
                sess.commit()
                batch = []
        except queue.Empty:
            if batch:
                sess.bulk_save_objects(batch)
                sess.commit()
                batch = []
        except Exception as e:
            sess.rollback()
            logger.error(f"DB Write Error: {e}")
    if batch:
        sess.bulk_save_objects(batch)
        sess.commit()
    sess.close()


def start_db_writer():
    global DB_WRITER
    DB_WRITER = threading.Thread(target=db_writer_thread, daemon=True)
    DB_WRITER.start()


def stop_db_writer():
    DB_QUEUE.put(None)
    DB_WRITER.join()


def ensure_resources(device: str = None):
    if device:
        os.environ['CUDA_VISIBLE_DEVICES'] = device
    if 'pynvml' in sys.modules:
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        info = pynvml.nvmlDeviceGetMemoryInfo(handle)
        if info.used / info.total > 0.8:
            logger.warning("⚠️ High GPU Memory Usage. May cause OOM.")


def run_batched_pipeline(task_ids: List[int]):
    """
    批处理管道：添加batch DB写、图特征
    """
    start_db_writer()

    batch_size = 16
    batches = [task_ids[i:i + batch_size] for i in range(0, len(task_ids), batch_size)]

    with tqdm(total=len(task_ids), desc="Processing Tasks") as pbar:
        for batch in batches:
            if STOP_EVENT.is_set():
                break

            with get_db_session() as db:
                tasks = db.query(Vulnerability).filter(Vulnerability.id.in_(batch)).all()
                tasks = db.query(Vulnerability).filter(Vulnerability.id.in_(batch)).all()
                cache_query = db.query(StaticAnalysisCache).filter(
                    StaticAnalysisCache.task_name.in_([t.name for t in tasks])
                ).all()
                cache_map = {c.task_name: c for c in cache_query}

            futures = []
            with ThreadPoolExecutor(max_workers=16) as exe:
                for t in tasks:
                    c_data = cache_map.get(t.name)
                    if not c_data:
                        STATS['static_source_none'] += 1
                        continue

                    if c_data.source_type == 2:
                        STATS['static_source_joern'] += 1
                    elif c_data.source_type == 1:
                        STATS['static_source_fallback'] += 1
                    else:
                        STATS['static_source_none'] += 1

                    f = exe.submit(process_inference, t, c_data)
                    futures.append(f)

                for f in as_completed(futures):
                    if STOP_EVENT.is_set():
                        for rem_f in futures:
                            rem_f.cancel()
                        break

                    try:
                        if f.result():
                            STATS['llm_success'] += 1
                        else:
                            STATS['llm_failed'] += 1
                    except:
                        STATS['llm_failed'] += 1

                    STATS['total_processed'] += 1
                    pbar.set_postfix({"OK": STATS['llm_success'], "Fail": STATS['llm_failed']})
                    pbar.update(1)

            manual_gc()

    stop_db_writer()
    print_final_stats()


def process_inference(task: Vulnerability, cache: StaticAnalysisCache):
    """
    单任务推理：添加图特征、加权冲突
    """
    retriever = HybridRetriever()
    llm_client = VLLMClient()
    compressor = SemanticCompressor()

    code = compressor.compress(task.code) if len(task.code) > settings.COMPRESSION_TRIGGER_LEN else task.code
    rag_entries = retriever.search(code, settings.RAG_TOP_K)

    # 从cache提取
    feat_json = json.loads(cache.feature_json) if cache.feature_json else {}
    has_flow = feat_json.get('has_flow', False)
    complexity = feat_json.get('complexity', 0)
    apis = feat_json.get('apis', [])

    # 新增：调用ast_analyzer获取图密度 (用Tree-sitter)
    analyzer = ASTHeuristicAnalyzer()
    _, _, graph_density = analyzer.scan(task.code)

    prompt = PromptManager.build_prompt(task.code, rag_entries, complexity, apis, has_flow)

    result, native_conf = llm_client.generate(prompt)
    if not result:
        task.status = "Failed"
        DB_QUEUE.put(task)  # queue写
        return False

    # [改进] 加权冲突
    decision_num = 1 if result.final_decision == "VULNERABLE" else 0
    conflict_disagree = cache.source_type * abs(has_flow - decision_num)

    # 保存结果（queue batch写）
    record = AnalysisResultRecord(
        vuln_id=task.id,
        raw_json=json.dumps(result.dict()),
        final_decision=result.final_decision,
        cwe_id=result.cwe_id,
        native_confidence=native_conf,
        calibrated_confidence=0.0,  # 后校准
        static_has_flow=has_flow,
        static_complexity=complexity,
        feat_static_apis_count=len(apis),
        feat_static_risk_density=len(apis) / len(task.code) if len(task.code) > 0 else 0,
        feat_static_source_type=cache.source_type,
        feat_code_len=len(task.code),
        feat_is_compressed=len(task.code) > settings.COMPRESSION_TRIGGER_LEN,
        feat_rag_agreement=... ,  # 原逻辑
        feat_rag_top1_sim=... ,
        feat_rag_sim_variance=... ,
        feat_conflict_disagreement=conflict_disagree,
        feat_conflict_static_yes_llm_no=1 if has_flow and decision_num == 0 else 0,
        feat_llm_uncertainty=... ,
        feat_graph_density=graph_density  # 新增
    )
    DB_QUEUE.put(record)
    task.status = "Success"
    DB_QUEUE.put(task)

    # [改进] 前置校准反馈（简化：如果conf低，log警告）
    model = joblib.load(settings.CONFIDENCE_MODEL_PATH)
    X = np.array([[native_conf, has_flow, complexity, len(apis), record.feat_static_risk_density, cache.source_type, np.log1p(len(task.code)), record.feat_is_compressed, ...]])  # 全特征
    calibrated_conf = model.predict(X)[0]
    if calibrated_conf < 0.5:
        logger.warning("Low conf, consider re-prompt")

    return True


def manual_gc():
    gc.collect()
    import torch
    if torch.cuda.is_available(): torch.cuda.empty_cache()


def print_final_stats():
    print(f"\n===== PIPELINE FINISHED =====")
    print(f"Total Processed: {STATS['total_processed']}")
    print(f"Success: {STATS['llm_success']} | Failed: {STATS['llm_failed']}")
    print(f"Static Source: Joern={STATS['static_source_joern']} | Fallback={STATS['static_source_fallback']}")


@app.command()
def run(split_name: str = typer.Option(..., help="Target dataset split prefix"),
        limit: int = -1, offset: int = 0, device: str = None):
    """Run pipeline with Graceful Shutdown (Double Ctrl+C to kill)"""
    ensure_resources(device)
    with SessionLocal() as db:
        q = db.query(Vulnerability.id).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status.in_(["Pending", "Failed"])
        )
        if offset > 0: q = q.offset(offset)
        if limit > 0: q = q.limit(limit)
        tasks = [r[0] for r in q.all()]

    if tasks:
        try:
            run_batched_pipeline(tasks)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    app()