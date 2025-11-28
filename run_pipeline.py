# --- START OF FILE run_pipeline.py ---

import typer
import json
import threading
import os
import queue
import signal
import sys
import gc
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from typing import List

try:
    import pynvml

    pynvml.nvmlInit()
except:
    pass

# 引入核心模块
from vulnsil.database import SessionLocal, get_db_session
from vulnsil.models import Vulnerability, AnalysisResultRecord, StaticAnalysisCache, Prediction
from vulnsil.core.rag.client import RAGClient
from vulnsil.core.llm.service import LLMService
from vulnsil.core.confidence import ConfidenceModel
from vulnsil.utils.feature_builder import FeatureBuilder
from vulnsil.core.static_analysis.compressor import SemanticCompressor
from vulnsil.core.static_analysis.ast_analyzer import ASTHeuristicAnalyzer
from vulnsil.utils_log import setup_logging
from config import settings

app = typer.Typer()
logger = setup_logging("pipeline")

# 全局变量与 Worker 单例服务
STOP_EVENT = threading.Event()
INTERRUPT_COUNT = 0
DB_QUEUE = queue.Queue(maxsize=100)
DB_WRITER = None

# Worker 内使用的服务单例（避免每个 Task 重新加载大文件）
_rag_client = None
_llm_service = None
_conf_model = None
_feat_builder = None
_compressor = None
_ast_analyzer = None

# 统计信息
STATS = {
    'total_processed': 0,
    'llm_success': 0,
    'llm_failed': 0,
    'static_source_joern': 0,
    'static_source_fallback': 0,
    'static_source_none': 0
}


def signal_handler(signum, frame):
    global INTERRUPT_COUNT
    INTERRUPT_COUNT += 1
    if INTERRUPT_COUNT >= 2:
        print("\n💀 Force killing process...")
        os._exit(1)
    else:
        logger.warning("\n🛑 Stopping pipeline gracefully... (Ctrl+C again to force)")
        STOP_EVENT.set()


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def db_writer_thread():
    """DB 批量写入线程，写入 Prediction 及 Update Task"""
    sess = SessionLocal()
    batch = []
    while not STOP_EVENT.is_set():
        try:
            item = DB_QUEUE.get(timeout=1)
            if item is None: break
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


def init_worker_services():
    """Worker 初始化单例服务"""
    global _rag_client, _llm_service, _conf_model, _feat_builder, _compressor, _ast_analyzer
    if _rag_client is None:
        _rag_client = RAGClient()
    if _llm_service is None:
        _llm_service = LLMService()
    if _conf_model is None:
        _conf_model = ConfidenceModel()
    if _feat_builder is None:
        _feat_builder = FeatureBuilder(_conf_model.get_feature_names())
    if _compressor is None:
        _compressor = SemanticCompressor()
    if _ast_analyzer is None:
        _ast_analyzer = ASTHeuristicAnalyzer()


def ensure_resources(device: str = None):
    if device: os.environ['CUDA_VISIBLE_DEVICES'] = device


def process_inference(task: Vulnerability, cache: StaticAnalysisCache):
    """
    单任务处理流程:
    1. Static Data Setup
    2. RAG Search
    3. LLM Analysis
    4. Feature Building
    5. Confidence Model Prediction
    6. DB Output
    """
    init_worker_services()

    try:
        raw_code = task.code or ""
        code_for_prompt = raw_code
        if len(raw_code) > settings.COMPRESSION_TRIGGER_LEN:
            code_for_prompt = _compressor.compress(raw_code, settings.MAX_CODE_TOKENS_INPUT)

        # 1. 静态分析特征
        static_data = {}
        if cache and cache.feature_json:
            static_data = json.loads(cache.feature_json)

        static_data['source_type'] = cache.source_type if cache else 0

        # 如果缓存中缺少 graph_density (旧缓存兼容), 临时补算
        if 'graph_density' not in static_data:
            _, _, gd = _ast_analyzer.scan(raw_code[:5000])
            static_data['graph_density'] = gd

        # 2. RAG 检索
        rag_results = _rag_client.search(code_for_prompt, top_k=settings.RAG_TOP_K)

        # 3. LLM 推理
        llm_result = _llm_service.analyze(code_for_prompt, static_data, rag_results)

        # 4. 特征构建
        feat_dict, feat_vector = _feat_builder.build(
            llm_result=llm_result,
            static_feats=static_data,
            rag_results=rag_results,
            code_len=len(raw_code)
        )

        # 5. 置信度预测
        calib_conf, final_pred = _conf_model.predict(feat_vector)

        # 6. 生成结果记录 (New Table)
        prediction = Prediction(
            vuln_id=task.id,
            name=task.name,
            dataset=task.dataset or "unknown",
            llm_pred=int(feat_dict['llm_pred']),
            llm_native_confidence=feat_dict['llm_confidence'],
            llm_reasoning=llm_result.reasoning[:3000],
            feature_json=json.dumps(feat_dict),
            rag_result_json=json.dumps(rag_results),
            calibrated_confidence=calib_conf,
            final_pred=final_pred
        )

        # 为了兼容性，也可以写旧表 (如果必要)，此处重点写入 Prediction
        # 更新任务状态
        task.status = "Success"

        DB_QUEUE.put(prediction)
        DB_QUEUE.put(task)

        return True

    except Exception as e:
        logger.error(f"Processing failed for task {task.id}: {e}")
        task.status = "Failed"
        DB_QUEUE.put(task)
        return False


def run_batched_pipeline(task_ids: List[int]):
    """多线程调度执行"""
    start_db_writer()

    batch_size = 32  # 调度批次大小
    total = len(task_ids)
    batches = [task_ids[i:i + batch_size] for i in range(0, total, batch_size)]

    with tqdm(total=total, desc="Running Pipeline") as pbar:
        for batch in batches:
            if STOP_EVENT.is_set(): break

            # 读取数据
            with get_db_session() as db:
                tasks = db.query(Vulnerability).filter(Vulnerability.id.in_(batch)).all()
                # 预读缓存
                names = [t.name for t in tasks]
                caches = db.query(StaticAnalysisCache).filter(StaticAnalysisCache.task_name.in_(names)).all()
                cache_map = {c.task_name: c for c in caches}

            futures = []
            with ThreadPoolExecutor(max_workers=settings.STATIC_ANALYSIS_CONCURRENCY) as executor:
                for t in tasks:
                    cache = cache_map.get(t.name)
                    # 统计静态来源
                    if cache:
                        if cache.source_type == 2:
                            STATS['static_source_joern'] += 1
                        else:
                            STATS['static_source_fallback'] += 1
                    else:
                        STATS['static_source_none'] += 1

                    futures.append(executor.submit(process_inference, t, cache))

                for f in as_completed(futures):
                    if STOP_EVENT.is_set():
                        [xf.cancel() for xf in futures]
                        break
                    try:
                        if f.result():
                            STATS['llm_success'] += 1
                        else:
                            STATS['llm_failed'] += 1
                    except Exception:
                        STATS['llm_failed'] += 1

                    STATS['total_processed'] += 1
                    pbar.set_postfix({"OK": STATS['llm_success'], "Fail": STATS['llm_failed']})
                    pbar.update(1)

            # 定期清理显存
            gc.collect()

    stop_db_writer()
    print_stats()


def print_stats():
    print(f"\n===== DONE =====")
    print(f"Processed: {STATS['total_processed']}")
    print(f"Success: {STATS['llm_success']} | Failed: {STATS['llm_failed']}")
    print(
        f"Joern/Fallback/None: {STATS['static_source_joern']}/{STATS['static_source_fallback']}/{STATS['static_source_none']}")


@app.command()
def run(split_name: str = typer.Option(..., help="Dataset split name like diversevul_test"),
        limit: int = -1,
        offset: int = 0,
        device: str = None):
    """
    Main Entry Point: Load pending tasks and run the RAG-LLM pipeline.
    """
    ensure_resources(device)

    logger.info(f"🚀 Starting Pipeline for split: {split_name}")

    with SessionLocal() as db:
        q = db.query(Vulnerability.id).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status.in_(["Pending", "Failed"])
        )
        if offset > 0: q = q.offset(offset)
        if limit > 0: q = q.limit(limit)
        task_ids = [r[0] for r in q.all()]

    if not task_ids:
        logger.warning(f"No pending tasks found for {split_name}")
        return

    try:
        run_batched_pipeline(task_ids)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    app()