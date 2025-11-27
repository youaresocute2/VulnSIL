# scripts/offline_static_analysis.py
import sys
import os
import json
import logging
import typer
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from sqlalchemy import or_

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vulnsil.database import SessionLocal, engine
from vulnsil.models import StaticAnalysisCache, Vulnerability, Base
from vulnsil.core.static_analysis.engine import DualEngineAnalyzer
from config import settings

# 初始化日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(name)s | %(message)s')
logger = logging.getLogger("OfflineEngine")

app = typer.Typer()


def analyze_chunk_worker(tasks_chunk):
    """
    Worker 进程执行静态分析
    """
    # 实例化引擎
    try:
        analyzer = DualEngineAnalyzer()
    except Exception as e:
        return []

    engine_input = []
    name_map = {}

    for i, t in enumerate(tasks_chunk):
        tmp_id = 10000 + i
        engine_input.append({'id': tmp_id, 'code': t['code']})
        name_map[tmp_id] = t['name']

    raw_results = analyzer.analyze_batch(engine_input)

    processed = []
    for tmp_id, features in raw_results.items():
        original_name = name_map.get(tmp_id)
        if not original_name: continue

        s_type = features.get('source_type', 0)
        feat_payload = {
            "has_flow": features.get('has_data_flow', False),
            "complexity": features.get('complexity', 0),
            "apis": features.get('apis', [])
        }

        processed.append({
            "task_name": original_name,
            "source_type": s_type,
            "feature_json": json.dumps(feat_payload)
        })

    return processed


def save_chunk_to_db(records):
    if not records: return
    sess = SessionLocal()
    try:
        for r in records:
            cache_obj = StaticAnalysisCache(
                task_name=r['task_name'],
                source_type=r['source_type'],
                feature_json=r['feature_json']
            )
            sess.add(cache_obj)
        sess.commit()
    except Exception as e:
        sess.rollback()
        logger.error(f"DB Save Failed: {e}")
    finally:
        sess.close()


@app.command()
def analyze_split(
        split_name: str = typer.Option(..., help="Dataset prefix (e.g., 'diversevul_test')"),
        limit: int = typer.Option(-1, help="Limit number of tasks to analyze (default: all)"),
):
    """
    Offline Static Analysis for a dataset split
    """
    Base.metadata.create_all(bind=engine)

    with get_db_session() as sess:
        cached_names = [r[0] for r in sess.query(StaticAnalysisCache.task_name).filter(
            StaticAnalysisCache.task_name.like(f"{split_name}%")
        ).all()]

    # 获取该 Split 下的所有任务
    query = sess.query(Vulnerability.name, Vulnerability.code) \
        .filter(Vulnerability.name.like(f"{split_name}%"))

    todo_list = []
    total_scanned = 0

    # 使用 yield_per 优化大查询，并支持 limit 中断
    logger.info("Scanning for uncached tasks...")
    for row in query.yield_per(1000):
        total_scanned += 1
        if row.name not in cached_names:
            if row.code:
                todo_list.append({'name': row.name, 'code': row.code})

            # [新增] Limit 控制逻辑
            if limit > 0 and len(todo_list) >= limit:
                logger.info(f"🛑 Reached limit of {limit} pending tasks. Stopping scan.")
                break

    sess.close()

    count_todo = len(todo_list)
    logger.info(f"Pending Analysis    : {count_todo}")

    if count_todo == 0:
        logger.info("✅ No new tasks to analyze.")
        return

    # 3. Configure Pool
    BATCH_SIZE = settings.STATIC_ANALYSIS_BATCH_SIZE
    MAX_WORKERS = max(1, os.cpu_count() - 2)

    logger.info(f"Launching Pool: {MAX_WORKERS} workers, Batch Size: {BATCH_SIZE}")

    batches = [todo_list[i:i + BATCH_SIZE] for i in range(0, count_todo, BATCH_SIZE)]

    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_batch = {pool.submit(analyze_chunk_worker, b): b for b in batches}

        with tqdm(total=count_todo, unit="file", desc="Analyzing") as pbar:
            for future in as_completed(future_to_batch):
                try:
                    result_records = future.result()
                    save_chunk_to_db(result_records)
                    pbar.update(len(future_to_batch[future]))
                except Exception as e:
                    logger.error(f"Chunk processing failed: {e}")
                    pbar.update(len(future_to_batch[future]))

    logger.info("🎉 Offline Analysis Complete.")


if __name__ == "__main__":
    app()