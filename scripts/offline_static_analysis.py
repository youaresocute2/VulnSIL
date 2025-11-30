# scripts/offline_static_analysis.py
import sys
import os
import json
import logging
import typer
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from sqlalchemy import or_

# Ensure project root in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnsil.database import SessionLocal, engine, Base
from vulnsil.models import StaticAnalysisCache, Vulnerability
# Assuming the engine file is named vulnsil/core/static_analysis/engine.py
# (Since not provided in modification request, standard import assumed)
from vulnsil.core.static_analysis.engine import DualEngineAnalyzer
from config import settings

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(name)s | %(message)s')
logger = logging.getLogger("OfflineEngine")

app = typer.Typer()


def analyze_chunk_worker(tasks_chunk):
    """
    Worker process. Runs DualEngineAnalyzer on a batch of tasks.
    """
    try:
        # Each worker initializes its own Engine (isolated JVM context usually for Joern)
        analyzer = DualEngineAnalyzer()
    except Exception as e:
        # If Engine init fails, fail safe for the whole batch
        logger.error(f"Worker Init Fail: {e}")
        return []

    # Map input format for Engine: needs list of {'id': int, 'code': str}
    engine_input = []
    name_map = {}

    for i, t in enumerate(tasks_chunk):
        # We assign a temporary integer ID for the Engine batch processing logic
        # Ideally using unique hash or simply enumerate idx within batch
        tmp_id = 10000 + i
        engine_input.append({'id': tmp_id, 'code': t['code']})
        name_map[tmp_id] = t['name']

    # Execute Analysis (Heavy Operation)
    raw_results = analyzer.analyze_batch(engine_input)

    processed_records = []
    for tmp_id, features in raw_results.items():
        original_name = name_map.get(tmp_id)
        if not original_name: continue

        # [Compatibility] Extract core fields needed by run_pipeline
        # DualEngineAnalyzer guarantees these fields
        s_type = features.get('source_type', 0)  # 2=Joern, 1=Regex, 0=None

        # Prepare the JSON blob required by models.StaticAnalysisCache
        feat_payload = {
            "has_flow": bool(features.get('has_data_flow', False)),
            "complexity": int(features.get('complexity', 0)),
            "apis": features.get('apis', [])
        }

        processed_records.append({
            "task_name": original_name,
            "source_type": s_type,
            "feature_json": json.dumps(feat_payload)
        })

    return processed_records


def save_chunk_to_db(records):
    """Save processed cache results to DB in main process."""
    if not records: return
    sess = SessionLocal()
    try:
        # Use bulk insert or merge. Merge checks for existing keys (task_name).
        for r in records:
            # Upsert Logic
            existing = sess.query(StaticAnalysisCache).filter(StaticAnalysisCache.task_name == r['task_name']).first()
            if existing:
                existing.source_type = r['source_type']
                existing.feature_json = r['feature_json']
            else:
                obj = StaticAnalysisCache(
                    task_name=r['task_name'],
                    source_type=r['source_type'],
                    feature_json=r['feature_json']
                )
                sess.add(obj)
        sess.commit()
    except Exception as e:
        sess.rollback()
        logger.error(f"DB Write Error: {e}")
    finally:
        sess.close()


@app.command()
def run(
        split_name: str = typer.Option(..., help="Target dataset split prefix (e.g., 'diversevul_train')"),
        limit: int = typer.Option(-1, help="Max number of tasks to analyze. -1 for all."),
        concurrency: int = typer.Option(settings.STATIC_ANALYSIS_CONCURRENCY, help="Number of worker processes")
):
    """
    Offline Static Analysis Runner.
    Populates 'StaticAnalysisCache' for 'run_pipeline.py' to use later.
    This step requires JOERN installed and configured in config.py.
    """
    # Ensure Tables
    Base.metadata.create_all(bind=engine)

    logger.info(f"🔥 Starting Static Analysis for: '{split_name}'")

    sess = SessionLocal()

    # 1. Check existing cache to skip
    logger.info("Checking existing cache...")
    cached_query = sess.query(StaticAnalysisCache.task_name).filter(
        StaticAnalysisCache.task_name.like(f"{split_name}%"))
    cached_names = {x[0] for x in cached_query.all()}

    # 2. Check pending tasks in Vulnerability table
    task_query = sess.query(Vulnerability.name, Vulnerability.code).filter(Vulnerability.name.like(f"{split_name}%"))

    todo_list = []

    logger.info("Calculating delta...")
    # yield_per for memory efficiency on huge datasets
    for row in task_query.yield_per(2000):
        if row.name not in cached_names:
            if row.code:
                todo_list.append({'name': row.name, 'code': row.code})

            # Early break if limit applied to collection
            if limit > 0 and len(todo_list) >= limit:
                break

    sess.close()

    count = len(todo_list)
    logger.info(f"Tasks pending analysis: {count}")
    if count == 0:
        logger.info("All tasks cached. Exiting.")
        return

    # 3. Batch Processing Pool
    # Batched logic reduces process overhead overhead of creating CPGs one-by-one if Engine supports it
    # Engine maps [id] -> cpg -> script -> results
    BATCH_SIZE = settings.STATIC_ANALYSIS_BATCH_SIZE

    # Chunking
    batches = [todo_list[i:i + BATCH_SIZE] for i in range(0, count, BATCH_SIZE)]

    workers = min(concurrency, os.cpu_count() or 1)
    logger.info(f"Starting Pool (Workers={workers}, Batch={BATCH_SIZE})")

    with ProcessPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(analyze_chunk_worker, b): b for b in batches}

        with tqdm(total=count, unit="task", desc="Joern Analysis") as pbar:
            for future in as_completed(future_map):
                try:
                    result_chunk = future.result()
                    # Main process writes DB (SQLite safer this way)
                    save_chunk_to_db(result_chunk)

                    # Update progress by batch size processed
                    pbar.update(len(future_map[future]))
                except Exception as e:
                    logger.error(f"Batch Failed: {e}")
                    pbar.update(len(future_map[future]))

    logger.info("🎉 Offline Static Analysis Complete.")


if __name__ == "__main__":
    app()