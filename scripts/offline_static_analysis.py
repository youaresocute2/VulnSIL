# scripts/offline_static_analysis.py
import sys
import os
import json
import logging
import typer
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnsil.database import SessionLocal, engine, get_db_session  # 修复：引入 get_db_session
from vulnsil.models import StaticAnalysisCache, Vulnerability, Base
from vulnsil.core.static_analysis.engine import DualEngineAnalyzer
from vulnsil.core.static_analysis.ast_analyzer import ASTHeuristicAnalyzer  # 新增：AST 特征
from config import settings

# 初始化日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(name)s | %(message)s'
)
logger = logging.getLogger("OfflineEngine")

app = typer.Typer()


def analyze_chunk_worker(tasks_chunk):
    """
    Worker 进程执行静态分析：
    - 使用 DualEngineAnalyzer（Joern + c2cpg 等）
    - 使用 ASTHeuristicAnalyzer（Tree-sitter）补充危险 API + 图密度特征
    返回的列表元素结构：
    {
        "task_name": str,
        "source_type": int,
        "feature_json": json.dumps({
            "has_flow": bool,
            "complexity": int,
            "apis": List[str],
            "ast_has_dangerous": bool,
            "graph_density": float,
            "api_count": int
        })
    }
    """
    try:
        analyzer = DualEngineAnalyzer()
    except Exception as e:
        # 如果初始化失败，整个 chunk 跳过
        logger.error(f"[Worker] DualEngineAnalyzer init failed: {e}")
        return []

    try:
        ast_analyzer = ASTHeuristicAnalyzer()
    except Exception as e:
        logger.error(f"[Worker] ASTHeuristicAnalyzer init failed: {e}")
        ast_analyzer = None

    engine_input = []
    name_map = {}
    code_map = {}

    # 构造 batch 输入
    for i, t in enumerate(tasks_chunk):
        tmp_id = 10000 + i  # 本地临时 id，不入库
        code = t.get("code", "") or ""
        name = t.get("name")

        engine_input.append({"id": tmp_id, "code": code})
        name_map[tmp_id] = name
        code_map[tmp_id] = code

    # 调用 DualEngineAnalyzer 批量分析
    try:
        raw_results = analyzer.analyze_batch(engine_input)
    except Exception as e:
        logger.error(f"[Worker] analyze_batch failed: {e}")
        return []

    processed = []
    for tmp_id, features in raw_results.items():
        original_name = name_map.get(tmp_id)
        if not original_name:
            continue

        # --- 从 DualEngineAnalyzer 提取特征 ---
        s_type = features.get("source_type", 0)
        has_flow = bool(features.get("has_data_flow", False))
        complexity = int(features.get("complexity", 0))
        apis_from_engine = features.get("apis", []) or []

        # --- 使用 ASTHeuristicAnalyzer 补充危险 API + 图密度 ---
        ast_has_dangerous = False
        graph_density = 0.0
        ast_apis = []

        code = code_map.get(tmp_id, "")
        if ast_analyzer is not None and code:
            try:
                ast_has_dangerous, ast_apis, graph_density = ast_analyzer.scan(code)
            except Exception:
                # AST 分析失败时不影响整体流程
                ast_has_dangerous = False
                graph_density = 0.0
                ast_apis = []

        # 合并 API 列表（去重）
        merged_apis_set = set(apis_from_engine) | set(ast_apis)
        merged_apis = sorted(list(merged_apis_set))
        api_count = len(merged_apis)

        feat_payload = {
            "has_flow": has_flow,                       # 来自 Joern 数据流分析
            "complexity": complexity,                   # 复杂度
            "apis": merged_apis,                        # 综合静态分析 & AST 提取的危险 API
            "ast_has_dangerous": ast_has_dangerous,     # AST 是否检测到危险函数
            "graph_density": float(graph_density),      # Tree-sitter AST 简单图密度
            "api_count": api_count                      # 危险 API 数量
        }

        processed.append({
            "task_name": original_name,
            "source_type": s_type,
            "feature_json": json.dumps(feat_payload)
        })

    return processed


def save_chunk_to_db(records):
    """
    将一批静态分析结果写入 StaticAnalysisCache 表。
    """
    if not records:
        return

    sess = SessionLocal()
    try:
        for r in records:
            cache_obj = StaticAnalysisCache(
                task_name=r["task_name"],
                source_type=r["source_type"],
                feature_json=r["feature_json"]
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
    split_name: str = typer.Option(..., help="Dataset prefix (e.g., 'diversevul_train')"),
    limit: int = typer.Option(-1, help="Limit number of tasks to analyze (default: all)"),
):
    """
    对指定 split 前缀的 Vulnerability 记录做离线静态分析，并写入 StaticAnalysisCache。

    示例：
        python scripts/offline_static_analysis.py analyze-split \\
            --split-name diversevul_train \\
            --limit 20000
    """
    # 确保表结构存在
    Base.metadata.create_all(bind=engine)

    # 1. 查询已有缓存的 task_name 列表（使用 get_db_session，避免 session 生命周期问题）
    with get_db_session() as sess:
        logger.info(f"Scanning existing StaticAnalysisCache for split: {split_name}")
        cached_names = [
            r[0]
            for r in sess.query(StaticAnalysisCache.task_name)
            .filter(StaticAnalysisCache.task_name.like(f"{split_name}%"))
            .all()
        ]
        cached_set = set(cached_names)
        logger.info(f"Cached Records Found: {len(cached_set)}")

        # 2. 获取该 split 下所有待分析任务
        query = (
            sess.query(Vulnerability.name, Vulnerability.code)
            .filter(Vulnerability.name.like(f"{split_name}%"))
        )

        todo_list = []
        total_scanned = 0

        logger.info("Scanning for uncached tasks...")
        # 使用 yield_per 避免一次性加载过多行
        for row in query.yield_per(1000):
            total_scanned += 1
            if row.name not in cached_set:
                if row.code:
                    todo_list.append({"name": row.name, "code": row.code})

                # Limit 控制逻辑
                if limit > 0 and len(todo_list) >= limit:
                    logger.info(f"🛑 Reached limit of {limit} pending tasks. Stopping scan.")
                    break

    count_todo = len(todo_list)
    logger.info(f"Total Scanned Tasks : {total_scanned}")
    logger.info(f"Pending Analysis    : {count_todo}")

    if count_todo == 0:
        logger.info("✅ No new tasks to analyze.")
        return

    # 3. 配置多进程池
    BATCH_SIZE = settings.STATIC_ANALYSIS_BATCH_SIZE
    # 给系统和其他服务留一点 CPU
    MAX_WORKERS = max(1, (os.cpu_count() or 4) - 2)

    logger.info(f"Launching Pool: {MAX_WORKERS} workers, Batch Size: {BATCH_SIZE}")

    batches = [todo_list[i:i + BATCH_SIZE] for i in range(0, count_todo, BATCH_SIZE)]

    # 4. 多进程执行静态分析 + 写入 DB
    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_batch = {pool.submit(analyze_chunk_worker, b): b for b in batches}

        with tqdm(total=count_todo, unit="func", desc="Analyzing") as pbar:
            for future in as_completed(future_to_batch):
                batch = future_to_batch[future]
                try:
                    result_records = future.result()
                    save_chunk_to_db(result_records)
                    pbar.update(len(batch))
                except Exception as e:
                    logger.error(f"Chunk processing failed: {e}")
                    pbar.update(len(batch))

    logger.info("🎉 Offline Analysis Complete.")


if __name__ == "__main__":
    app()
