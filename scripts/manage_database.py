# scripts/manage_database.py
import sys
import os
import json
import argparse
import logging
from tqdm import tqdm

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vulnsil.database import get_db_session, engine, Base
# 引入所有模型以确保 SQLAlchemy 能正确识别表关系
from vulnsil.models import Vulnerability, StaticAnalysisCache, KnowledgeBase, Prediction
from config import settings, init_runtime

# 初始化日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s'
)
log = logging.getLogger("ManageDB")


def init_db():
    """初始化数据库表结构"""
    Base.metadata.create_all(bind=engine)
    log.info(f"Checking Schema at: {settings.DATABASE_URI}")


def perform_cleanup(db, mode):
    """
    根据不同模式执行数据清理
    """
    # 模式 0: 物理重建 (危险操作，也会清空 RAG)
    if mode == 'recreate':
        log.warning("🔥 RECREATE MODE: Deleting DB file (ALL DATA INCLUDING RAG WILL BE LOST)...")
        if "sqlite" in settings.DATABASE_URI:
            f = settings.DATABASE_URI.replace("sqlite:///", "")
            try:
                if os.path.exists(f): os.remove(f)
                if os.path.exists(f + "-wal"): os.remove(f + "-wal")
                if os.path.exists(f + "-shm"): os.remove(f + "-shm")
            except Exception as e:
                log.error(f"Remove failed: {e}")
        init_db()
        return

    # 事务操作
    try:
        # 模式 1: 仅清空分析结果 (--clear_results)
        # 行为: 删除推理结果，重置任务状态。
        # 保留: 漏洞任务(Vulnerability), 静态分析(StaticAnalysisCache), RAG(KnowledgeBase)
        if mode == 'results_only':
            log.info("Action: Clearing Analysis Results...")
            deleted_res = db.query(Prediction).delete()

            log.info("Action: Resetting Vulnerability status to 'Pending'...")
            updated_vulns = db.query(Vulnerability).update(
                {Vulnerability.status: "Pending"},
                synchronize_session=False
            )
            log.info(f"Deleted {deleted_res} results. Reset {updated_vulns} tasks.")
            db.commit()
            return

        # 模式 2: 清空结果 + 静态缓存 (--clear_vulns)
        # 行为: 删除结果 + 静态缓存，重置任务状态。
        # 保留: 漏洞任务(Vulnerability), RAG(KnowledgeBase)
        if mode == 'results_and_static':
            log.info("Action: Clearing Analysis Results...")
            deleted_res = db.query(Prediction).delete()

            log.info("Action: Clearing Static Cache...")
            deleted_cache = db.query(StaticAnalysisCache).delete()

            log.info("Action: Resetting Vulnerability status to 'Pending'...")
            updated_vulns = db.query(Vulnerability).update(
                {Vulnerability.status: "Pending"},
                synchronize_session=False
            )
            log.info(f"Deleted {deleted_res} results, {deleted_cache} cache. Reset {updated_vulns} tasks.")
            db.commit()
            return

        # 模式 3: 清空结果 + 静态缓存 + 任务 (--clear_all)
        # 行为: 删除结果 + 静态缓存 + 任务。
        # 保留: RAG(KnowledgeBase)
        if mode == 'all_tasks':
            log.info("Action: Clearing Analysis Results...")
            deleted_res = db.query(Prediction).delete()

            log.info("Action: Clearing Static Cache...")
            deleted_cache = db.query(StaticAnalysisCache).delete()

            log.info("Action: Clearing Vulnerabilities...")
            deleted_vulns = db.query(Vulnerability).delete()

            log.info(f"Deleted {deleted_res} results, {deleted_cache} cache, {deleted_vulns} tasks.")
            db.commit()
            return

        # 模式 4: 清空所有，包括 RAG (--clear_all_including_rag)
        if mode == 'all_including_rag':
            log.info("Action: Clearing Analysis Results...")
            deleted_res = db.query(Prediction).delete()

            log.info("Action: Clearing Static Cache...")
            deleted_cache = db.query(StaticAnalysisCache).delete()

            log.info("Action: Clearing Vulnerabilities...")
            deleted_vulns = db.query(Vulnerability).delete()

            log.info("Action: Clearing Knowledge Base...")
            deleted_kb = db.query(KnowledgeBase).delete()

            log.info(f"Deleted {deleted_res} results, {deleted_cache} cache, {deleted_vulns} tasks, {deleted_kb} KB entries.")
            db.commit()
            return

    except Exception as e:
        db.rollback()
        log.error(f"Cleanup Failed: {e}")


def import_jsonl(db, file_path: str, split_name: str):
    """
    从 JSONL 文件导入 Vulnerability 数据
    """
    records = parse_json_file(file_path)
    buffer = []
    batch_size = 500

    for rec in tqdm(records, desc="Importing"):
        commit_id = rec.get('commit_id', None)
        name = f"{split_name}_{commit_id}_{rec.get('idx', 'unk')}"

        obj = Vulnerability(
            name=name,
            commit_id=commit_id,
            code=rec.get('func', ''),
            ground_truth_label=rec.get('target', 0),
            cwe_id=rec.get('cwe', 'N/A')
        )
        buffer.append(obj)

        if len(buffer) >= batch_size:
            db.bulk_save_objects(buffer)
            db.commit()
            buffer = []

    if buffer:
        db.bulk_save_objects(buffer)
        db.commit()

    log.info(f"Import {split_name} successfully completed.")


def parse_json_file(filepath: str):
    """解析 JSONL 文件"""
    records = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnSIL Database Management Tool")

    # 清理参数组 (互斥)
    cleanup_group = parser.add_mutually_exclusive_group()
    cleanup_group.add_argument("--clear_results", action="store_true",
                               help="[Mode 1] Clear LLM analysis results only. Keep tasks, static cache, and RAG.")
    cleanup_group.add_argument("--clear_vulns", action="store_true",
                               help="[Mode 2] Clear results AND static analysis cache. Keep tasks and RAG.")
    cleanup_group.add_argument("--clear_all", action="store_true",
                               help="[Mode 3] Clear results, static cache, AND tasks. Keep RAG only.")
    cleanup_group.add_argument("--recreate", action="store_true",
                               help="[Mode 0] DELETE DB FILE and re-init. WARNING: Clears EVERYTHING including RAG.")

    # 导入参数
    parser.add_argument("--import_file", type=str, help="Path to JSONL file to import")
    parser.add_argument("--split_name", type=str,
                        help="Dataset split prefix (Required for import), e.g. diversevul_test")

    args = parser.parse_args()

    init_runtime()

    # 1. 处理 Recreate
    if args.recreate:
        perform_cleanup(None, 'recreate')
    else:
        # 确保表存在
        init_db()

        with get_db_session() as db:
            # 2. 处理三种清理模式
            if args.clear_results:
                perform_cleanup(db, 'results_only')
            elif args.clear_vulns:
                perform_cleanup(db, 'results_and_static')
            elif args.clear_all:
                perform_cleanup(db, 'all_tasks')

            # 3. 处理导入
            if args.import_file:
                if not args.split_name:
                    log.error("--split_name is required when importing!")
                    exit(1)
                import_jsonl(db, args.import_file, args.split_name)