# scripts/manage_database.py
import sys
import os
import json
import argparse
import logging
from tqdm import tqdm

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vulnsil.database import get_db_session, engine, Base
from vulnsil.models import Vulnerability, AnalysisResultRecord, StaticAnalysisCache, KnowledgeBase
from config import settings

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s')
log = logging.getLogger("ManageDB")


def init_db():
    Base.metadata.create_all(bind=engine)
    log.info(f"Schema checked at: {settings.DATABASE_URI}")


def perform_cleanup(db, mode):
    # Mode Logic Preserved
    if mode == 'recreate':
        log.warning("🔥 RECREATE MODE: Deleting DB file...")
        if "sqlite" in settings.DATABASE_URI:
            f = settings.DATABASE_URI.replace("sqlite:///", "")
            try:
                if os.path.exists(f): os.remove(f)
                if os.path.exists(f + "-wal"): os.remove(f + "-wal")
            except:
                pass
        init_db()
        return

    try:
        if mode == 'results_only':
            log.info("Action: Clearing Analysis Results...")
            db.query(AnalysisResultRecord).delete()
            db.query(Vulnerability).update({Vulnerability.status: "Pending"})

        elif mode == 'results_and_static':
            log.info("Action: Clearing Results & Static Cache...")
            db.query(AnalysisResultRecord).delete()
            db.query(StaticAnalysisCache).delete()
            db.query(Vulnerability).update({Vulnerability.status: "Pending"})

        elif mode == 'all_tasks':
            log.info("Action: Clearing ALL Tasks...")
            db.query(AnalysisResultRecord).delete()
            db.query(StaticAnalysisCache).delete()
            db.query(Vulnerability).delete()

        db.commit()
        log.info("✅ Cleanup completed.")

    except Exception as e:
        db.rollback()
        log.error(f"Cleanup failed: {e}")


def import_jsonl(db, filepath, split_name):
    if not os.path.exists(filepath):
        log.error(f"File missing: {filepath}")
        return

    with open(filepath) as f:
        total_lines = sum(1 for _ in f)

    log.info(f"Importing {split_name} ({total_lines} rows)...")

    buffer = []
    batch_size = 5000

    with open(filepath, 'r') as f:
        for idx, line in enumerate(tqdm(f, total=total_lines, unit="task")):
            if not line.strip(): continue
            try:
                item = json.loads(line)

                # Name Logic
                cid = item.get('commit_id') or "unk"
                unique_name = f"{split_name}_{cid}_{idx}"

                # [Fix] CWE Mapping
                raw_cwe = item.get('cwe') or item.get('cwe_id')
                if isinstance(raw_cwe, list):
                    c_str = raw_cwe[0] if raw_cwe else "N/A"
                else:
                    c_str = str(raw_cwe) if raw_cwe else "N/A"

                vuln = Vulnerability(
                    name=unique_name,
                    commit_id=cid,
                    code=item.get('func') or item.get('code', ""),
                    ground_truth_label=int(item.get('target', 0)),
                    cwe_id=c_str,
                    status="Pending"
                )
                buffer.append(vuln)

                if len(buffer) >= batch_size:
                    db.bulk_save_objects(buffer)
                    db.commit()
                    buffer = []
            except:
                pass

    if buffer:
        db.bulk_save_objects(buffer)
        db.commit()
    log.info(f"Import {split_name} successfully completed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnSIL Database Management")

    cleanup_group = parser.add_mutually_exclusive_group()
    cleanup_group.add_argument("--clear_results", action="store_true")
    cleanup_group.add_argument("--clear_vulns", action="store_true")
    cleanup_group.add_argument("--clear_all", action="store_true")
    cleanup_group.add_argument("--recreate", action="store_true")

    parser.add_argument("--import_file", type=str)
    parser.add_argument("--split_name", type=str)

    args = parser.parse_args()

    if args.recreate:
        perform_cleanup(None, 'recreate')
    else:
        init_db()
        with get_db_session() as db:
            if args.clear_results:
                perform_cleanup(db, 'results_only')
            elif args.clear_vulns:
                perform_cleanup(db, 'results_and_static')
            elif args.clear_all:
                perform_cleanup(db, 'all_tasks')

            if args.import_file and args.split_name:
                import_jsonl(db, args.import_file, args.split_name)