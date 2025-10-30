# vulnsil/utils/data_loader.py

import json
from sqlalchemy.orm import Session
from .. import config
from ..models import Vulnerability  # 导入 *更新后* 的 Vulnerability 模型
from ..database import get_db_session


def load_data_from_jsonl(db: Session, jsonl_path: str):

    print(f"Starting data load from {jsonl_path}...")

    existing_names = set(name[0] for name in db.query(Vulnerability.name).all())
    print(f"Found {len(existing_names)} existing entries. Will skip duplicates.")

    count_added = 0
    count_skipped = 0

    try:
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    print(f"Warning: Skipping malformed JSON line: {line[:50]}...")
                    continue

                func_name = data.get('name')
                code = data.get('func')

                if not func_name or not code:
                    print("Warning: Skipping entry with missing 'name' or 'func'.")
                    continue

                if func_name in existing_names:
                    count_skipped += 1
                    continue

                # 创建新的 Vulnerability 数据库模型实例
                db_entry = Vulnerability(
                    name=func_name,
                    code=code,
                    ground_truth_label=str(data.get('label', '0')),
                    ground_truth_cwe=str(data.get('cwe_id', 'None')),

                    # -------------------------------------------------
                    # [新增] 加载丰富的语义标签
                    ground_truth_source=data.get('source'),
                    ground_truth_sink=data.get('sink'),
                    ground_truth_reason=data.get('reason')
                    # -------------------------------------------------
                )

                db.add(db_entry)
                existing_names.add(func_name)
                count_added += 1

                if count_added % 1000 == 0:
                    db.commit()
                    print(f"Committed {count_added} new entries...")

        db.commit()
        print("Data loading finished.")
        print(f"Added: {count_added} new vulnerabilities.")
        print(f"Skipped: {count_skipped} duplicates.")

    except FileNotFoundError:
        print(f"Error: Dataset file not found at {jsonl_path}")
    except Exception as e:
        print(f"An error occurred during data loading: {e}")
        db.rollback()