# scripts/setup_database.py

import sys
import os
from sqlalchemy.orm import Session
from sqlalchemy import text
import argparse


from vulnsil import config
from vulnsil.database import init_db, get_db_session, engine # 导入 engine
from vulnsil.utils.data_loader import load_data_from_jsonl
from vulnsil.models import Vulnerability, VulnSILAnalysis, Base # 导入 VulnSILAnalysis 和 Base

def clear_analysis_table(db: Session):
    """清空 vulnsil_analysis 表"""
    try:
        logging.info("正在清空 'vulnsil_analysis' 表...")
        # 更安全的方式是使用 ORM 删除，但对于 SQLite，DELETE 效果相同且更快
        num_deleted = db.query(VulnSILAnalysis).delete()
        db.commit()
        logging.info(f"已从 'vulnsil_analysis' 表中删除 {num_deleted} 条记录。")
    except Exception as e:
        logging.error(f"清空 'vulnsil_analysis' 表时出错: {e}")
        db.rollback()
        raise # 重新抛出异常，让调用者知道失败了

def main(args): # 接收解析后的参数
    """
    主执行函数：初始化数据库并根据参数加载数据。
    """
    try:
        init_db() # 确保数据库和表存在
        logging.info(f"数据库初始化成功: {config.DATABASE_URI}")
    except Exception as e:
        logging.error(f"初始化数据库时出错: {e}")
        return

    db_gen = get_db_session()
    db: Session = next(db_gen)

    try:
        # --- [新增] 清空分析结果表 ---
        if args.clear_analysis:
            clear_analysis_table(db)
        # ---------------------------

        # --- [修改] 根据 --split 参数确定加载哪个文件 ---
        if args.split == "all":
            # 保持原始行为，加载主文件 (现在假设是筛选过的 focused 文件)
            jsonl_file_path = os.path.join(config.BASE_DIR, 'data', 'vcldata_focused.jsonl')
            logging.info("加载模式: all (使用主数据集文件)")
        elif args.split in ["train", "validation", "test"]:
            # 加载特定分割的文件，假设它们在 data/splits/ 目录下
            split_dir = os.path.join(config.BASE_DIR, 'data', 'splits')
            jsonl_file_path = os.path.join(split_dir, f"{args.split}.jsonl")
            logging.info(f"加载模式: split '{args.split}'")
        else:
            logging.error(f"无效的 --split 参数: '{args.split}'. 必须是 'all', 'train', 'validation', 或 'test'。")
            return

        if not os.path.exists(jsonl_file_path):
            logging.error(f"错误: 数据文件未找到 '{jsonl_file_path}'")
            logging.error("请先运行 'scripts/split_data.py' (如果需要分割) 或确保主数据文件存在。")
            return
        # ---------------------------------------------

        # --- [修改] 加载数据时清除 vulnerabilities 表 ---
        # 为了确保每次加载 split 时数据库只包含该 split 的数据
        if args.split != "all":
            try:
                logging.info(f"正在清空 'vulnerabilities' 表以加载 '{args.split}' 数据...")
                num_deleted_vulns = db.query(Vulnerability).delete()
                db.commit()
                logging.info(f"已从 'vulnerabilities' 表中删除 {num_deleted_vulns} 条记录。")
            except Exception as e:
                logging.error(f"清空 'vulnerabilities' 表时出错: {e}")
                db.rollback()
                raise

        # 执行数据加载
        load_data_from_jsonl(db, jsonl_file_path)

        count = db.query(Vulnerability).count()
        logging.info(f"验证: 'vulnerabilities' 表现在包含 {count} 条记录。")

    except Exception as e:
        logging.error(f"数据加载过程中发生错误: {e}")
        db.rollback()
        import traceback
        traceback.print_exc()
    finally:
        logging.info("关闭数据库会话。")
        db.close()

if __name__ == "__main__":
    # --- [新增] 添加命令行参数解析 ---
    parser = argparse.ArgumentParser(description="初始化数据库并加载指定的数据分割。")
    parser.add_argument(
        "--split",
        type=str,
        default="valid", # 默认加载验证集，方便调优
        choices=["all", "train", "valid", "test"],
        help="要加载的数据分割 ('all', 'train', 'valid', 'test')。默认为 'valid'。"
    )
    parser.add_argument(
        "--clear_analysis",
        action='store_true', # 设为 flag，存在即为 True
        help="如果设置，将在加载数据前清空 'vulnsil_analysis' 表。"
    )
    parsed_args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    main(parsed_args) # 将解析后的参数传递给 main 函数
    # -----------------------------------