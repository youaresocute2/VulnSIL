import time
import os
import sys
from tqdm import tqdm
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from config import settings
from vulnsil.models import Vulnerability


def monitor_progress(split_name):
    # 使用 readonly 模式或者短连接查询，避免锁表
    engine = create_engine(settings.DATABASE_URI)
    Session = sessionmaker(bind=engine)
    session = Session()

    print("📊 正在连接数据库计算任务总量...")

    # 获取任务总量
    total_tasks = session.query(func.count(Vulnerability.id)) \
        .filter(Vulnerability.name.like(f"{split_name}%")).scalar()

    print(f"🎯 监控对象: {split_name} | 总任务数: {total_tasks}")

    # 使用 tqdm
    pbar = tqdm(total=total_tasks, unit="task", desc="🔥 总进度", ncols=100, dynamic_ncols=True)

    last_count = 0
    try:
        while True:
            # 查询 Success 的数量
            current_completed = session.query(func.count(Vulnerability.id)) \
                .filter(Vulnerability.name.like(f"{split_name}%")) \
                .filter(Vulnerability.status == "Success").scalar()

            delta = current_completed - last_count
            if delta > 0:
                pbar.update(delta)
                last_count = current_completed

            # 刷新间隔 (2秒)，避免把数据库查挂了
            time.sleep(2)

            if current_completed >= total_tasks and total_tasks > 0:
                print("\n✅ 完成！")
                break

    except KeyboardInterrupt:
        pbar.close()
        print("\n🛑 监控退出")
    finally:
        session.close()


if __name__ == "__main__":
    monitor_progress("confidence_train")