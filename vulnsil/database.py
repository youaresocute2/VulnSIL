# vulnsil/database.py

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from . import config
from .models import Base  # 导入在 models.py 中定义的 Base

# 1. 创建数据库引擎
# engine 是 SQLAlchemy 的核心接口，它管理连接池和方言
# 我们使用 config.DATABASE_URI (sqlite:///...)
engine = create_engine(
    config.DATABASE_URI,
    # connect_args 是 SQLite 特有的，确保在多线程中（如果需要）表现正常
    connect_args={"check_same_thread": False},
)

# 2. 创建数据库会话工厂
# SessionLocal 是一个会话“类”，我们稍后会实例化它
# autocommit=False 和 autoflush=False 是标准配置，
# 意味着我们需要显式调用 db.commit()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 3. (可选但推荐) 创建一个线程安全的会话代理
# scoped_session 确保在同一线程中总是返回同一个会话实例
db_session = scoped_session(SessionLocal)

def get_db_session():
    """
    提供一个可用的数据库会话。
    在脚本或 Web 应用中，这通常是每个请求/任务的入口。
    """
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

def init_db():
    """
    初始化数据库，创建所有在 models.py 中定义的表。
    这个函数应该由 setup_database.py 脚本调用。
    """
    print("Initializing database...")
    # Base.metadata 包含了所有继承自 Base 的模型类（如 Vulnerability, VulnSILAnalysis）
    # create_all 会检查表是否存在，不存在则创建
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully.")

if __name__ == "__main__":
    # 可以直接运行此文件来创建数据库
    init_db()