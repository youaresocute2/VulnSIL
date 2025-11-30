# vulnsil/database.py
import logging
from contextlib import contextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base
from config import settings

log = logging.getLogger(__name__)

engine_args = {}
if settings.DATABASE_URI.startswith("sqlite"):
    engine_args["connect_args"] = {
        "check_same_thread": False,
        "timeout": 60  # 增加锁等待超时
    }

engine = create_engine(
    settings.DATABASE_URI,
    # [关键修改]: 适配 AutoScaler 的高并发
    # 64个线程 + Buffer -> 推荐总量 > 80
    pool_size=80,        # 常驻连接
    max_overflow=60,     # 突发连接
    pool_recycle=3600,   # 回收防断连
    **engine_args
)

if settings.DATABASE_URI.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL") # 高并发必备
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
ScopedSession = scoped_session(SessionLocal)
Base = declarative_base()

@contextmanager
def get_db_session():
    session = ScopedSession()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        log.error(f"DB Error: {e}")
        raise
    finally:
        session.close()
        ScopedSession.remove()