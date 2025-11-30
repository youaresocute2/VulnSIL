# VulnSIL/config.py
import os
import json
import logging
from pydantic_settings import BaseSettings, SettingsConfigDict
import multiprocessing # 新增导入

PROJECT_ROOT_DIR = os.path.abspath(os.path.dirname(__file__))

# ==============================================================================
# [NEW] 全局特征定义 (必须与 confidence.py 和 run_pipeline.py 严格一致)
# ==============================================================================
ML_FEATURE_NAMES = [
    "llm_native_conf",            # 0
    "static_has_flow",            # 1
    "static_complexity",          # 2
    "static_apis_count",          # 3
    "static_risk_density",        # 4
    "static_graph_density",       # 5 [New AST Metric]
    "source_type",                # 6
    "code_len_log",               # 7
    "is_compressed",              # 8
    "rag_sim_avg",                # 9
    "rag_top1_sim",               # 10
    "rag_var",                    # 11
    "conflict_disagree_weighted", # 12
    "conflict_special",           # 13
    "llm_entropy"                 # 14 [New Uncertainty]
]

class Settings(BaseSettings):
    # --- 基础路径 ---
    DATA_DIR: str = os.path.join(PROJECT_ROOT_DIR, 'data')
    RESULTS_DIR: str = os.path.join(PROJECT_ROOT_DIR, 'results')
    LOG_DIR: str = os.path.join(RESULTS_DIR, 'logs')
    DB_DIR: str = os.path.join(RESULTS_DIR, 'database')

    # Linux下优先使用内存盘(/dev/shm)以极大提升 Joern IO速度
    STATIC_TMP_DIR: str = "/dev/shm/vulnsil_tmp" if os.path.exists("/dev/shm") else os.path.join(PROJECT_ROOT_DIR, "temp_work")

    # RAG资源
    FAISS_INDEX_PATH: str = os.path.join(RESULTS_DIR, 'faiss_index', 'kb.faiss')
    BM25_INDEX_PATH: str = os.path.join(RESULTS_DIR, 'faiss_index', 'kb.bm25')
    RESOURCE_DIR: str = os.path.join(PROJECT_ROOT_DIR, 'vulnsil', 'resources')
    JOERN_SCRIPT_PATH: str = os.path.join(RESOURCE_DIR, 'query.sc')

    # 数据库
    DATABASE_URI: str = f"sqlite:///{os.path.join(DB_DIR, 'vulnsil.db')}"

    # 模型路径
    CONFIDENCE_MODEL_PATH: str = os.path.join(RESULTS_DIR, 'confidence', 'lgb_model.joblib')
    CONFIDENCE_META_PATH: str = os.path.join(RESULTS_DIR, 'confidence', 'model_meta.json')

    # --- LLM 配置 ---
    LLM_API_URL: str = "http://localhost:8000/v1/chat/completions"
    LLM_MODEL_NAME: str = "Llama-3.1-8B-Instruct"
    LLM_MAX_MODEL_LEN: int = 14480
    LLM_MAX_TOKENS: int = 2048
    LLM_TEMPERATURE: float = 0.1
    LLM_REPETITION_PENALTY: float = 1.1
    LLM_TIMEOUT: int = 300

    # --- Embedding / Static Config ---
    EMBEDDING_MODEL_PATH: str = "/home/daiwenju/codebert-base"

    # [核心修改] 指定 GPU 0 和 CPU 混合部署 (逗号分隔)
    EMBEDDING_DEVICE: str = "cpu"

    # Joern 环境
    JOERN_CLI_PATH: str = "/home/daiwenju/joern4.4.3/joern-cli/joern"
    JOERN_PARSE_PATH: str = "/home/daiwenju/joern4.4.3/joern-cli/c2cpg.sh"

    # [优化] Joern JVM
    JOERN_JAVA_OPTS: str = "-Xmx14g -Xms4g"
    JOERN_JAVA_OPTIONS: str = "-Xmx14g -Xms4g"

    # [优化] 超时设置
    STATIC_PARSE_TIMEOUT: int = 900  # 15 min
    STATIC_QUERY_TIMEOUT: int = 1200  # 20 min

    # --- 业务参数 & 并发控制 ---
    MAX_CODE_TOKENS_INPUT: int = 12000
    COMPRESSION_TRIGGER_LEN: int = 12000
    RAG_TOP_K: int = 5
    RETRIEVAL_VECTOR_CANDIDATE_MULTIPLIER: int = 10
    RETRIEVAL_RRF_K: int = 60
    KB_BUILD_CHUNK_SIZE: int = 1000
    KB_BUILD_BATCH_INSERT_SIZE: int = 500
    AGENT_MIN_CONFIDENCE_THRESHOLD: float = 0.3

    # 默认阈值
    CALIBRATION_THRESHOLD: float = 0.5

    # 并发控制
    STATIC_ANALYSIS_CONCURRENCY: int = 6
    STATIC_ANALYSIS_BATCH_SIZE: int = 200
    TORCH_NUM_THREADS: int = 1

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def model_post_init(self, __context):
        # [修改] 仅在主进程打印日志，防止 16 个子进程刷屏
        if multiprocessing.current_process().name == 'MainProcess':
            if os.path.exists(self.CONFIDENCE_META_PATH):
                try:
                    with open(self.CONFIDENCE_META_PATH, 'r') as f:
                        meta = json.load(f)
                        best_th = meta.get("best_threshold")
                        if best_th is not None:
                            self.CALIBRATION_THRESHOLD = float(best_th)
                            print(f"✅ [Config] Loaded Dynamic Threshold: {self.CALIBRATION_THRESHOLD:.4f}")
                except Exception as e:
                    print(f"⚠️ [Config] Failed to load threshold meta: {e}")
            else:
                print(f"ℹ️ [Config] Using Default Threshold: {self.CALIBRATION_THRESHOLD} (No meta file found)")

settings = Settings()

for path in [settings.RESULTS_DIR, settings.LOG_DIR, settings.DB_DIR, settings.STATIC_TMP_DIR]:
    os.makedirs(path, exist_ok=True)