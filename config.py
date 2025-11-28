# --- START OF FILE config.py ---

import os
import json
import logging
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT_DIR = os.path.abspath(os.path.dirname(__file__))


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
    FAISS_IDS_MAP_PATH: str = os.path.join(RESULTS_DIR, 'faiss_index', 'faiss_ids_map.json')
    BM25_INDEX_PATH: str = os.path.join(RESULTS_DIR, 'faiss_index', 'kb.bm25')
    RESOURCE_DIR: str = os.path.join(PROJECT_ROOT_DIR, 'vulnsil', 'resources')
    JOERN_SCRIPT_PATH: str = os.path.join(RESOURCE_DIR, 'query.sc')

    # 数据库
    DATABASE_URI: str = f"sqlite:///{os.path.join(DB_DIR, 'vulnsil.db')}"

    # --- 模型路径 (新增) ---
    # 训练好的LightGBM模型
    CONFIDENCE_MODEL_PATH: str = os.path.join(RESULTS_DIR, 'confidence', 'lgb_model.joblib')
    # PCA模型 (可选)
    CONFIDENCE_PCA_PATH: str = os.path.join(RESULTS_DIR, 'confidence', 'pca_model.joblib')
    # 模型元数据 (阈值、特征名)
    CONFIDENCE_META_PATH: str = os.path.join(RESULTS_DIR, 'confidence', 'model_meta.json')

    # [核心设计] 默认15维特征顺序，必须与训练时保持一致
    DEFAULT_FEATURE_ORDER: list = [
        "llm_confidence", "llm_pred",
        "static_has_flow", "static_complexity", "static_api_count", "static_risk_density",
        "static_source_type",
        "rag_top1_similarity", "rag_mean_similarity", "rag_std_similarity", "rag_positive_ratio", "rag_support_agreement",
        "conflict_disagree",
        "graph_density",
        "code_len_log"
    ]

    # --- LLM 配置 ---
    LLM_API_BASE: str = "http://localhost:8000/v1"  # 根据实际 vLLM 或 API 地址修改
    LLM_API_KEY: str = "EMPTY"
    LLM_MODEL_NAME: str = "Llama-3.1-8B-Instruct"
    LLM_MAX_MODEL_LEN: int = 14480
    LLM_MAX_TOKENS: int = 2048
    LLM_TEMPERATURE: float = 0.1
    LLM_REPETITION_PENALTY: float = 1.1
    LLM_TIMEOUT: int = 300

    # --- Embedding / Static Config ---
    EMBEDDING_MODEL_PATH: str = "/home/daiwenju/codebert-base"

    # 指定 GPU 0 和 CPU 混合部署
    EMBEDDING_DEVICE: str = "cuda:0,cpu"

    # 静态分析路径
    JOERN_CLI_PATH: str = "/home/daiwenju/joern4.0.443/joern-cli/joern"
    C2CPG_PATH: str = "/home/daiwenju/joern4.0.443/joern-cli/c2cpg.sh"
    JOERN_JAVA_OPTS: str = "-Xmx14g -Xms4g"
    JOERN_JAVA_OPTIONS: str = "-Xmx14g -Xms4g"

    # 超时设置
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

    # 默认阈值 (会被 model_meta.json 覆盖)
    CALIBRATION_THRESHOLD: float = 0.5

    # 并发控制
    STATIC_ANALYSIS_CONCURRENCY: int = 6
    STATIC_ANALYSIS_BATCH_SIZE: int = 200
    TORCH_NUM_THREADS: int = 1

    # 特征参数
    TREE_SITTER_GRAPH_METRICS: bool = True
    PCA_N_COMPONENTS: int = 10

    # 评估指标开关
    USE_MCC: bool = True
    USE_AUPRC: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def update_threshold_from_meta(self) -> None:
        if os.path.exists(self.CONFIDENCE_META_PATH):
            try:
                with open(self.CONFIDENCE_META_PATH, 'r') as f:
                    meta = json.load(f)
                    best_th = meta.get("best_threshold")
                    if best_th is not None:
                        self.CALIBRATION_THRESHOLD = float(best_th)
                        print(f"✅ [Config] Loaded Dynamic Threshold: {self.CALIBRATION_THRESHOLD:.4f}")
                        return
            except Exception as e:
                print(f"⚠️ [Config] Failed to load threshold meta: {e}")
        print(f"ℹ️ [Config] Using Default Threshold: {self.CALIBRATION_THRESHOLD} (No meta file found)")


settings = Settings()


def init_runtime():
    """初始化运行时资源（仅在入口调用）"""
    for path in [settings.RESULTS_DIR, settings.LOG_DIR, settings.DB_DIR, settings.STATIC_TMP_DIR]:
        os.makedirs(path, exist_ok=True)

    settings.update_threshold_from_meta()

    logging.getLogger(__name__).info("[Config] Runtime initialized.")