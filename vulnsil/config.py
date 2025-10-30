import os

# 项目根目录
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 数据库配置 (借鉴 VulnSage)
DB_NAME = "vulnsil_analysis.db"
DB_PATH = os.path.join(BASE_DIR, "results", DB_NAME)
DATABASE_URI = f"sqlite:///{DB_PATH}"

# vLLM (OpenAI API 兼容) 配置
# 我们连接到步骤0中启动的本地服务器
VLLM_API_BASE = "http://localhost:8000/v1"
VLLM_API_KEY = "not-needed-for-local" # vLLM 本地服务不需要 key
# VLLM 加载的模型名称，用于 API 请求
# 这通常是模型路径，或者您在启动时指定的别名
VLLM_MODEL_NAME = "/home/daiwenju/CodeLlama-7b-Instruct"

# VulnSIL 流程控制参数
# VAPA 迭代优化的最大次数
MAX_VAPA_ITERATIONS = 3
# SIL 验证器接受的最低置信度阈值
SIL_CONFIDENCE_THRESHOLD = 0.8  # 80%
# SIL 推理器（T&V）接受的最低置信度阈值
REASONING_CONFIDENCE_THRESHOLD = 0.9 # 90%