# vulnsil/core/retrieval/vector_db_manager.py
import numpy as np
import torch
import logging
import queue
import os

# 尝试检测 GPU 环境
try:
    import pynvml

    pynvml.nvmlInit()
    HAS_GPU = True
except:
    HAS_GPU = False

from transformers import AutoTokenizer, AutoModel
from config import settings

log = logging.getLogger(__name__)


class EmbeddingModel:
    """
    Embedding Model Resource Pool.
    Supports Hybrid (GPU + CPU) deployment strategies for high-throughput encoding.
    """

    def __init__(self):
        # [Optimization] 限制 PyTorch 内部算子并行线程数
        # 防止与 Pipeline 的 ThreadPoolExecutor (8-16 线程) 冲突导致 Context Switching 过高
        torch.set_num_threads(1)

        self.model_path = settings.EMBEDDING_MODEL_PATH
        self.worker_pool = queue.Queue()

        try:
            # Tokenizer 是线程安全的，全局加载一次
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        except Exception as e:
            log.critical(f"Tokenizer load failed at {self.model_path}: {e}")
            raise

        loaded_count = 0

        # 解析配置中的设备列表 "cuda:0,cpu"
        target_devices = []
        if settings.EMBEDDING_DEVICE:
            target_devices = [d.strip() for d in settings.EMBEDDING_DEVICE.split(',')]

        # 兜底默认逻辑
        if not target_devices:
            target_devices = ['cuda:0'] if HAS_GPU else ['cpu']

        log.info(f"🔧 Embedding Setup | Target Devices: {target_devices}")

        # 加载 Worker
        for d_str in target_devices:
            if d_str == 'cpu':
                # CPU 吞吐较弱，为了防止 bottleneck，通常启动多个 CPU Workers
                cpu_worker_count = 4
                log.info(f"🚀 Spawning {cpu_worker_count} CPU workers...")
                for _ in range(cpu_worker_count):
                    if self._load_worker('cpu'):
                        loaded_count += 1
            else:
                # GPU Worker
                if d_str.startswith("cuda") and not HAS_GPU:
                    log.warning(f"⚠️ Device {d_str} requested but NVML says No GPU. Skipping.")
                    continue
                if self._load_worker(d_str):
                    loaded_count += 1

        if loaded_count == 0:
            log.warning("⚠️ No devices loaded! Falling back to single CPU worker safety mode.")
            self._load_worker("cpu")
            loaded_count = 1

        log.info(f"✅ Embedding Pool Ready. Total Workers: {loaded_count}")

    def _load_worker(self, device_str):
        """Helper to load model onto specific device"""
        try:
            dev = torch.device(device_str)
            model = AutoModel.from_pretrained(self.model_path).to(dev)
            model.eval()

            # GPU 半精度优化 (FP16)
            if dev.type == 'cuda':
                model.half()

                # 将模型放入池中 (Model, Device)
            self.worker_pool.put((model, dev))
            return True
        except Exception as e:
            log.error(f"❌ Load failed on {device_str}: {e}")
            return False

    @torch.no_grad()
    def encode(self, text: str) -> np.ndarray:
        """
        Encode text to 768-dim vector.
        Thread-safe wrapper around resource pool.
        """
        if not text or not text.strip():
            # Return zero vector for empty inputs to maintain pipeline stability
            return np.zeros(768, dtype='float32')

        # Limit extreme lengths for Bert
        text = text[:8000]

        # Borrow worker (Block until available)
        model, device = self.worker_pool.get()

        try:
            inputs = self.tokenizer(
                text,
                return_tensors='pt',
                max_length=512,
                truncation=True,
                padding=True
            )
            inputs = {k: v.to(device) for k, v in inputs.items()}

            outputs = model(**inputs)
            # CLS pooling
            embedding = outputs.last_hidden_state[:, 0, :]

            # Move to CPU / NumPy
            embedding_np = embedding.float().cpu().numpy()[0].astype('float32')

            # Normalize (Cosine Similarity Prep)
            norm = np.linalg.norm(embedding_np)
            if norm > 1e-10:
                embedding_np /= norm

            return embedding_np

        except Exception as e:
            log.error(f"Encoding Error on {device}: {e}")
            return np.zeros(768, dtype='float32')

        finally:
            # Return worker
            self.worker_pool.put((model, device))