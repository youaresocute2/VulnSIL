# vulnsil/core/retrieval/vector_db_manager.py
import numpy as np
import torch
import logging
import threading
import queue
import os

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
    Hybrid Resource Pool for Embedding (GPU + CPU).
    """

    def __init__(self):
        # [关键] 限制 PyTorch 算子级并行，防止干扰 Pipeline 主线程
        torch.set_num_threads(1)

        self.model_path = settings.EMBEDDING_MODEL_PATH
        self.worker_pool = queue.Queue()

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        except Exception as e:
            log.critical(f"Tokenizer load fail: {e}")
            raise

        loaded_count = 0

        # 解析配置中的设备列表
        target_devices = []
        if settings.EMBEDDING_DEVICE:
            target_devices = [d.strip() for d in settings.EMBEDDING_DEVICE.split(',')]

        # 默认兜底逻辑
        if not target_devices:
            target_devices = ['cuda:0', 'cpu'] if HAS_GPU else ['cpu']

        log.info(f"🔧 Embedding Device Config: {target_devices}")

        for d_str in target_devices:
            if d_str == 'cpu':
                # [修改] CPU Worker 数量设为 4。
                # 配合 Pipeline 的 16 线程，避免 CPU 过载。
                # 1个 GPU Worker (处理约 60% 流量) + 4个 CPU Worker (处理约 40% 流量)
                cpu_workers = 6
                log.info(f"🚀 Spawning {cpu_workers} CPU workers for Embedding...")
                for _ in range(cpu_workers):
                    if self._load_worker('cpu'):
                        loaded_count += 1
            else:
                # GPU 设备 (cuda:0)
                if d_str.startswith("cuda") and not HAS_GPU:
                    log.warning(f"⚠️ Configured {d_str} but no GPU detected. Skipping.")
                    continue
                # GPU Worker 通常 1 个就够了，吞吐量极大
                if self._load_worker(d_str):
                    loaded_count += 1

        if loaded_count == 0:
            log.warning("⚠️ No workers loaded! Falling back to single CPU worker.")
            self._load_worker("cpu")
            loaded_count = 1

        self.active_ids = [i for i in range(loaded_count)]
        log.info(f"🚀 Embedding Pool Ready. Total Workers: {loaded_count}")

    def _load_worker(self, device_str):
        try:
            dev = torch.device(device_str)
            model = AutoModel.from_pretrained(self.model_path).to(dev)
            model.eval()

            if dev.type == 'cuda':
                model.half()  # GPU FP16
            else:
                # CPU FP32 (部分 CPU 不支持半精度)
                pass

            self.worker_pool.put((model, dev))
            return True
        except Exception as e:
            log.error(f"❌ Failed to load model on {device_str}: {e}")
            return False

    def get_active_devices(self):
        return self.active_ids

    @torch.no_grad()
    def encode(self, text: str) -> np.ndarray:
        if not text or not text.strip():
            return np.zeros(768, dtype='float32')

        text = text[:5000]

        # 从资源池获取模型 (阻塞等待)
        model, device = self.worker_pool.get()

        try:
            inputs = self.tokenizer(text, return_tensors='pt', max_length=512, truncation=True, padding=True)
            inputs = {k: v.to(device) for k, v in inputs.items()}

            outputs = model(**inputs)
            embedding = outputs.last_hidden_state[:, 0, :]
            embedding = embedding.float().cpu().numpy()[0].astype('float32')

            norm = np.linalg.norm(embedding)
            if norm > 1e-10: embedding /= norm
            return embedding

        except Exception as e:
            log.error(f"Encoding Error on {device}: {e}")
            return np.zeros(768, dtype='float32')

        finally:
            # 归还模型
            self.worker_pool.put((model, device))