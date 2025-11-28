# --- START OF FILE vulnsil/core/confidence.py ---

import joblib
import json
import logging
import os
import numpy as np
from config import settings

logger = logging.getLogger("ConfidenceModel")

class ConfidenceModel:
    """
    置信度校准与预测模块
    职责：加载 LightGBM 和元数据，输入特征向量，输出 calibrated_confidence 和 final_label
    """
    def __init__(self):
        self.model = None
        self.pca = None
        self.meta = {}
        self.threshold = settings.CALIBRATION_THRESHOLD
        self._load()

    def _load(self):
        try:
            # 1. 加载元数据 (阈值)
            if os.path.exists(settings.CONFIDENCE_META_PATH):
                with open(settings.CONFIDENCE_META_PATH, 'r') as f:
                    self.meta = json.load(f)
                    th = self.meta.get("best_threshold")
                    if th:
                        self.threshold = float(th)
                    logger.info(f"[ConfidenceModel] Meta loaded. Threshold: {self.threshold}")
            else:
                logger.warning("[ConfidenceModel] Meta file missing, using default threshold.")

            # 2. 加载 LightGBM
            if os.path.exists(settings.CONFIDENCE_MODEL_PATH):
                self.model = joblib.load(settings.CONFIDENCE_MODEL_PATH)
                logger.info("[ConfidenceModel] LightGBM model loaded.")
            else:
                logger.warning(f"[ConfidenceModel] Model missing at {settings.CONFIDENCE_MODEL_PATH}")

            # 3. 加载 PCA
            if settings.CONFIDENCE_PCA_PATH and os.path.exists(settings.CONFIDENCE_PCA_PATH):
                self.pca = joblib.load(settings.CONFIDENCE_PCA_PATH)
                logger.info("[ConfidenceModel] PCA model loaded.")

        except Exception as e:
            logger.error(f"[ConfidenceModel] Load failed: {e}")

    def get_feature_names(self):
        """获取特征名称顺序 (从 Meta 或 Config)"""
        return self.meta.get("feature_names", settings.DEFAULT_FEATURE_ORDER)

    def predict(self, feature_vector: np.ndarray) -> tuple:
        """
        :param feature_vector: 1D numpy array
        :return: (confidence_float, final_pred_int)
        """
        if self.model is None:
            # 如果没有模型（未训练阶段），返回默认 0.5 中性
            return 0.5, 0

        # Reshape for sklearn/lgb
        X = feature_vector.reshape(1, -1)

        # PCA 变换
        if self.pca:
            try:
                X = self.pca.transform(X)
            except Exception as e:
                logger.error(f"PCA transform error: {e}")

        # 推理
        try:
            if hasattr(self.model, "predict_proba"):
                # Classifier: 取正类概率
                probs = self.model.predict_proba(X)
                calib_conf = float(probs[0][1])
            else:
                # Regressor
                calib_conf = float(self.model.predict(X)[0])
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            calib_conf = 0.5

        # 阈值决策
        final_label = 1 if calib_conf >= self.threshold else 0
        return calib_conf, final_label