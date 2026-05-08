"""
ONNX Inference Engine for XGBoost and RandomForest models.
Phase 2 upgrade for high-performance detection.
"""

from __future__ import annotations

import os
import joblib
import numpy as np
import onnxruntime as rt
from typing import Optional, Tuple

from src.config.config import XGBOOST_MODEL_PATH, RF_ONNX_PATH, MODEL_DIR
from src.utils.logger import get_logger

log = get_logger(__name__)

class ONNXEngine:
    def __init__(self):
        self.xgb_session = None
        self.rf_session = None
        self.label_map = {}
        self.reverse_label_map = {}
        self._load_models()

    def _load_models(self) -> None:
        """Load ONNX sessions and the label mapping."""
        # Load XGBoost ONNX model
        if os.path.isfile(XGBOOST_MODEL_PATH):
            try:
                self.xgb_session = rt.InferenceSession(XGBOOST_MODEL_PATH, providers=['CPUExecutionProvider'])
                self.xgb_input_name = self.xgb_session.get_inputs()[0].name
                log.info("XGBoost ONNX model loaded.")
            except Exception as e:
                log.error("Failed to load XGBoost ONNX model: %s", e)

        # Load RandomForest ONNX model
        if os.path.isfile(RF_ONNX_PATH):
            try:
                self.rf_session = rt.InferenceSession(RF_ONNX_PATH, providers=['CPUExecutionProvider'])
                self.rf_input_name = self.rf_session.get_inputs()[0].name
                log.info("RandomForest ONNX model loaded.")
            except Exception as e:
                log.error("Failed to load RandomForest ONNX model: %s", e)

        # Load Label Map
        label_map_path = os.path.join(MODEL_DIR, "label_map.pkl")
        if os.path.isfile(label_map_path):
            try:
                self.label_map = joblib.load(label_map_path)
                self.reverse_label_map = {v: k for k, v in self.label_map.items()}
            except Exception as e:
                log.error("Failed to load label map: %s", e)

    def predict_xgb(self, features: np.ndarray) -> Optional[Tuple[str, float]]:
        """Run XGBoost prediction. Returns (label, probability)."""
        if not self.xgb_session or not self.reverse_label_map:
            return None
            
        try:
            # Predict
            pred_onx = self.xgb_session.run(None, {self.xgb_input_name: features.astype(np.float32)})
            
            # Extract label and prob
            label_idx = pred_onx[0][0]
            label_str = self.reverse_label_map.get(label_idx, "UNKNOWN")
            
            # The second output usually contains probabilities, depending on ONNX export
            # If probabilities are unavailable, assume 1.0 confidence for simplicity
            prob = 1.0
            if len(pred_onx) > 1 and isinstance(pred_onx[1], list) and len(pred_onx[1]) > 0:
                prob_dict = pred_onx[1][0]
                if label_idx in prob_dict:
                    prob = float(prob_dict[label_idx])
                    
            return label_str, prob
        except Exception as e:
            log.error("XGBoost inference error: %s", e)
            return None

    def predict_rf(self, features: np.ndarray) -> Optional[Tuple[str, float]]:
        """Run RandomForest prediction. Returns (label, probability)."""
        if not self.rf_session or not self.reverse_label_map:
            return None
            
        try:
            # Predict
            pred_onx = self.rf_session.run(None, {self.rf_input_name: features.astype(np.float32)})
            
            # Extract label and prob
            label_idx = pred_onx[0][0]
            label_str = self.reverse_label_map.get(label_idx, "UNKNOWN")
            
            # The second output contains probabilities for scikit-learn ONNX
            prob = 1.0
            if len(pred_onx) > 1 and isinstance(pred_onx[1], list) and len(pred_onx[1]) > 0:
                prob_dict = pred_onx[1][0]
                if label_idx in prob_dict:
                    prob = float(prob_dict[label_idx])
                    
            return label_str, prob
        except Exception as e:
            log.error("RandomForest inference error: %s", e)
            return None
