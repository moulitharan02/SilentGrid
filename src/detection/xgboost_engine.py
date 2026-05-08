"""
ONNX Inference Engine for XGBoost and RandomForest models.
Falls back to the joblib RandomForest in models/classifier.pkl when ONNX
artifacts are missing or onnxruntime is not installed.
"""

from __future__ import annotations

import os
from typing import Any, Optional, Tuple

import joblib
import numpy as np

try:
    import onnxruntime as rt
except ImportError:  # pragma: no cover - optional dependency path
    rt = None  # type: ignore[misc, assignment]

from src.config.config import (
    XGBOOST_MODEL_PATH,
    RF_ONNX_PATH,
    MODEL_DIR,
    CLASSIFIER_MODEL_PATH,
)
from src.utils.logger import get_logger

log = get_logger(__name__)


class ONNXEngine:
    def __init__(self) -> None:
        self.xgb_session = None
        self.rf_session = None
        self.label_map: dict = {}
        self.reverse_label_map: dict = {}
        self._sklearn_clf: Any = None
        self._load_models()

    def _load_models(self) -> None:
        """Load ONNX sessions and label mapping, or sklearn classifier fallback."""
        if rt is not None:
            if os.path.isfile(XGBOOST_MODEL_PATH):
                try:
                    self.xgb_session = rt.InferenceSession(
                        XGBOOST_MODEL_PATH, providers=["CPUExecutionProvider"]
                    )
                    self.xgb_input_name = self.xgb_session.get_inputs()[0].name
                    log.info("XGBoost ONNX model loaded.")
                except Exception as e:
                    log.error("Failed to load XGBoost ONNX model: %s", e)

            if os.path.isfile(RF_ONNX_PATH):
                try:
                    self.rf_session = rt.InferenceSession(
                        RF_ONNX_PATH, providers=["CPUExecutionProvider"]
                    )
                    self.rf_input_name = self.rf_session.get_inputs()[0].name
                    log.info("RandomForest ONNX model loaded.")
                except Exception as e:
                    log.error("Failed to load RandomForest ONNX model: %s", e)
        else:
            log.warning(
                "onnxruntime not installed — using sklearn classifier only if available."
            )

        label_map_path = os.path.join(MODEL_DIR, "label_map.pkl")
        if os.path.isfile(label_map_path):
            try:
                self.label_map = joblib.load(label_map_path)
                self.reverse_label_map = {v: k for k, v in self.label_map.items()}
            except Exception as e:
                log.error("Failed to load label map: %s", e)

        onnx_ready = (
            self.reverse_label_map
            and (self.xgb_session is not None or self.rf_session is not None)
        )
        if not onnx_ready and os.path.isfile(CLASSIFIER_MODEL_PATH):
            try:
                self._sklearn_clf = joblib.load(CLASSIFIER_MODEL_PATH)
                log.info(
                    "Using joblib classifier fallback from %s", CLASSIFIER_MODEL_PATH
                )
            except Exception as e:
                log.error("Failed to load sklearn classifier: %s", e)

    def _predict_sklearn(self, features: np.ndarray) -> Optional[Tuple[str, float]]:
        if self._sklearn_clf is None:
            return None
        try:
            vec2d = features.reshape(1, -1).astype(np.float64)
            probs = self._sklearn_clf.predict_proba(vec2d)[0]
            idx = int(np.argmax(probs))
            label = str(self._sklearn_clf.classes_[idx])
            return label, float(probs[idx])
        except Exception as e:
            log.error("Sklearn inference error: %s", e)
            return None

    def predict_xgb(self, features: np.ndarray) -> Optional[Tuple[str, float]]:
        """Run XGBoost prediction, or sklearn fallback when ONNX is unavailable."""
        if self.xgb_session and self.reverse_label_map:
            try:
                pred_onx = self.xgb_session.run(
                    None, {self.xgb_input_name: features.astype(np.float32)}
                )
                label_idx = pred_onx[0][0]
                label_str = self.reverse_label_map.get(label_idx, "UNKNOWN")
                prob = 1.0
                if len(pred_onx) > 1 and isinstance(pred_onx[1], list) and len(pred_onx[1]) > 0:
                    prob_dict = pred_onx[1][0]
                    if label_idx in prob_dict:
                        prob = float(prob_dict[label_idx])
                return label_str, prob
            except Exception as e:
                log.error("XGBoost inference error: %s", e)

        return self._predict_sklearn(features)

    def predict_rf(self, features: np.ndarray) -> Optional[Tuple[str, float]]:
        """RandomForest ONNX path only (sklearn RF is consumed via predict_xgb fallback)."""
        if self.rf_session and self.reverse_label_map:
            try:
                pred_onx = self.rf_session.run(
                    None, {self.rf_input_name: features.astype(np.float32)}
                )
                label_idx = pred_onx[0][0]
                label_str = self.reverse_label_map.get(label_idx, "UNKNOWN")
                prob = 1.0
                if len(pred_onx) > 1 and isinstance(pred_onx[1], list) and len(pred_onx[1]) > 0:
                    prob_dict = pred_onx[1][0]
                    if label_idx in prob_dict:
                        prob = float(prob_dict[label_idx])
                return label_str, prob
            except Exception as e:
                log.error("RandomForest inference error: %s", e)
        return None
