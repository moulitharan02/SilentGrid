"""
Detection Engine — Phase 2.
Combines an Isolation Forest anomaly detector with XGBoost and RandomForest
classifiers via ONNX inference, returning a unified DetectionResult.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, Optional

import joblib
import numpy as np

from src.config.config import (
    ANOMALY_MODEL_PATH,
    ANOMALY_THRESHOLD,
)
from src.detection.xgboost_engine import ONNXEngine
from src.utils.logger import get_logger

log = get_logger(__name__)


@dataclasses.dataclass
class DetectionResult:
    is_anomaly: bool
    anomaly_score: float
    predicted_label: str
    label_confidence: float
    raw_record: Dict[str, Any]


class DetectionEngine:
    """
    Combines an Isolation Forest anomaly detector with an ensemble of
    XGBoost and RandomForest classifiers.
    """

    def __init__(self):
        self._anomaly_model = None
        self._onnx_engine = ONNXEngine()
        self._load_models()

    # ── Public API ────────────────────────────────────────────────────────────

    def predict(
        self,
        feature_vector: np.ndarray,
        raw_record: Dict[str, Any],
    ) -> Optional[DetectionResult]:
        """
        Run models on the feature vector.

        Args:
            feature_vector: Scaled 1-D numpy array from FeatureEngine.
            raw_record:     Original traffic dict (passed through for context).

        Returns:
            DetectionResult or None if models are not loaded.
        """
        if self._anomaly_model is None:
            log.warning("Anomaly model not loaded — skipping detection.")
            return None

        vec2d = feature_vector.reshape(1, -1)

        # Anomaly detection (score < threshold → anomaly)
        score      = float(self._anomaly_model.decision_function(vec2d)[0])
        is_anomaly = score < ANOMALY_THRESHOLD

        # Supervised classification (Ensemble via ONNX)
        final_label = "UNKNOWN"
        final_confidence = 0.0

        xgb_res = self._onnx_engine.predict_xgb(vec2d)
        rf_res  = self._onnx_engine.predict_rf(vec2d)

        # Ensemble logic:
        # We prefer XGBoost but fall back to RandomForest.
        # If both predict the same, confidence increases.
        # If they disagree, we take XGBoost if its confidence is > 0.8, else RF.
        # For simplicity, we can do a basic weighted decision.
        labels_scores = {}
        
        if xgb_res:
            l, c = xgb_res
            labels_scores[l] = labels_scores.get(l, 0) + c * 0.6  # XGBoost weight 60%
        
        if rf_res:
            l, c = rf_res
            labels_scores[l] = labels_scores.get(l, 0) + c * 0.4  # RF weight 40%

        if labels_scores:
            final_label = max(labels_scores, key=labels_scores.get)
            final_confidence = labels_scores[final_label]

        log.debug(
            "Detection — anomaly=%s score=%.4f label=%s conf=%.2f",
            is_anomaly, score, final_label, final_confidence,
        )

        return DetectionResult(
            is_anomaly=is_anomaly,
            anomaly_score=score,
            predicted_label=final_label,
            label_confidence=final_confidence,
            raw_record=raw_record,
        )

    # ── Internals ─────────────────────────────────────────────────────────────

    def _load_models(self) -> None:
        try:
            self._anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
            log.info("Loaded anomaly model from %s", ANOMALY_MODEL_PATH)
        except FileNotFoundError:
            log.warning("Anomaly model not found at %s — run training/train.py first.", ANOMALY_MODEL_PATH)
        except Exception as exc:
            log.error("Error loading anomaly model: %s", exc)
