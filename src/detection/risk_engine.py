"""
Risk Engine — Phase 2.
Converts raw DetectionResult signals into a normalised 0-100 risk score
and severity label (LOW / MEDIUM / HIGH / CRITICAL).
"""

from __future__ import annotations

import dataclasses
from typing import Dict

from src.config.config import RISK_HIGH_THRESHOLD, RISK_MED_THRESHOLD
from src.detection.detection_engine import DetectionResult
from src.utils.logger import get_logger

log = get_logger(__name__)

# Severity labels mapped to risk score bands
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"

# Weight contribution of each signal (must sum to 1.0)
_W_ANOMALY     = 0.40  # anomaly score component
_W_LABEL       = 0.35  # classifier label component
_W_CONFIDENCE  = 0.25  # prediction confidence component

# Known attack label → base risk score contribution (0-100)
_LABEL_RISK: Dict[str, int] = {
    "BENIGN":       0,
    "DOS":          80,
    "DDOS":         95,
    "PORTSCAN":     60,
    "BRUTEFORCE":   75,
    "BOTNET":       85,
    "INFILTRATION": 90,
    "XSS":          65,
    "SQLINJECTION": 70,
    "UNKNOWN":      30,
}


@dataclasses.dataclass
class RiskResult:
    risk_score: int          # 0-100
    severity: str            # LOW / MEDIUM / HIGH / CRITICAL
    detection_result: DetectionResult


class RiskEngine:
    """Maps detection signals to a normalised risk score + severity label."""

    def score(self, result: DetectionResult) -> RiskResult:
        """
        Compute the composite risk score.

        Args:
            result: Output from DetectionEngine.predict().

        Returns:
            RiskResult with risk_score [0-100] and severity label.
        """
        anomaly_component = self._anomaly_component(result.anomaly_score, result.is_anomaly)
        label_component   = _LABEL_RISK.get(result.predicted_label.upper(), 30)
        conf_component    = result.label_confidence * 100

        risk = int(
            _W_ANOMALY    * anomaly_component
            + _W_LABEL    * label_component
            + _W_CONFIDENCE * conf_component
        )
        risk = max(0, min(100, risk))  # clamp

        severity = self._severity(risk)
        log.debug(
            "Risk — score=%d severity=%s  (anomaly_c=%.1f label_c=%d conf_c=%.1f)",
            risk, severity, anomaly_component, label_component, conf_component,
        )
        return RiskResult(risk_score=risk, severity=severity, detection_result=result)

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _anomaly_component(score: float, is_anomaly: bool) -> float:
        """
        Transform the raw Isolation Forest decision score [-inf, +inf]
        to a 0-100 value.  Negative scores (anomalies) map to higher risk.
        """
        if not is_anomaly:
            return max(0.0, 10.0 - score * 10)   # small baseline risk
        # score is negative; more negative → higher risk
        return min(100.0, abs(score) * 40)

    @staticmethod
    def _severity(score: int) -> str:
        if score >= 90:
            return SEVERITY_CRITICAL
        if score >= RISK_HIGH_THRESHOLD:
            return SEVERITY_HIGH
        if score >= RISK_MED_THRESHOLD:
            return SEVERITY_MEDIUM
        return SEVERITY_LOW
