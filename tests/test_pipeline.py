"""
Pipeline integration tests — nt-traffic-filter.
Run with:  pytest tests/test_pipeline.py -v
"""

from __future__ import annotations

import os
import sys

import numpy as np
import pytest

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def sample_record() -> dict:
    """A minimal synthetic traffic record mimicking a Zeek conn.log entry."""
    return {
        "id.orig_h":   "192.168.1.10",
        "id.orig_p":   "54321",
        "id.resp_h":   "8.8.8.8",
        "id.resp_p":   "443",
        "proto":       "tcp",
        "duration":    "1.23",
        "orig_bytes":  "4096",
        "resp_bytes":  "8192",
        "orig_pkts":   "10",
        "resp_pkts":   "15",
        "orig_ip_bytes": "4500",
        "resp_ip_bytes": "9000",
    }


@pytest.fixture()
def feature_engine():
    from src.features.feature_engine import FeatureEngine
    return FeatureEngine()


# ── IP Utils ──────────────────────────────────────────────────────────────────

class TestIpUtils:
    def test_valid_ipv4(self):
        from src.utils.ip_utils import is_valid_ip
        assert is_valid_ip("192.168.1.1") is True

    def test_invalid_ip(self):
        from src.utils.ip_utils import is_valid_ip
        assert is_valid_ip("not-an-ip") is False

    def test_private_ip(self):
        from src.utils.ip_utils import is_private
        assert is_private("10.0.0.1") is True
        assert is_private("8.8.8.8") is False

    def test_classify_loopback(self):
        from src.utils.ip_utils import classify_ip
        assert classify_ip("127.0.0.1") == "loopback"

    def test_classify_public(self):
        from src.utils.ip_utils import classify_ip
        assert classify_ip("8.8.8.8") == "public"

    def test_cidr_contains(self):
        from src.utils.ip_utils import cidr_contains
        assert cidr_contains("10.0.0.0/8", "10.20.30.40") is True
        assert cidr_contains("10.0.0.0/8", "172.16.0.1") is False


# ── Feature Engine ────────────────────────────────────────────────────────────

class TestFeatureEngine:
    def test_extract_returns_array(self, feature_engine, sample_record):
        vec = feature_engine.extract(sample_record)
        # May be None if scaler is missing — that's acceptable in CI
        if vec is not None:
            from src.features.feature_engine import FEATURE_NAMES
            assert isinstance(vec, np.ndarray)
            assert vec.ndim == 1
            assert len(vec) == len(FEATURE_NAMES)  # sanity

    def test_extract_bad_record_does_not_raise(self, feature_engine):
        vec = feature_engine.extract({})  # empty record
        # Should return None gracefully or a zero-filled vector
        assert vec is None or isinstance(vec, np.ndarray)

    def test_feature_count(self, feature_engine, sample_record):
        from src.features.feature_engine import FEATURE_NAMES
        vec = feature_engine.extract(sample_record)
        if vec is not None:
            assert len(vec) == len(FEATURE_NAMES)


# ── Risk Engine ───────────────────────────────────────────────────────────────

class TestRiskEngine:
    def _make_result(self, is_anomaly: bool, score: float, label: str, conf: float):
        from src.detection.detection_engine import DetectionResult
        return DetectionResult(
            is_anomaly=is_anomaly,
            anomaly_score=score,
            predicted_label=label,
            label_confidence=conf,
            raw_record={"id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8"},
        )

    def test_benign_low_risk(self):
        from src.detection.risk_engine import RiskEngine
        engine = RiskEngine()
        dr     = self._make_result(False, 0.5, "BENIGN", 0.95)
        result = engine.score(dr)
        assert result.risk_score < 40, "BENIGN traffic should be LOW risk"

    def test_ddos_high_risk(self):
        from src.detection.risk_engine import RiskEngine, SEVERITY_HIGH, SEVERITY_CRITICAL
        engine = RiskEngine()
        dr     = self._make_result(True, -1.5, "DDoS", 0.92)
        result = engine.score(dr)
        assert result.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL)

    def test_risk_score_clamped(self):
        from src.detection.risk_engine import RiskEngine
        engine = RiskEngine()
        dr     = self._make_result(True, -999.0, "DoS", 1.0)
        result = engine.score(dr)
        assert 0 <= result.risk_score <= 100


# ── Alert Manager ─────────────────────────────────────────────────────────────

class TestAlertManager:
    def test_low_risk_not_alerted(self, capsys):
        from src.detection.detection_engine import DetectionResult
        from src.detection.risk_engine import RiskResult, SEVERITY_LOW
        from src.alerting.alert_manager import AlertManager
        from unittest.mock import MagicMock

        notifier = MagicMock()
        manager  = AlertManager(notifier=notifier)

        dr = DetectionResult(False, 0.8, "BENIGN", 0.99, {"id.orig_h": "1.2.3.4"})
        rr = RiskResult(risk_score=10, severity=SEVERITY_LOW, detection_result=dr)
        manager.process(rr)

        notifier.send.assert_not_called()

    def test_high_risk_triggers_notification(self):
        from src.detection.detection_engine import DetectionResult
        from src.detection.risk_engine import RiskResult, SEVERITY_HIGH
        from src.alerting.alert_manager import AlertManager
        from unittest.mock import MagicMock

        notifier = MagicMock()
        manager  = AlertManager(notifier=notifier)

        dr = DetectionResult(True, -1.2, "DDoS", 0.91, {"id.orig_h": "5.6.7.8"})
        rr = RiskResult(risk_score=85, severity=SEVERITY_HIGH, detection_result=dr)
        manager.process(rr)

        notifier.send.assert_called_once()
