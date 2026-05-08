"""
Alert Manager — nt-traffic-filter.
Receives RiskResult objects, decides whether an alert should fire,
deduplicates recent alerts, and dispatches via Notifier.
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from typing import Optional

from src.detection.risk_engine import RiskResult, SEVERITY_HIGH, SEVERITY_CRITICAL
from src.alerting.notifier import Notifier
from src.utils.logger import get_logger, get_alert_logger

log       = get_logger(__name__)
alert_log = get_alert_logger()

# Suppress duplicate alerts for the same (src_ip, label) within this window (seconds)
_DEDUP_WINDOW_SEC = 300
_DEDUP_CACHE_SIZE = 2_000


class AlertManager:
    """
    Decides which RiskResults cross the alerting threshold and dispatches them.
    Deduplicates identical alerts within a rolling time window.
    """

    def __init__(self, notifier: Optional[Notifier] = None):
        self._notifier = notifier or Notifier()
        # OrderedDict used as an LRU-style dedup cache: key → last_fired_ts
        self._seen: OrderedDict[str, float] = OrderedDict()

    # ── Public API ────────────────────────────────────────────────────────────

    def process(self, risk_result: RiskResult) -> None:
        """
        Evaluate the risk result and fire an alert if needed.

        Args:
            risk_result: Output from RiskEngine.score().
        """
        if risk_result.severity not in (SEVERITY_HIGH, SEVERITY_CRITICAL):
            return  # only alert on HIGH / CRITICAL

        record = risk_result.detection_result.raw_record
        key    = self._dedup_key(risk_result)

        if self._is_duplicate(key):
            log.debug("Suppressing duplicate alert: %s", key)
            return

        self._record_seen(key)
        self._fire(risk_result, record)

    # ── Internals ─────────────────────────────────────────────────────────────

    def _fire(self, risk_result: RiskResult, record: dict) -> None:
        src_ip  = record.get("id.orig_h") or record.get("src_ip", "?")
        dst_ip  = record.get("id.resp_h") or record.get("dst_ip", "?")
        label   = risk_result.detection_result.predicted_label
        score   = risk_result.risk_score
        severity = risk_result.severity

        msg = (
            f"[{severity}] Traffic alert — "
            f"src={src_ip}  dst={dst_ip}  "
            f"label={label}  risk={score}/100"
        )
        alert_log.warning(msg)
        log.warning(msg)

        # Dispatch external notifications
        try:
            self._notifier.send(
                title=f"[{severity}] Network Threat Detected",
                body=msg,
                metadata={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "label": label,
                    "risk_score": score,
                    "severity": severity,
                },
            )
        except Exception as exc:
            log.error("Notifier failed: %s", exc)

    @staticmethod
    def _dedup_key(risk_result: RiskResult) -> str:
        record = risk_result.detection_result.raw_record
        src_ip = record.get("id.orig_h") or record.get("src_ip", "")
        label  = risk_result.detection_result.predicted_label
        raw    = f"{src_ip}:{label}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _is_duplicate(self, key: str) -> bool:
        last_seen = self._seen.get(key)
        if last_seen is None:
            return False
        return (time.monotonic() - last_seen) < _DEDUP_WINDOW_SEC

    def _record_seen(self, key: str) -> None:
        if key in self._seen:
            self._seen.move_to_end(key)
        self._seen[key] = time.monotonic()
        # Evict oldest entry if cache is too large
        while len(self._seen) > _DEDUP_CACHE_SIZE:
            self._seen.popitem(last=False)
