"""
Behavior Engine — Phase 3 (future).
Placeholder for per-host / per-session behavioral profiling.
Will track rolling baselines and detect statistical deviations over time.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Tuple

from src.utils.logger import get_logger

log = get_logger(__name__)

# Rolling window length in seconds for per-host statistics
_WINDOW_SEC = 300

# (bytes_sent, bytes_recv, pkt_count, timestamp)
_Sample = Tuple[float, float, float, float]


class BehaviorEngine:
    """
    Maintains per-source-IP rolling traffic windows and computes
    baseline deviation scores.

    Phase 3 — not yet integrated into the main pipeline.
    """

    def __init__(self, window_sec: int = _WINDOW_SEC):
        self._window_sec = window_sec
        # host → deque of _Sample tuples
        self._history: Dict[str, Deque[_Sample]] = defaultdict(
            lambda: deque(maxlen=10_000)
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def update(self, record: Dict[str, Any]) -> Dict[str, float]:
        """
        Add a new traffic record to the host's rolling window and return
        a dict of behavioral metrics for that host.

        Args:
            record: Raw Zeek/Kafka traffic dict.

        Returns:
            Dict with keys: avg_bytes_per_sec, pkt_rate, deviation_score.
        """
        src_ip = record.get("id.orig_h") or record.get("src_ip", "unknown")
        now    = time.monotonic()

        sample: _Sample = (
            float(record.get("orig_bytes") or 0),
            float(record.get("resp_bytes") or 0),
            float(record.get("orig_pkts") or 0),
            now,
        )
        window = self._history[src_ip]
        window.append(sample)

        # Prune samples outside the rolling window
        cutoff = now - self._window_sec
        while window and window[0][3] < cutoff:
            window.popleft()

        return self._compute_metrics(src_ip, window)

    def host_summary(self) -> Dict[str, dict]:
        """Return a summary of all tracked hosts."""
        return {
            ip: self._compute_metrics(ip, window)
            for ip, window in self._history.items()
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _compute_metrics(
        self, src_ip: str, window: Deque[_Sample]
    ) -> Dict[str, float]:
        if not window:
            return {"avg_bytes_per_sec": 0.0, "pkt_rate": 0.0, "deviation_score": 0.0}

        total_bytes = sum(s[0] + s[1] for s in window)
        total_pkts  = sum(s[2] for s in window)
        elapsed     = max((window[-1][3] - window[0][3]), 1e-6)

        avg_bps   = total_bytes / elapsed
        pkt_rate  = total_pkts  / elapsed

        # Simple deviation: ratio of latest sample to rolling mean
        latest_bytes = window[-1][0] + window[-1][1]
        mean_bytes   = total_bytes / len(window)
        deviation    = (latest_bytes / max(mean_bytes, 1e-6)) - 1.0

        return {
            "avg_bytes_per_sec": round(avg_bps,  2),
            "pkt_rate":          round(pkt_rate, 2),
            "deviation_score":   round(deviation, 4),
        }
