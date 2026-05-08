"""
Prometheus metrics for nt-traffic-filter (Phase 3).

Exposes an HTTP /metrics endpoint on METRICS_PORT (default: 8001)
that Prometheus scrapes every 15 seconds.

Usage — import and call helpers from anywhere in the pipeline:
    from src.utils.metrics import (
        inc_records_processed,
        inc_alerts_fired,
        inc_detections,
        observe_latency,
        inc_dropped,
        inc_es_errors,
        start_metrics_server,
    )
"""

from __future__ import annotations

import time
import threading

from prometheus_client import (
    Counter,
    Histogram,
    start_http_server,
    REGISTRY,
)

from src.config.config import METRICS_PORT
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Metric definitions ────────────────────────────────────────────────────────

RECORDS_PROCESSED = Counter(
    "pipeline_records_processed_total",
    "Total traffic records consumed from Kafka",
)

ALERTS_FIRED = Counter(
    "pipeline_alerts_fired_total",
    "Total alerts dispatched, labelled by severity",
    labelnames=["severity"],
)

DETECTIONS = Counter(
    "pipeline_detections_total",
    "Total ML detections, labelled by predicted class",
    labelnames=["label"],
)

PROCESSING_LATENCY = Histogram(
    "pipeline_processing_latency_seconds",
    "End-to-end latency per Kafka record (feature extraction → alert dispatch)",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)

DROPPED_RECORDS = Counter(
    "pipeline_dropped_records_total",
    "Records discarded due to bad format or missing fields",
)

ES_WRITE_ERRORS = Counter(
    "elasticsearch_write_errors_total",
    "Elasticsearch bulk indexing failures",
)


# ── Helper functions ──────────────────────────────────────────────────────────

def inc_records_processed() -> None:
    RECORDS_PROCESSED.inc()


def inc_alerts_fired(severity: str = "UNKNOWN") -> None:
    ALERTS_FIRED.labels(severity=severity).inc()


def inc_detections(label: str = "UNKNOWN") -> None:
    DETECTIONS.labels(label=label).inc()


def observe_latency(seconds: float) -> None:
    PROCESSING_LATENCY.observe(seconds)


def inc_dropped() -> None:
    DROPPED_RECORDS.inc()


def inc_es_errors() -> None:
    ES_WRITE_ERRORS.inc()


class _LatencyTimer:
    """Context manager that records elapsed time to PROCESSING_LATENCY."""

    def __enter__(self) -> "_LatencyTimer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_: object) -> None:
        PROCESSING_LATENCY.observe(time.perf_counter() - self._start)


def record_latency() -> _LatencyTimer:
    """Use as a context manager: ``with metrics.record_latency(): ...``"""
    return _LatencyTimer()


# ── Server startup ────────────────────────────────────────────────────────────

_server_started = False
_server_lock = threading.Lock()


def start_metrics_server() -> None:
    """Start the Prometheus HTTP metrics server (idempotent)."""
    global _server_started
    with _server_lock:
        if _server_started:
            return
        try:
            start_http_server(METRICS_PORT)
            log.info("Prometheus metrics server started on :%d /metrics", METRICS_PORT)
            _server_started = True
        except OSError as exc:
            log.warning("Could not start metrics server on port %d: %s", METRICS_PORT, exc)
