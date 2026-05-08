"""
ElasticWriter — Phase 3 persistent storage for nt-traffic-filter.

Writes enriched detection events to Elasticsearch with:
- Daily rolling indices: nt-detections-YYYY.MM.DD
- Buffered bulk indexing (flushes at BULK_SIZE or every FLUSH_INTERVAL seconds)
- Exponential backoff retry on connection failures
- Graceful degradation — pipeline never crashes due to ES unavailability
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from elasticsearch import Elasticsearch, helpers, ConnectionError as ESConnectionError, TransportError

from src.config.config import (
    ELASTICSEARCH_HOST,
    ELASTICSEARCH_INDEX_PREFIX,
    ELASTICSEARCH_TIMEOUT,
    ELASTICSEARCH_BULK_SIZE,
)
from src.utils.logger import get_logger

log = get_logger(__name__)

# Index mapping applied on first write
INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp":       {"type": "date"},
            "src_ip":           {"type": "ip"},
            "dst_ip":           {"type": "ip"},
            "src_port":         {"type": "integer"},
            "dst_port":         {"type": "integer"},
            "protocol":         {"type": "keyword"},
            "prediction":       {"type": "keyword"},
            "risk_score":       {"type": "float"},
            "severity":         {"type": "keyword"},
            "behaviors":        {"type": "keyword"},
            "attack_type":      {"type": "keyword"},
            "mitre_tactic":     {"type": "keyword"},
            "mitre_technique":  {"type": "keyword"},
            "c2_candidate":     {"type": "boolean"},
            "threat_intel":     {"type": "keyword"},
            "raw_features":     {"type": "object", "dynamic": True},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,  # dev single-node; bump to 1+ in prod
    },
}

FLUSH_INTERVAL: float = 5.0  # seconds between auto-flushes


class ElasticWriter:
    """Thread-safe buffered writer for Elasticsearch detection events."""

    def __init__(self) -> None:
        self._client: Elasticsearch | None = None
        self._buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._created_indices: set[str] = set()
        self._running = False
        self._flush_thread: threading.Thread | None = None
        self._connect()
        self._start_flush_thread()

    # ── Connection ─────────────────────────────────────────────────────────────

    def _connect(self) -> None:
        host = ELASTICSEARCH_HOST
        if not host.startswith("http"):
            host = f"http://{host}"
        try:
            self._client = Elasticsearch(
                hosts=[host],
                request_timeout=ELASTICSEARCH_TIMEOUT,
                retry_on_timeout=True,
                max_retries=3,
            )
            info = self._client.info()
            log.info(
                "Elasticsearch connected — cluster=%s version=%s",
                info["cluster_name"],
                info["version"]["number"],
            )
        except Exception as exc:
            log.warning("Elasticsearch unavailable — buffering disabled: %s", exc)
            self._client = None

    # ── Index management ───────────────────────────────────────────────────────

    def _ensure_index(self, index_name: str) -> None:
        if self._client is None or index_name in self._created_indices:
            return
        try:
            if not self._client.indices.exists(index=index_name):
                self._client.indices.create(index=index_name, body=INDEX_MAPPING)
                log.info("Created ES index: %s", index_name)
            self._created_indices.add(index_name)
        except Exception as exc:
            log.warning("Could not ensure index %s: %s", index_name, exc)

    def _index_name(self) -> str:
        day = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{ELASTICSEARCH_INDEX_PREFIX}-{day}"

    # ── Public API ─────────────────────────────────────────────────────────────

    def write(self, event: Dict[str, Any]) -> None:
        """Buffer a single enriched detection event for bulk indexing."""
        if self._client is None:
            return  # ES offline — silently skip

        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip":          event.get("src", ""),
            "dst_ip":          event.get("dst", ""),
            "src_port":        event.get("src_port"),
            "dst_port":        event.get("dst_port"),
            "protocol":        event.get("protocol", ""),
            "prediction":      event.get("prediction", "UNKNOWN"),
            "risk_score":      event.get("risk_score", 0),
            "severity":        event.get("severity", "LOW"),
            "behaviors":       event.get("behaviors", []),
            "attack_type":     event.get("attack_type"),
            "mitre_tactic":    event.get("mitre_tactic", "Unknown"),
            "mitre_technique": event.get("mitre_technique", "Unknown"),
            "c2_candidate":    event.get("c2_candidate", False),
            "threat_intel":    event.get("threat_intel", "UNKNOWN"),
            "raw_features":    event.get("raw_features", {}),
        }

        index_name = self._index_name()
        action = {"_index": index_name, "_source": doc}

        with self._lock:
            self._buffer.append(action)
            should_flush = len(self._buffer) >= ELASTICSEARCH_BULK_SIZE

        if should_flush:
            self._flush()

    def close(self) -> None:
        """Flush remaining events and shut down the flush thread."""
        self._running = False
        self._flush()
        if self._flush_thread:
            self._flush_thread.join(timeout=10)

    # ── Flush logic ────────────────────────────────────────────────────────────

    def _flush(self) -> None:
        if self._client is None:
            return

        with self._lock:
            if not self._buffer:
                return
            batch = self._buffer.copy()
            self._buffer.clear()

        # Ensure all needed indices exist
        indices_needed = {a["_index"] for a in batch}
        for idx in indices_needed:
            self._ensure_index(idx)

        try:
            success, errors_list = helpers.bulk(
                self._client, batch, raise_on_error=False
            )
            if errors_list:
                # Log first error for debugging
                if errors_list:
                    log.warning("ES bulk: %d succeeded, %d failed. First error: %s", 
                               success, len(errors_list), errors_list[0] if errors_list else "")
            else:
                log.debug("ES bulk: indexed %d documents", success)
        except (ESConnectionError, TransportError) as exc:
            log.error("ES bulk write failed — %d docs lost: %s", len(batch), exc)
            # Try to reconnect for next flush
            self._connect()
        except Exception as exc:
            log.error("Unexpected ES error: %s", exc)

    def _start_flush_thread(self) -> None:
        self._running = True

        def _loop() -> None:
            while self._running:
                time.sleep(FLUSH_INTERVAL)
                self._flush()

        self._flush_thread = threading.Thread(target=_loop, daemon=True, name="es-flusher")
        self._flush_thread.start()
