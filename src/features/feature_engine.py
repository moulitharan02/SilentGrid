"""
Feature engineering for nt-traffic-filter.
Transforms raw Zeek/Kafka records into the numeric feature vector
expected by the ML models, and computes advanced behavioral features.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

import numpy as np
import joblib

from src.config.config import SCALER_PATH
from src.utils.logger import get_logger

log = get_logger(__name__)

# Ordered feature names that must match the training pipeline.
FEATURE_NAMES: List[str] = [
    "duration",
    "protocol_num",
    "src_port",
    "dst_port",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "bytes_per_pkt",
    "pkt_rate",
    "byte_rate",
]

# Protocol → integer encoding
_PROTO_MAP: Dict[str, int] = {
    "tcp": 0,
    "udp": 1,
    "icmp": 2,
    "unknown": 3,
}


class FeatureEngine:
    """Converts raw traffic dicts to scaled numpy feature vectors and enriches behavioral features."""

    def __init__(self):
        self._scaler = None
        self._load_scaler()
        
        # State for time-windowed features
        self._ip_history = defaultdict(list)
        self._port_history = defaultdict(list)
        self._failed_conns = defaultdict(int)
        self._total_conns = defaultdict(int)

    # ── Public API ────────────────────────────────────────────────────────────

    def extract(self, record: Dict[str, Any]) -> Optional[np.ndarray]:
        """
        Extract and scale features from a raw traffic record, and mutate `record` 
        to add behavioral features for downstream correlation.

        Args:
            record: Dict with keys produced by the Zeek/Kafka producer.

        Returns:
            1-D numpy array of shape (len(FEATURE_NAMES),) or None on failure.
        """
        try:
            raw = self._extract_raw(record)
            
            # 1. Base ML Features
            vector = np.array([raw[f] for f in FEATURE_NAMES], dtype=float)
            vector = self._sanitize(vector)
            if self._scaler:
                vector = self._scaler.transform(vector.reshape(1, -1))[0]
            
            # 2. Enrich behavioral features (mutates record in-place)
            self._enrich_behavioral(record, raw)
            
            return vector
        except Exception as exc:
            log.warning("Feature extraction failed: %s | record=%s", exc, record)
            return None

    # ── Internals ─────────────────────────────────────────────────────────────

    def _extract_raw(self, r: Dict[str, Any]) -> Dict[str, float]:
        duration   = float(r.get("duration") or 0.0)
        orig_bytes = float(r.get("orig_bytes") or 0.0)
        resp_bytes = float(r.get("resp_bytes") or 0.0)
        orig_pkts  = float(r.get("orig_pkts") or 1.0)
        resp_pkts  = float(r.get("resp_pkts") or 0.0)

        bytes_per_pkt = (orig_bytes + resp_bytes) / max(orig_pkts + resp_pkts, 1.0)
        pkt_rate      = (orig_pkts + resp_pkts) / max(duration, 1e-6)
        byte_rate     = (orig_bytes + resp_bytes) / max(duration, 1e-6)

        return {
            "duration":      duration,
            "protocol_num":  _PROTO_MAP.get(str(r.get("proto", "unknown")).lower(), 3),
            "src_port":      float(r.get("id.orig_p") or r.get("src_port") or 0),
            "dst_port":      float(r.get("id.resp_p") or r.get("dst_port") or 0),
            "orig_bytes":    orig_bytes,
            "resp_bytes":    resp_bytes,
            "orig_pkts":     orig_pkts,
            "resp_pkts":     resp_pkts,
            "orig_ip_bytes": float(r.get("orig_ip_bytes") or orig_bytes),
            "resp_ip_bytes": float(r.get("resp_ip_bytes") or resp_bytes),
            "bytes_per_pkt": bytes_per_pkt,
            "pkt_rate":      pkt_rate,
            "byte_rate":     byte_rate,
        }

    def _enrich_behavioral(self, record: Dict[str, Any], raw: Dict[str, float]) -> None:
        """Computes Phase 2 advanced behavioral features and appends to the record."""
        src_ip = record.get("src_ip", "unknown")
        dst_port = raw["dst_port"]
        now = time.time()
        
        # Cleanup old state (older than 60s) — keep port/time pairs aligned
        _pairs = list(zip(self._port_history[src_ip], self._ip_history[src_ip]))
        _pairs = [(p, ts) for p, ts in _pairs if now - ts < 60]
        self._port_history[src_ip] = [p for p, _ in _pairs]
        self._ip_history[src_ip] = [ts for _, ts in _pairs]
        
        # 1. Time-windowed features (connections in last 60s)
        self._ip_history[src_ip].append(now)
        self._port_history[src_ip].append(dst_port)
        conns_60s = len(self._ip_history[src_ip])
        record["behavior_conns_60s"] = conns_60s
        
        # 2. Burst detection
        record["behavior_is_burst"] = conns_60s > 100
        
        # 3. Entropy of destination ports
        port_counts = {}
        for p in self._port_history[src_ip]:
            port_counts[p] = port_counts.get(p, 0) + 1
            
        entropy = 0.0
        total_ports = len(self._port_history[src_ip])
        if total_ports > 0:
            for count in port_counts.values():
                p_i = count / total_ports
                entropy -= p_i * math.log2(p_i)
        record["behavior_port_entropy"] = entropy
        
        # 4. SYN/ACK imbalance (heuristic based on packets sent vs received)
        orig_pkts = raw["orig_pkts"]
        resp_pkts = raw["resp_pkts"]
        imbalance = 0.0
        if orig_pkts > 0:
            imbalance = max(0, 1.0 - (resp_pkts / orig_pkts))
        record["behavior_syn_ack_imbalance"] = imbalance
        
        # 5. Failed connection ratio
        # A simple proxy: if duration is near 0 and no response packets, assume failed/rejected
        is_failed = raw["duration"] < 0.001 and resp_pkts == 0
        self._total_conns[src_ip] += 1
        if is_failed:
            self._failed_conns[src_ip] += 1
            
        record["behavior_failed_conn_ratio"] = self._failed_conns[src_ip] / max(1, self._total_conns[src_ip])


    @staticmethod
    def _sanitize(vector: np.ndarray) -> np.ndarray:
        """Replace NaN / Inf with 0."""
        vector = np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)
        return vector

    def _load_scaler(self) -> None:
        try:
            self._scaler = joblib.load(SCALER_PATH)
            log.info("Loaded scaler from %s", SCALER_PATH)
        except FileNotFoundError:
            log.warning("Scaler not found at %s — features will NOT be scaled.", SCALER_PATH)
        except Exception as exc:
            log.error("Failed to load scaler: %s", exc)
