"""
FastAPI REST server — nt-traffic-filter (Phase 3).

Endpoints:
  GET /                       — root info
  GET /health                 — liveness + model availability
  GET /stats                  — pipeline config + alert count
  GET /alerts                 — recent log-file alerts (legacy)
  GET /detections             — ES-backed paginated detection events
  GET /detections/summary     — aggregated ES stats
  GET /timeline/{ip}          — attack chain for a specific IP
  GET /graph                  — C2 graph data (nodes + edges)
  GET /metrics/summary        — pipeline throughput counters

Run:
    uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.config.config import (
    ANOMALY_MODEL_PATH,
    CLASSIFIER_MODEL_PATH,
    SCALER_PATH,
    ALERT_LOG_PATH,
    RISK_HIGH_THRESHOLD,
    ELASTICSEARCH_HOST,
    ELASTICSEARCH_INDEX_PREFIX,
    DASHBOARD_ORIGIN,
)
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Elasticsearch client (optional — API works without ES) ────────────────────
_es = None
try:
    from elasticsearch import Elasticsearch
    _host = ELASTICSEARCH_HOST
    if not _host.startswith("http"):
        _host = f"http://{_host}"
    _es = Elasticsearch(hosts=[_host], request_timeout=5, max_retries=1)
    _es.info()  # test connection at startup
    log.info("API: Elasticsearch connected at %s", ELASTICSEARCH_HOST)
except Exception as _exc:
    log.warning("API: Elasticsearch unavailable — ES endpoints will return empty results: %s", _exc)
    _es = None

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="VulnXploit Core API",
    description="Runtime interface for the network traffic anomaly detection pipeline.",
    version="0.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tightened to DASHBOARD_ORIGIN in Phase 4
    allow_methods=["GET"],
    allow_headers=["*"],
)

# ── Response models ────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    models: Dict[str, bool]
    elasticsearch: bool

class AlertEntry(BaseModel):
    timestamp: str
    level: str
    message: str

class StatsResponse(BaseModel):
    risk_high_threshold: int
    alert_log_path: str
    recent_alert_count: int

class DetectionEvent(BaseModel):
    timestamp: str
    src_ip: str
    src_port: Optional[str] = None
    dst_ip: str
    dst_port: Optional[str] = None
    prediction: str
    risk_score: float
    severity: str
    behaviors: List[str]
    attack_type: Optional[str]
    mitre_tactic: str
    mitre_technique: str
    c2_candidate: bool
    threat_intel: str

class DetectionSummary(BaseModel):
    total_detections: int
    by_label: Dict[str, int]
    by_severity: Dict[str, int]
    avg_risk_score: float
    top_src_ips: List[Dict[str, Any]]
    top_attack_types: List[Dict[str, Any]]

class TimelineEntry(BaseModel):
    timestamp: str
    attack_type: Optional[str]
    mitre_tactic: str
    mitre_technique: str
    risk_score: float
    behaviors: List[str]

class GraphData(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]

class MetricsSummary(BaseModel):
    index_prefix: str
    elasticsearch_connected: bool
    total_detections_in_es: int

# ── Helpers ────────────────────────────────────────────────────────────────────

def _model_exists(path: str) -> bool:
    return os.path.isfile(path)

def _read_recent_alerts(n: int = 50) -> List[AlertEntry]:
    if not os.path.isfile(ALERT_LOG_PATH):
        return []
    try:
        with open(ALERT_LOG_PATH, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        results = []
        for line in lines[-n:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(" | ", maxsplit=3)
            results.append(AlertEntry(
                timestamp=parts[0] if len(parts) > 0 else "",
                level=parts[1].strip() if len(parts) > 1 else "UNKNOWN",
                message=parts[-1] if len(parts) > 0 else line,
            ))
        return results
    except Exception as exc:
        log.error("Error reading alert log: %s", exc)
        return []

def _es_index_pattern() -> str:
    return f"{ELASTICSEARCH_INDEX_PREFIX}-*"

def _es_available() -> bool:
    return _es is not None

# ── Routes — System ────────────────────────────────────────────────────────────

@app.get("/", tags=["System"])
def root() -> Dict[str, Any]:
    return {
        "name": "VulnXploit Core API",
        "version": "0.3.0",
        "docs": "/docs",
        "health": "/health",
        "phase": 3,
    }

@app.get("/health", response_model=HealthResponse, tags=["System"])
def health() -> HealthResponse:
    """Liveness check — confirms API is running, reports model and ES availability."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(timezone.utc).isoformat(),
        models={
            "scaler":     _model_exists(SCALER_PATH),
            "anomaly":    _model_exists(ANOMALY_MODEL_PATH),
            "classifier": _model_exists(CLASSIFIER_MODEL_PATH),
        },
        elasticsearch=_es_available(),
    )

@app.get("/stats", response_model=StatsResponse, tags=["System"])
def stats() -> StatsResponse:
    """Return runtime configuration and alert summary statistics."""
    alerts = _read_recent_alerts(1000)
    return StatsResponse(
        risk_high_threshold=RISK_HIGH_THRESHOLD,
        alert_log_path=ALERT_LOG_PATH,
        recent_alert_count=len(alerts),
    )

# ── Routes — Legacy alerts (log-file based) ────────────────────────────────────

@app.get("/alerts", response_model=List[AlertEntry], tags=["Alerts"])
def get_alerts(limit: int = Query(50, ge=1, le=1000)) -> List[AlertEntry]:
    """Return the most recent alert log entries (log-file based, legacy)."""
    return _read_recent_alerts(limit)

# ── Routes — Detections (Elasticsearch backed) ────────────────────────────────

@app.get("/detections", response_model=List[DetectionEvent], tags=["Detections"])
def get_detections(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    label: Optional[str] = Query(None, description="Filter by prediction label, e.g. DDoS"),
    hours: int = Query(24, ge=1, le=168, description="Time window in hours (default: last 24h)"),
) -> List[DetectionEvent]:
    """Paginated list of detection events from Elasticsearch."""
    if not _es_available():
        raise HTTPException(status_code=503, detail="Elasticsearch is not available")

    must_clauses: List[Dict] = [
        {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}
    ]
    if severity:
        must_clauses.append({"term": {"severity": severity.upper()}})
    if label:
        must_clauses.append({"term": {"prediction": label}})

    try:
        resp = _es.search(
            index=_es_index_pattern(),
            body={
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": must_clauses}},
            },
        )
    except Exception as exc:
        log.error("ES search error: %s", exc)
        raise HTTPException(status_code=502, detail=f"Elasticsearch error: {exc}")

    results = []
    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        results.append(DetectionEvent(
            timestamp=src.get("@timestamp", ""),
            src_ip=src.get("src_ip", ""),
            src_port=str(src.get("src_port", "")),
            dst_ip=src.get("dst_ip", ""),
            dst_port=str(src.get("dst_port", "")),
            prediction=src.get("prediction", "UNKNOWN"),
            risk_score=src.get("risk_score", 0.0),
            severity=src.get("severity", "LOW"),
            behaviors=src.get("behaviors", []),
            attack_type=src.get("attack_type"),
            mitre_tactic=src.get("mitre_tactic", "Unknown"),
            mitre_technique=src.get("mitre_technique", "Unknown"),
            c2_candidate=src.get("c2_candidate", False),
            threat_intel=src.get("threat_intel", "UNKNOWN"),
        ))
    return results


@app.get("/detections/summary", response_model=DetectionSummary, tags=["Detections"])
def get_detections_summary(
    hours: int = Query(24, ge=1, le=168)
) -> DetectionSummary:
    """Aggregated detection statistics for the given time window."""
    if not _es_available():
        raise HTTPException(status_code=503, detail="Elasticsearch is not available")

    try:
        resp = _es.search(
            index=_es_index_pattern(),
            body={
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                "aggs": {
                    "by_label":     {"terms": {"field": "prediction", "size": 20}},
                    "by_severity":  {"terms": {"field": "severity", "size": 10}},
                    "avg_risk":     {"avg": {"field": "risk_score"}},
                    "top_src_ips":  {"terms": {"field": "src_ip", "size": 10}},
                    "top_attacks":  {"terms": {"field": "attack_type", "size": 10}},
                },
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    aggs = resp.get("aggregations", {})
    total = resp["hits"]["total"]["value"]

    return DetectionSummary(
        total_detections=total,
        by_label={b["key"]: b["doc_count"] for b in aggs.get("by_label", {}).get("buckets", [])},
        by_severity={b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])},
        avg_risk_score=round(aggs.get("avg_risk", {}).get("value") or 0.0, 2),
        top_src_ips=[{"ip": b["key"], "count": b["doc_count"]} for b in aggs.get("top_src_ips", {}).get("buckets", [])],
        top_attack_types=[{"type": b["key"], "count": b["doc_count"]} for b in aggs.get("top_attacks", {}).get("buckets", []) if b["key"]],
    )


@app.get("/timeline/{ip}", response_model=List[TimelineEntry], tags=["Detections"])
def get_timeline(
    ip: str,
    hours: int = Query(72, ge=1, le=720),
) -> List[TimelineEntry]:
    """Full attack chain timeline for a specific source IP."""
    if not _es_available():
        raise HTTPException(status_code=503, detail="Elasticsearch is not available")

    try:
        resp = _es.search(
            index=_es_index_pattern(),
            body={
                "size": 200,
                "sort": [{"@timestamp": {"order": "asc"}}],
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"src_ip": ip}},
                            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                        ]
                    }
                },
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    results = []
    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        results.append(TimelineEntry(
            timestamp=src.get("@timestamp", ""),
            attack_type=src.get("attack_type"),
            mitre_tactic=src.get("mitre_tactic", "Unknown"),
            mitre_technique=src.get("mitre_technique", "Unknown"),
            risk_score=src.get("risk_score", 0.0),
            behaviors=src.get("behaviors", []),
        ))
    return results


@app.get("/graph", response_model=GraphData, tags=["Detections"])
def get_graph(
    hours: int = Query(24, ge=1, le=168),
    min_risk: float = Query(50.0, ge=0.0, le=100.0, description="Minimum risk score to include"),
) -> GraphData:
    """
    C2 graph data for visualization.
    Returns nodes (IPs) and edges (connections) for high-risk traffic.
    """
    if not _es_available():
        raise HTTPException(status_code=503, detail="Elasticsearch is not available")

    try:
        resp = _es.search(
            index=_es_index_pattern(),
            body={
                "size": 500,
                "_source": ["src_ip", "dst_ip", "risk_score", "c2_candidate",
                            "prediction", "attack_type", "threat_intel"],
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                            {"range": {"risk_score": {"gte": min_risk}}},
                        ]
                    }
                },
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    node_map: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        s_ip = src.get("src_ip", "")
        d_ip = src.get("dst_ip", "")
        if not s_ip or not d_ip:
            continue

        # Track nodes
        for ip, is_c2 in [(s_ip, src.get("c2_candidate", False)), (d_ip, False)]:
            if ip not in node_map:
                node_map[ip] = {"id": ip, "label": ip, "c2": False, "risk": 0.0, "count": 0}
            if is_c2:
                node_map[ip]["c2"] = True
            node_map[ip]["risk"] = max(node_map[ip]["risk"], src.get("risk_score", 0.0))
            node_map[ip]["count"] += 1

        edges.append({
            "source": s_ip,
            "target": d_ip,
            "risk": src.get("risk_score", 0.0),
            "type": src.get("prediction", "UNKNOWN"),
            "attack_type": src.get("attack_type"),
        })

    return GraphData(nodes=list(node_map.values()), edges=edges)


@app.get("/metrics/summary", response_model=MetricsSummary, tags=["System"])
def metrics_summary() -> MetricsSummary:
    """Quick pipeline summary for dashboard header cards."""
    total = 0
    if _es_available():
        try:
            resp = _es.count(index=_es_index_pattern())
            total = resp.get("count", 0)
        except Exception:
            pass
    return MetricsSummary(
        index_prefix=ELASTICSEARCH_INDEX_PREFIX,
        elasticsearch_connected=_es_available(),
        total_detections_in_es=total,
    )
