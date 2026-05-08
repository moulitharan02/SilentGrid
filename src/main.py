"""
Main entry point — nt-traffic-filter (Phase 3).

Wires together:
  KafkaConsumer → FeatureEngine → DetectionEngine → RiskEngine → AlertManager
                  GraphEngine → CorrelationEngine → IntelEngine
                  ElasticWriter (Phase 3 — persistent storage)
                  Prometheus metrics (Phase 3 — observability)

Run:
    python -m src.main
"""

from __future__ import annotations

import sys
import json
import time

from rich.console import Console
from rich.panel import Panel

from src.config.config import (
    KAFKA_BOOTSTRAP_SERVERS,
    KAFKA_TOPIC_RAW,
    KAFKA_GROUP_ID,
    ANOMALY_THRESHOLD,
    RISK_HIGH_THRESHOLD,
)
from src.consumer.kafka_consumer import TrafficConsumer
from src.features.feature_engine import FeatureEngine
from src.detection.detection_engine import DetectionEngine
from src.detection.risk_engine import RiskEngine
from src.alerting.alert_manager import AlertManager
from src.correlation.graph_engine import GraphEngine
from src.correlation.correlation_engine import CorrelationEngine
from src.threat_intel.intel_engine import IntelEngine
from src.storage.elastic_writer import ElasticWriter
from src.utils import metrics as m
from src.utils.logger import get_logger

log     = get_logger(__name__)
console = Console()


def build_pipeline() -> TrafficConsumer:
    """Instantiate and wire all pipeline components."""
    feature_engine   = FeatureEngine()
    detection_engine = DetectionEngine()
    risk_engine      = RiskEngine()
    alert_manager    = AlertManager()

    # Phase 2 engines
    graph_engine       = GraphEngine()
    correlation_engine = CorrelationEngine()
    intel_engine       = IntelEngine()

    # Phase 3 — storage + metrics
    elastic_writer     = ElasticWriter()

    def process(record: dict) -> None:
        """Full processing pipeline for one traffic record."""
        t0 = time.perf_counter()
        m.inc_records_processed()

        # 1. Feature extraction
        vector = feature_engine.extract(record)
        if vector is None:
            m.inc_dropped()
            return

        # 2. Detection (IsolationForest + XGBoost + RandomForest)
        detection_result = detection_engine.predict(vector, record)
        if detection_result is None:
            m.inc_dropped()
            return

        m.inc_detections(detection_result.predicted_label)

        # 3. Risk scoring
        risk_result = risk_engine.score(detection_result)

        # 4. Intelligence Layer
        graph_engine.update_graph(record)
        c2_nodes = graph_engine.detect_c2()
        is_c2 = any(node == record.get("src_ip") for node, score in c2_nodes)

        behaviors = []
        if detection_result.predicted_label != "BENIGN":
            behaviors.append(detection_result.predicted_label)
        if record.get("behavior_is_burst"):
            behaviors.append("TRAFFIC_SPIKE")
        if risk_result.risk_score > 50:
            behaviors.append("HIGH_RISK_TRAFFIC")

        correlation_result = correlation_engine.correlate(record, behaviors)
        attack_type = correlation_result["attack_type"] if correlation_result else None
        mitre_info  = correlation_result if correlation_result else {}

        intel = None
        if risk_result.risk_score > 70 or is_c2 or attack_type:
            intel = intel_engine.check_ip(record.get("src_ip"))

        # 5. Alert dispatch
        alert_manager.process(risk_result)
        if risk_result.severity in ("HIGH", "CRITICAL"):
            m.inc_alerts_fired(risk_result.severity)

        # 6. Build enriched event
        enriched_data = {
            "src":              record.get("src_ip", "unknown"),
            "dst":              record.get("dst_ip", "unknown"),
            "src_port":         record.get("src_port"),
            "dst_port":         record.get("dst_port"),
            "protocol":         record.get("proto", ""),
            "prediction":       detection_result.predicted_label,
            "severity":         risk_result.severity,
            "behaviors":        behaviors,
            "attack_type":      attack_type,
            "c2_candidate":     is_c2,
            "threat_intel":     (
                "KNOWN_MALICIOUS"
                if (intel and intel.get("abuseConfidenceScore", 0) > 50)
                else ("BENIGN" if intel else "UNKNOWN")
            ),
            "risk_score":       risk_result.risk_score,
            "mitre_tactic":     mitre_info.get("mitre_tactic", "Unknown"),
            "mitre_technique":  mitre_info.get("mitre_technique", "Unknown"),
            "raw_features":     vector if isinstance(vector, dict) else {},
        }

        # 7. Index to Elasticsearch (Phase 3)
        elastic_writer.write(enriched_data)

        # 8. Record latency
        m.observe_latency(time.perf_counter() - t0)

        # 9. Console output
        if attack_type or is_c2 or (intel and intel.get("abuseConfidenceScore", 0) > 50):
            log.warning("🔥 THREAT INTELLIGENCE ALERT: %s", json.dumps(enriched_data))
        else:
            log.info(
                "Processed record — label=%-15s  risk=%3d  severity=%s",
                detection_result.predicted_label,
                risk_result.risk_score,
                risk_result.severity,
            )

    return TrafficConsumer(callback=process)


def print_banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]VulnXploit Core (Phase 3)[/bold cyan]\n"
            "[dim]Network Traffic Anomaly & Threat Detection Pipeline[/dim]\n\n"
            f"  Broker  : [yellow]{KAFKA_BOOTSTRAP_SERVERS}[/yellow]\n"
            f"  Topic   : [yellow]{KAFKA_TOPIC_RAW}[/yellow]\n"
            f"  Group   : [yellow]{KAFKA_GROUP_ID}[/yellow]\n"
            f"  Anomaly threshold : [yellow]{ANOMALY_THRESHOLD}[/yellow]\n"
            f"  High-risk threshold : [yellow]{RISK_HIGH_THRESHOLD}[/yellow]\n"
            f"  Storage : [yellow]Elasticsearch[/yellow]\n"
            f"  Metrics : [yellow]:8001/metrics[/yellow]",
            title="[bold green]Starting[/bold green]",
            border_style="green",
        )
    )


def main() -> None:
    print_banner()

    # Start Prometheus metrics HTTP server
    m.start_metrics_server()

    log.info("Initialising pipeline …")

    try:
        consumer = build_pipeline()
        consumer.start()
    except KeyboardInterrupt:
        log.info("Interrupted — exiting.")
        sys.exit(0)
    except Exception as exc:
        log.critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
