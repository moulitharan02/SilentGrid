#!/usr/bin/env bash
# kafka/topics.sh
# Helper script to create and describe the Kafka topics used by nt-traffic-filter.
# Usage:
#   ./kafka/topics.sh create   — create all required topics
#   ./kafka/topics.sh list     — list existing topics
#   ./kafka/topics.sh describe — describe topic configs

set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-localhost:9092}"
RAW_TOPIC="${KAFKA_TOPIC_RAW:-raw-traffic}"
ALERTS_TOPIC="${KAFKA_TOPIC_ALERTS:-traffic-alerts}"
PARTITIONS=3
REPLICATION=1

_kafka_topics() {
  kafka-topics.sh --bootstrap-server "$BOOTSTRAP" "$@"
}

create_topics() {
  echo "[+] Creating topic: $RAW_TOPIC"
  _kafka_topics --create --if-not-exists \
    --topic "$RAW_TOPIC" \
    --partitions "$PARTITIONS" \
    --replication-factor "$REPLICATION"

  echo "[+] Creating topic: $ALERTS_TOPIC"
  _kafka_topics --create --if-not-exists \
    --topic "$ALERTS_TOPIC" \
    --partitions "$PARTITIONS" \
    --replication-factor "$REPLICATION"

  echo "✅  Topics created successfully."
}

list_topics() {
  echo "[+] Existing topics on $BOOTSTRAP:"
  _kafka_topics --list
}

describe_topics() {
  echo "[+] Topic details:"
  _kafka_topics --describe --topic "$RAW_TOPIC"
  _kafka_topics --describe --topic "$ALERTS_TOPIC"
}

case "${1:-help}" in
  create)   create_topics   ;;
  list)     list_topics     ;;
  describe) describe_topics ;;
  *)
    echo "Usage: $0 {create|list|describe}"
    exit 1
    ;;
esac
