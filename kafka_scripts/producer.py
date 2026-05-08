"""
Kafka producer for nt-traffic-filter.
Used for testing: reads a CICIDS CSV or JSON file and publishes records
to the raw-traffic Kafka topic.

Usage:
    python kafka_scripts/producer.py --source data/cicids.csv --rate 100
    python kafka_scripts/producer.py --source data/sample.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.config.config import KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC_RAW


def publish_csv(path: str, producer, rate: int) -> None:
    delay = 1.0 / rate if rate > 0 else 0
    count = 0
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            producer.send(KAFKA_TOPIC_RAW, dict(row))
            count += 1
            if delay:
                time.sleep(delay)
            if count % 500 == 0:
                print(f"  → {count} records sent …", flush=True)
    producer.flush()
    print(f"Done. Sent {count} CSV records to '{KAFKA_TOPIC_RAW}'.")


def publish_json(path: str, producer, rate: int) -> None:
    delay = 1.0 / rate if rate > 0 else 0
    count = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            producer.send(KAFKA_TOPIC_RAW, record)
            count += 1
            if delay:
                time.sleep(delay)
    producer.flush()
    print(f"Done. Sent {count} JSON records to '{KAFKA_TOPIC_RAW}'.")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="nt-traffic-filter Kafka test producer")
    p.add_argument("--source",    required=True, help="CSV or NDJSON source file")
    p.add_argument("--bootstrap", default=KAFKA_BOOTSTRAP_SERVERS,
                   help=f"Kafka bootstrap servers (default: {KAFKA_BOOTSTRAP_SERVERS})")
    p.add_argument("--rate",      type=int, default=0,
                   help="Records per second (0 = unlimited)")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    from kafka import KafkaProducer

    producer = KafkaProducer(
        bootstrap_servers=args.bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    ext = os.path.splitext(args.source)[1].lower()
    print(f"Publishing '{args.source}' → topic '{KAFKA_TOPIC_RAW}' …")
    if ext == ".csv":
        publish_csv(args.source, producer, args.rate)
    else:
        publish_json(args.source, producer, args.rate)
