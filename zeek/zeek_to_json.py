"""
Zeek conn.log → JSON converter — Phase 1.

Reads Zeek TSV log files (conn.log) and emits newline-delimited JSON records,
either to stdout or directly into a Kafka topic.

Usage:
    # Stream to stdout
    python zeek/zeek_to_json.py --log /var/log/zeek/current/conn.log

    # Stream to Kafka
    python zeek/zeek_to_json.py --log /var/log/zeek/current/conn.log --kafka

    # Follow (tail -f style)
    python zeek/zeek_to_json.py --log /var/log/zeek/current/conn.log --follow
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Dict, Iterator, List, Optional

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def parse_zeek_log(path: str) -> Iterator[Dict]:
    """
    Lazily parse a Zeek TSV log file.
    Yields one dict per data line, skipping comment / directive lines.
    """
    fields: List[str] = []
    types:  List[str] = []

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")

            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#types"):
                types = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                values = line.split("\t")
                record = {}
                for i, field in enumerate(fields):
                    val = values[i] if i < len(values) else "-"
                    record[field] = None if val == "-" else val
                yield record


def tail_log(path: str, poll_interval: float = 0.5) -> Iterator[Dict]:
    """Tail a Zeek log in real-time, yielding new records as they appear."""
    fields: List[str] = []

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        # Fast-forward to end of existing content
        fh.seek(0, 2)

        while True:
            line = fh.readline()
            if not line:
                time.sleep(poll_interval)
                continue

            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#") or not fields:
                continue
            else:
                values = line.split("\t")
                record = {
                    field: (None if (values[i] if i < len(values) else "-") == "-"
                            else values[i])
                    for i, field in enumerate(fields)
                }
                yield record


def to_kafka(records: Iterator[Dict], topic: str, bootstrap: str) -> None:
    """Publish records to a Kafka topic."""
    from kafka import KafkaProducer  # lazy import

    producer = KafkaProducer(
        bootstrap_servers=bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    count = 0
    for record in records:
        producer.send(topic, record)
        count += 1
        if count % 1000 == 0:
            print(f"  → {count} records sent …", flush=True)
    producer.flush()
    print(f"Done. Total records sent: {count}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Zeek conn.log → JSON / Kafka")
    p.add_argument("--log",       default="/var/log/zeek/current/conn.log",
                   help="Path to Zeek conn.log")
    p.add_argument("--kafka",     action="store_true",
                   help="Publish to Kafka instead of stdout")
    p.add_argument("--follow",    action="store_true",
                   help="Tail the log file in real-time")
    p.add_argument("--topic",     default="raw-traffic",
                   help="Kafka topic name (default: raw-traffic)")
    p.add_argument("--bootstrap", default="localhost:9092",
                   help="Kafka bootstrap servers")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    source = tail_log(args.log) if args.follow else parse_zeek_log(args.log)

    if args.kafka:
        print(f"Publishing to Kafka topic '{args.topic}' @ {args.bootstrap} …")
        to_kafka(source, args.topic, args.bootstrap)
    else:
        for record in source:
            print(json.dumps(record))
