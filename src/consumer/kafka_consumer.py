"""
Kafka consumer for nt-traffic-filter.
Reads raw traffic messages from the Kafka topic, deserialises them,
and hands them off to the feature engine → detection engine pipeline.
"""

import json
import signal
import sys
from typing import Any, Dict

from kafka import KafkaConsumer
from kafka.errors import KafkaError

from src.config.config import (
    KAFKA_BOOTSTRAP_SERVERS,
    KAFKA_TOPIC_RAW,
    KAFKA_GROUP_ID,
    KAFKA_AUTO_OFFSET_RESET,
    TARGET_IPS,
)
from src.utils.logger import get_logger

log = get_logger(__name__)


class TrafficConsumer:
    """Threadsafe Kafka consumer wrapper for the raw-traffic topic."""

    def __init__(self, callback=None):
        """
        Args:
            callback: Optional callable(record: dict) invoked for every message.
        """
        self._callback = callback
        self._running = False
        self._consumer: KafkaConsumer | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Connect to Kafka and begin consuming messages."""
        log.info(
            "Connecting to Kafka broker(s): %s  topic: %s  group: %s",
            KAFKA_BOOTSTRAP_SERVERS,
            KAFKA_TOPIC_RAW,
            KAFKA_GROUP_ID,
        )
        try:
            self._consumer = KafkaConsumer(
                KAFKA_TOPIC_RAW,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                group_id=KAFKA_GROUP_ID,
                auto_offset_reset=KAFKA_AUTO_OFFSET_RESET,
                enable_auto_commit=True,
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            )
        except KafkaError as exc:
            log.error("Failed to connect to Kafka: %s", exc)
            sys.exit(1)

        self._running = True
        self._register_signals()
        self._consume_loop()

    def stop(self) -> None:
        """Gracefully stop the consumer."""
        log.info("Stopping Kafka consumer …")
        self._running = False
        if self._consumer:
            self._consumer.close()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _consume_loop(self) -> None:
        log.info("Consumer loop started — waiting for messages …")
        try:
            for message in self._consumer:
                if not self._running:
                    break
                self._handle(message.value)
        except Exception as exc:
            log.exception("Unexpected error in consumer loop: %s", exc)
        finally:
            self.stop()

    def _handle(self, record: Dict[str, Any]) -> None:
        """Process a single decoded record."""
        # Optional: Filter by specific target origin IP(s) if configured
        if TARGET_IPS:
            orig_h = record.get("id.orig_h")
            resp_h = record.get("id.resp_h")
            if orig_h not in TARGET_IPS and resp_h not in TARGET_IPS:
                return  # Skip records not involving the target IP(s)

        log.debug("Received record: %s", record)
        if self._callback:
            try:
                self._callback(record)
            except Exception as exc:
                log.error("Callback raised an exception: %s", exc)

    def _register_signals(self) -> None:
        signal.signal(signal.SIGINT, self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)

    def _on_signal(self, signum, frame) -> None:
        log.info("Received signal %s — shutting down …", signum)
        self.stop()


# ── Standalone entry point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    def _debug_callback(record: dict) -> None:
        print(json.dumps(record, indent=2))

    consumer = TrafficConsumer(callback=_debug_callback)
    consumer.start()
