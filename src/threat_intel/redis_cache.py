"""
Redis cache for Threat Intelligence lookups.
Avoids redundant API calls and helps avoid rate limits.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import redis

from src.config.config import REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD
from src.utils.logger import get_logger

log = get_logger(__name__)


class IntelCache:
    def __init__(self):
        self._redis = None
        self._ttl_seconds = 3600  # 1 hour
        self._connect()

    def _connect(self) -> None:
        try:
            self._redis = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                password=REDIS_PASSWORD or None,
                decode_responses=True,
            )
            # Ping to verify connection
            self._redis.ping()
            log.info("Connected to Redis cache at %s:%s", REDIS_HOST, REDIS_PORT)
        except Exception as e:
            log.error("Failed to connect to Redis cache: %s. TI caching disabled.", e)
            self._redis = None

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached intel for an IP."""
        if not self._redis:
            return None
            
        try:
            data = self._redis.get(f"ti:{ip}")
            if data:
                log.debug("TI cache hit for IP: %s", ip)
                return json.loads(data)
            return None
        except Exception as e:
            log.error("Redis get error: %s", e)
            return None

    def set(self, ip: str, data: Dict[str, Any]) -> None:
        """Cache intel for an IP."""
        if not self._redis:
            return
            
        try:
            self._redis.setex(
                f"ti:{ip}",
                self._ttl_seconds,
                json.dumps(data)
            )
        except Exception as e:
            log.error("Redis set error: %s", e)
