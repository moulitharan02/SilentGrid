"""
Threat Intelligence Engine — Phase 2.
Performs IP reputation lookups using APIs (AbuseIPDB, VirusTotal, OTX)
and caches results in Redis.
"""

from __future__ import annotations

import os
import requests
from typing import Optional, Dict, Any

from src.config.config import VT_API_KEY, OTX_API_KEY
from src.threat_intel.redis_cache import IntelCache
from src.utils.logger import get_logger

log = get_logger(__name__)


class IntelEngine:
    def __init__(self):
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.vt_key = VT_API_KEY
        self.otx_key = OTX_API_KEY
        self.cache = IntelCache()
        
        if not self.abuseipdb_key and not self.vt_key and not self.otx_key:
            log.warning("No Threat Intel API keys configured. Using mock responses.")

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Check an IP address against threat intelligence feeds.
        Returns aggregated result or cached data.
        """
        if not ip or ip == "0.0.0.0" or ip == "127.0.0.1":
            return None

        # Check Cache
        cached_result = self.cache.get(ip)
        if cached_result:
            return cached_result

        # Fetch from APIs
        result = self._fetch_all_intel(ip)
        
        # Fallback to mock if no APIs are configured
        if not result and not self._has_any_keys():
            result = self._mock_intel(ip)
            
        if result:
            self.cache.set(ip, result)
            
        return result

    def _has_any_keys(self) -> bool:
        return bool(self.abuseipdb_key or self.vt_key or self.otx_key)

    def _fetch_all_intel(self, ip: str) -> Optional[Dict[str, Any]]:
        """Fetch from all available APIs and aggregate."""
        abuse_score = 0
        engines_flagged = 0
        tags = set()
        
        # 1. AbuseIPDB
        if self.abuseipdb_key:
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
                params = {"ipAddress": ip, "maxAgeInDays": 90}
                res = requests.get(url, headers=headers, params=params, timeout=5.0)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    abuse_score = max(abuse_score, data.get("abuseConfidenceScore", 0))
            except Exception as e:
                log.error("AbuseIPDB error: %s", e)

        # 2. VirusTotal
        if self.vt_key:
            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                headers = {"x-apikey": self.vt_key}
                res = requests.get(url, headers=headers, timeout=5.0)
                if res.status_code == 200:
                    stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    engines_flagged += stats.get("malicious", 0) + stats.get("suspicious", 0)
            except Exception as e:
                log.error("VirusTotal error: %s", e)
                
        # 3. OTX AlienVault
        if self.otx_key:
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
                headers = {"X-OTX-API-KEY": self.otx_key}
                res = requests.get(url, headers=headers, timeout=5.0)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("pulse_info", {}).get("count", 0) > 0:
                        engines_flagged += 1
                        for pulse in data.get("pulse_info", {}).get("pulses", []):
                            tags.update(pulse.get("tags", []))
            except Exception as e:
                log.error("OTX error: %s", e)

        if abuse_score > 0 or engines_flagged > 0:
            return {
                "ipAddress": ip,
                "abuseConfidenceScore": abuse_score,
                "vt_engines_flagged": engines_flagged,
                "tags": list(tags)
            }
        
        return None

    def _mock_intel(self, ip: str) -> Dict[str, Any]:
        """Mock response for testing."""
        if ip in ["192.168.1.100", "10.0.0.55", "8.8.8.8"]:
            return {
                "ipAddress": ip,
                "abuseConfidenceScore": 85,
                "vt_engines_flagged": 4,
                "tags": ["malware", "c2"]
            }
        return {
            "ipAddress": ip,
            "abuseConfidenceScore": 0,
            "vt_engines_flagged": 0,
            "tags": []
        }
