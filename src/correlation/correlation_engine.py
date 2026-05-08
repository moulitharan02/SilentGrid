"""
Correlation Engine — Phase 2.
Event correlation across hosts and sessions.
Detects lateral movement, port-scan patterns, multi-stage attack chains,
and maps detected behaviors to MITRE ATT&CK tactics and techniques.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from src.utils.logger import get_logger

log = get_logger(__name__)

# Maximum age (seconds) of edges kept in the correlation graph
_EDGE_TTL_SEC = 600

# MITRE ATT&CK Mapping
MITRE_MAPPING = {
    "PORT_SCAN": {"tactic": "TA0043 Reconnaissance", "technique": "T1046 Network Service Discovery"},
    "TRAFFIC_SPIKE": {"tactic": "TA0040 Impact", "technique": "T1498 Network Denial of Service"},
    "BEACONING": {"tactic": "TA0011 Command and Control", "technique": "T1071 Application Layer Protocol"},
    "LATERAL_MOVEMENT": {"tactic": "TA0008 Lateral Movement", "technique": "T1021 Remote Services"},
    "MULTI_STAGE_ATTACK": {"tactic": "Multiple", "technique": "Multiple"},
    "BOTNET_ACTIVITY": {"tactic": "TA0011 Command and Control", "technique": "T1105 Ingress Tool Transfer"},
}

class CorrelationEdge:
    """Directed edge between two hosts in the correlation graph."""

    __slots__ = ("src", "dst", "label", "risk_score", "timestamp")

    def __init__(self, src: str, dst: str, label: str, risk_score: int):
        self.src        = src
        self.dst        = dst
        self.label      = label
        self.risk_score = risk_score
        self.timestamp  = time.monotonic()

    def is_expired(self, ttl: float = _EDGE_TTL_SEC) -> bool:
        return (time.monotonic() - self.timestamp) > ttl


class CorrelationEngine:
    """
    Maintains a time-windowed directed graph of traffic events.
    Provides query methods to detect suspicious multi-hop patterns and attack chains.
    """

    def __init__(self):
        # adjacency list: src_ip → list[CorrelationEdge]
        self._graph: Dict[str, List[CorrelationEdge]] = defaultdict(list)
        # attack chain: src_ip -> list[behavior_labels]
        self.attack_chain: Dict[str, List[str]] = defaultdict(list)
        self._chain_last_seen: Dict[str, float] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def add_event(
        self,
        src_ip: str,
        dst_ip: str,
        label: str,
        risk_score: int,
    ) -> None:
        """Add a detected traffic event as a directed edge in the graph."""
        self._prune()
        edge = CorrelationEdge(src_ip, dst_ip, label, risk_score)
        self._graph[src_ip].append(edge)

    def detect_lateral_movement(self, min_hops: int = 2) -> List[List[str]]:
        """Identify hosts that appear to be performing lateral movement."""
        self._prune()
        chains: List[List[str]] = []
        visited: Set[str] = set()

        for start in list(self._graph.keys()):
            if start in visited:
                continue
            chain = self._dfs_chain(start, visited, depth=0, max_depth=10)
            if len(chain) >= min_hops + 1:
                chains.append(chain)

        if chains:
            log.warning("Lateral movement detected — %d chain(s): %s", len(chains), chains)
        return chains

    def scan_pattern(self, src_ip: str, min_distinct_dsts: int = 10) -> bool:
        """Port-scan / host-scan heuristic."""
        self._prune()
        dsts = {e.dst for e in self._graph.get(src_ip, [])}
        result = len(dsts) >= min_distinct_dsts
        return result

    def correlate(self, flow: Dict[str, Any], behaviors: List[str]) -> Optional[Dict[str, str]]:
        """
        Identify multi-stage attack chains by observing sequence of behaviors.
        Returns a dict containing the attack type and MITRE ATT&CK mapping.
        """
        src = flow.get("src_ip", "0.0.0.0")
        if src == "0.0.0.0" or not behaviors:
            return None

        # Expire old chains
        now = time.monotonic()
        if src in self._chain_last_seen and now - self._chain_last_seen[src] > 3600:
            self.attack_chain[src] = []
            
        self._chain_last_seen[src] = now

        for b in behaviors:
            if b not in self.attack_chain[src]:
                self.attack_chain[src].append(b)

        chain = self.attack_chain[src]
        attack_type = None

        # Multi-stage attack signatures
        if "PORT_SCAN" in chain and "TRAFFIC_SPIKE" in chain:
            attack_type = "MULTI_STAGE_ATTACK"

        elif "BEACONING" in chain and "PORT_SCAN" in chain:
            attack_type = "BOTNET_ACTIVITY"

        if attack_type:
            log.warning("%s detected for %s. Chain: %s", attack_type, src, chain)
            mitre_info = MITRE_MAPPING.get(attack_type, {"tactic": "Unknown", "technique": "Unknown"})
            return {
                "attack_type": attack_type,
                "mitre_tactic": mitre_info["tactic"],
                "mitre_technique": mitre_info["technique"]
            }

        return None

    def get_mitre_mapping(self, behavior: str) -> Dict[str, str]:
        """Get MITRE ATT&CK mapping for a single behavior."""
        return MITRE_MAPPING.get(behavior, {"tactic": "Unknown", "technique": "Unknown"})

    def adjacency_summary(self) -> Dict[str, List[dict]]:
        """Return a serialisable snapshot of the correlation graph."""
        self._prune()
        return {
            src: [
                {
                    "dst": e.dst,
                    "label": e.label,
                    "risk_score": e.risk_score,
                    "age_sec": round(time.monotonic() - e.timestamp, 1),
                }
                for e in edges
            ]
            for src, edges in self._graph.items()
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _prune(self) -> None:
        """Remove expired edges from the graph."""
        for src in list(self._graph.keys()):
            self._graph[src] = [e for e in self._graph[src] if not e.is_expired()]
            if not self._graph[src]:
                del self._graph[src]

    def _dfs_chain(
        self, node: str, visited: Set[str], depth: int, max_depth: int
    ) -> List[str]:
        if depth >= max_depth or node in visited:
            return [node]
        visited.add(node)
        chain = [node]
        for edge in self._graph.get(node, []):
            if edge.dst not in visited:
                chain += self._dfs_chain(edge.dst, visited, depth + 1, max_depth)
                break  # follow first unvisited neighbour only
        return chain
