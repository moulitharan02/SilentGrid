"""
Graph Intelligence Engine — Phase 2.
Builds an IP-to-IP communication graph, detects Command & Control servers
using PageRank, and identifies attacker infrastructure using Community Detection.
"""

from __future__ import annotations

import time
import networkx as nx
from typing import Dict, Any, List, Tuple, Set
from src.utils.logger import get_logger

log = get_logger(__name__)

class GraphEngine:
    def __init__(self, max_nodes: int = 2000):
        self.G = nx.DiGraph()
        self.max_nodes = max_nodes
        self._last_prune = time.time()
        self._last_community_eval = time.time()
        self._communities: List[Set[str]] = []

    def update_graph(self, flow: Dict[str, Any]) -> None:
        """Add an edge to the graph for a communication flow."""
        src = flow.get("src_ip", "0.0.0.0")
        dst = flow.get("dst_ip", "0.0.0.0")

        if src == dst:
            return

        for node in (src, dst):
            if not self.G.has_node(node):
                self.G.add_node(node, last_seen=time.time())
            else:
                self.G.nodes[node]['last_seen'] = time.time()

        if self.G.has_edge(src, dst):
            self.G[src][dst]["weight"] += 1
            self.G[src][dst]["last_seen"] = time.time()
        else:
            self.G.add_edge(src, dst, weight=1, last_seen=time.time())

        # Periodically prune the graph to avoid unbounded memory growth
        if time.time() - self._last_prune > 60:
            self._prune()
            
        # Periodically evaluate communities (expensive, do every 5 mins)
        if time.time() - self._last_community_eval > 300:
            self._detect_communities()

    def detect_c2(self, threshold: float = 0.05) -> List[Tuple[str, float]]:
        """
        Detect potential Command & Control servers using PageRank centrality.
        PageRank helps identify nodes that many other active nodes talk to.
        """
        if self.G.number_of_nodes() < 3:
            return []

        try:
            # Calculate PageRank
            pr = nx.pagerank(self.G, weight='weight')
            
            suspicious = []
            for node, score in pr.items():
                if score > threshold:
                    suspicious.append((node, score))
                    
            if suspicious:
                log.warning("Detected %d potential C2 node(s) based on PageRank.", len(suspicious))
                
            return suspicious
        except Exception as e:
            log.error("PageRank calculation failed: %s", e)
            return []

    def _detect_communities(self) -> None:
        """
        Identify distinct groups of communicating nodes using the Louvain method.
        Useful for identifying botnets or segregated attacker infrastructure.
        Requires undirected graph.
        """
        self._last_community_eval = time.time()
        if self.G.number_of_nodes() < 5:
            return
            
        try:
            # Convert to undirected for community detection
            undirected_G = self.G.to_undirected(as_view=True)
            communities = list(nx.community.louvain_communities(undirected_G, weight='weight'))
            self._communities = communities
            log.debug("Detected %d communities in the traffic graph.", len(communities))
        except Exception as e:
            log.error("Community detection failed: %s", e)

    def _prune(self, max_age: float = 600) -> None:
        """Remove old nodes and edges to keep graph size manageable."""
        self._last_prune = time.time()
        now = time.time()
        
        # Prune old edges
        edges_to_remove = []
        for u, v, data in self.G.edges(data=True):
            if now - data.get('last_seen', 0) > max_age:
                edges_to_remove.append((u, v))
        self.G.remove_edges_from(edges_to_remove)

        # Prune isolated or old nodes
        nodes_to_remove = []
        for node, data in self.G.nodes(data=True):
            if now - data.get('last_seen', 0) > max_age:
                nodes_to_remove.append(node)
                continue
            if self.G.degree(node) == 0:
                nodes_to_remove.append(node)
                
        self.G.remove_nodes_from(nodes_to_remove)
        
        # If still too large, sort by last_seen and remove oldest
        if self.G.number_of_nodes() > self.max_nodes:
            sorted_nodes = sorted(self.G.nodes(data=True), key=lambda x: x[1].get('last_seen', 0))
            nodes_to_remove = [n[0] for n in sorted_nodes[:self.G.number_of_nodes() - self.max_nodes]]
            self.G.remove_nodes_from(nodes_to_remove)
