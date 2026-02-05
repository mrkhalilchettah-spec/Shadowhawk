"""
ML-powered Correlation Engine for ShadowHawk Platform.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import logging
from typing import Any, Dict, List, Optional, Set

import networkx as nx
import numpy as np

from shadowhawk.core.config.settings import settings
from shadowhawk.core.utils.metrics import PerformanceTracker, timed_prediction
from shadowhawk.ml.inference.engine import InferenceEngine

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    ML-powered correlation engine with graph-based analysis.
    
    Correlates security events to identify multi-stage attacks,
    attack campaigns, and advanced persistent threats (APTs).
    """
    
    ENGINE_NAME = "correlation"
    
    def __init__(self):
        self.inference_engine = InferenceEngine()
        self.performance_tracker = PerformanceTracker(self.ENGINE_NAME)
        
        # Event storage and graph
        self.events: Dict[str, Dict] = {}
        self.correlation_graph = nx.Graph()
        
        # Campaign detection
        self.campaigns: List[Dict] = []
        self.correlation_threshold = 0.7
    
    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the correlation engine."""
        event_id = event.get("id", str(hash(str(event))))
        self.events[event_id] = event
        
        # Add to graph
        self.correlation_graph.add_node(
            event_id,
            timestamp=event.get("timestamp"),
            severity=event.get("severity", 0),
            event_type=event.get("type", "unknown"),
        )
    
    def correlate(
        self, 
        event_ids: Optional[List[str]] = None,
        time_window_hours: Optional[int] = 24
    ) -> Dict[str, Any]:
        """
        Correlate events to identify related activities.
        
        Args:
            event_ids: Optional list of specific event IDs to correlate
            time_window_hours: Time window for correlation analysis
        
        Returns:
            Correlation results with campaigns and related events
        """
        with timed_prediction(self.ENGINE_NAME):
            # Get events to correlate
            if event_ids:
                events = {eid: self.events[eid] for eid in event_ids if eid in self.events}
            else:
                events = self.events
            
            # Build correlation graph
            self._build_correlation_graph(events)
            
            # Find related events
            related_events = self._find_related_events(events)
            
            # Detect campaigns
            campaigns = self._detect_campaigns()
            
            # Find attack chains
            attack_chains = self._find_attack_chains(events)
            
            # Compile results
            result = {
                "total_events_analyzed": len(events),
                "correlation_pairs": len(self.correlation_graph.edges),
                "related_event_groups": related_events,
                "detected_campaigns": campaigns,
                "attack_chains": attack_chains,
                "correlation_confidence": self._calculate_correlation_confidence(),
            }
            
            return result
    
    def _build_correlation_graph(self, events: Dict[str, Dict]) -> None:
        """Build correlation graph from events."""
        event_ids = list(events.keys())
        
        # Calculate pairwise correlations
        for i, event_id_i in enumerate(event_ids):
            for j in range(i + 1, len(event_ids)):
                event_id_j = event_ids[j]
                
                correlation_score = self._calculate_event_correlation(
                    events[event_id_i],
                    events[event_id_j]
                )
                
                if correlation_score >= self.correlation_threshold:
                    self.correlation_graph.add_edge(
                        event_id_i,
                        event_id_j,
                        weight=correlation_score
                    )
    
    def _calculate_event_correlation(
        self, 
        event1: Dict, 
        event2: Dict
    ) -> float:
        """Calculate correlation score between two events."""
        scores = []
        
        # Temporal correlation
        time_score = self._temporal_correlation(event1, event2)
        if time_score > 0:
            scores.append(time_score * 0.25)
        
        # Entity correlation (IP, user, etc.)
        entity_score = self._entity_correlation(event1, event2)
        if entity_score > 0:
            scores.append(entity_score * 0.35)
        
        # Type correlation
        type_score = self._type_correlation(event1, event2)
        if type_score > 0:
            scores.append(type_score * 0.20)
        
        # Technique correlation (MITRE)
        technique_score = self._technique_correlation(event1, event2)
        if technique_score > 0:
            scores.append(technique_score * 0.20)
        
        return sum(scores) if scores else 0.0
    
    def _temporal_correlation(
        self, 
        event1: Dict, 
        event2: Dict
    ) -> float:
        """Calculate temporal correlation between events."""
        from datetime import datetime
        
        ts1 = event1.get("timestamp")
        ts2 = event2.get("timestamp")
        
        if not ts1 or not ts2:
            return 0.0
        
        try:
            t1 = datetime.fromisoformat(str(ts1).replace('Z', '+00:00'))
            t2 = datetime.fromisoformat(str(ts2).replace('Z', '+00:00'))
            
            time_diff_hours = abs((t2 - t1).total_seconds()) / 3600
            
            # Exponential decay based on time difference
            if time_diff_hours <= 1:
                return 1.0
            elif time_diff_hours <= 24:
                return 0.8
            elif time_diff_hours <= 72:
                return 0.5
            elif time_diff_hours <= 168:  # 1 week
                return 0.3
            else:
                return 0.0
        
        except (ValueError, TypeError):
            return 0.0
    
    def _entity_correlation(
        self, 
        event1: Dict, 
        event2: Dict
    ) -> float:
        """Calculate entity correlation between events."""
        entities1 = self._extract_entities(event1)
        entities2 = self._extract_entities(event2)
        
        if not entities1 or not entities2:
            return 0.0
        
        # Jaccard similarity
        intersection = len(entities1 & entities2)
        union = len(entities1 | entities2)
        
        if union == 0:
            return 0.0
        
        jaccard = intersection / union
        
        # Boost if there are multiple shared entities
        if intersection >= 2:
            jaccard *= 1.2
        
        return min(jaccard, 1.0)
    
    def _extract_entities(self, event: Dict) -> Set[str]:
        """Extract entities from an event."""
        entities = set()
        
        # IPs
        if event.get("source_ip"):
            entities.add(f"ip:{event['source_ip']}")
        if event.get("dest_ip"):
            entities.add(f"ip:{event['dest_ip']}")
        
        # Users
        if event.get("user"):
            entities.add(f"user:{event['user']}")
        
        # Hosts
        if event.get("source_host"):
            entities.add(f"host:{event['source_host']}")
        if event.get("dest_host"):
            entities.add(f"host:{event['dest_host']}")
        
        # Processes
        if event.get("process"):
            entities.add(f"proc:{event['process']}")
        
        # Files
        if event.get("file"):
            entities.add(f"file:{event['file']}")
        
        return entities
    
    def _type_correlation(
        self, 
        event1: Dict, 
        event2: Dict
    ) -> float:
        """Calculate correlation based on event types."""
        type1 = event1.get("type", "unknown")
        type2 = event2.get("type", "unknown")
        
        if type1 == type2:
            return 0.8
        
        # Define related types
        related_types = {
            "network": ["authentication", "file"],
            "authentication": ["network", "process"],
            "file": ["network", "process"],
            "process": ["file", "authentication"],
            "malware": ["process", "file", "network"],
        }
        
        if type2 in related_types.get(type1, []):
            return 0.5
        
        return 0.0
    
    def _technique_correlation(
        self, 
        event1: Dict, 
        event2: Dict
    ) -> float:
        """Calculate correlation based on MITRE techniques."""
        techniques1 = set(event1.get("mitre_techniques", []))
        techniques2 = set(event2.get("mitre_techniques", []))
        
        if not techniques1 or not techniques2:
            return 0.0
        
        # Jaccard similarity
        intersection = len(techniques1 & techniques2)
        union = len(techniques1 | techniques2)
        
        if union == 0:
            return 0.0
        
        return intersection / union
    
    def _find_related_events(
        self, 
        events: Dict[str, Dict]
    ) -> List[Dict]:
        """Find groups of related events."""
        # Get connected components
        components = list(nx.connected_components(self.correlation_graph))
        
        related_groups = []
        for component in components:
            if len(component) >= 2:
                # Get subgraph for this component
                subgraph = self.correlation_graph.subgraph(component)
                
                # Calculate group metrics
                avg_weight = sum(
                    d["weight"] for _, _, d in subgraph.edges(data=True)
                ) / subgraph.number_of_edges() if subgraph.number_of_edges() > 0 else 0
                
                related_groups.append({
                    "event_ids": list(component),
                    "event_count": len(component),
                    "average_correlation": round(avg_weight, 3),
                    "confidence": min(avg_weight + 0.2, 0.95),
                })
        
        # Sort by size and correlation
        related_groups.sort(
            key=lambda x: (x["event_count"], x["average_correlation"]),
            reverse=True
        )
        
        return related_groups
    
    def _detect_campaigns(self) -> List[Dict]:
        """Detect attack campaigns from correlated events."""
        campaigns = []
        
        # Get connected components as potential campaigns
        components = list(nx.connected_components(self.correlation_graph))
        
        for idx, component in enumerate(components):
            if len(component) < 3:  # Need at least 3 events
                continue
            
            subgraph = self.correlation_graph.subgraph(component)
            
            # Calculate campaign metrics
            density = nx.density(subgraph)
            
            # Get event timestamps
            timestamps = [
                self.events[eid].get("timestamp")
                for eid in component
                if eid in self.events
            ]
            
            # Calculate duration
            duration = self._calculate_duration(timestamps)
            
            # Determine campaign type
            campaign_type = self._classify_campaign_type(subgraph, component)
            
            campaign = {
                "campaign_id": f"campaign_{idx + 1}",
                "event_count": len(component),
                "event_ids": list(component),
                "density": round(density, 3),
                "duration_hours": duration,
                "campaign_type": campaign_type,
                "confidence": round(min(density + 0.3, 0.9), 3),
                "key_events": self._identify_key_events(subgraph, component),
            }
            
            campaigns.append(campaign)
        
        # Sort by confidence
        campaigns.sort(key=lambda x: x["confidence"], reverse=True)
        
        return campaigns
    
    def _calculate_duration(self, timestamps: List) -> Optional[float]:
        """Calculate duration in hours from timestamps."""
        from datetime import datetime
        
        if not timestamps:
            return None
        
        try:
            parsed = []
            for ts in timestamps:
                try:
                    parsed.append(datetime.fromisoformat(str(ts).replace('Z', '+00:00')))
                except (ValueError, TypeError):
                    continue
            
            if not parsed:
                return None
            
            duration = (max(parsed) - min(parsed)).total_seconds() / 3600
            return round(duration, 2)
        
        except Exception:
            return None
    
    def _classify_campaign_type(
        self, 
        subgraph: nx.Graph, 
        component: Set[str]
    ) -> str:
        """Classify the type of campaign."""
        density = nx.density(subgraph)
        
        if density > 0.8:
            return "coordinated_attack"
        elif density > 0.5:
            return "distributed_attack"
        elif nx.is_tree(subgraph):
            return "sequential_attack"
        elif len(component) > 10:
            return "apt_campaign"
        else:
            return "opportunistic_attack"
    
    def _identify_key_events(
        self, 
        subgraph: nx.Graph, 
        component: Set[str]
    ) -> List[str]:
        """Identify key events in a campaign."""
        # Use degree centrality
        centrality = nx.degree_centrality(subgraph)
        
        # Sort by centrality
        sorted_events = sorted(
            centrality.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Return top 5
        return [e[0] for e in sorted_events[:5]]
    
    def _find_attack_chains(self, events: Dict[str, Dict]) -> List[Dict]:
        """Find attack chains (sequences of related events)."""
        chains = []
        
        # Find paths in the correlation graph
        for source in events:
            for target in events:
                if source != target:
                    try:
                        paths = list(nx.all_simple_paths(
                            self.correlation_graph,
                            source,
                            target,
                            cutoff=5
                        ))
                        
                        for path in paths:
                            if len(path) >= 3:  # At least 3 events in chain
                                chain = {
                                    "chain_id": f"chain_{len(chains) + 1}",
                                    "events": path,
                                    "length": len(path),
                                    "entry_point": path[0],
                                    "exit_point": path[-1],
                                }
                                chains.append(chain)
                    
                    except nx.NetworkXNoPath:
                        continue
        
        # Sort by length
        chains.sort(key=lambda x: x["length"], reverse=True)
        
        return chains[:10]  # Return top 10
    
    def _calculate_correlation_confidence(self) -> float:
        """Calculate overall confidence for correlation results."""
        if not self.correlation_graph.edges:
            return 0.0
        
        # Average edge weight
        weights = [d["weight"] for _, _, d in self.correlation_graph.edges(data=True)]
        avg_weight = sum(weights) / len(weights)
        
        # Confidence based on graph density and average weight
        density = nx.density(self.correlation_graph)
        
        confidence = (avg_weight * 0.6) + (density * 0.4)
        
        return round(min(confidence, 0.95), 3)
    
    def get_event_correlations(self, event_id: str) -> List[Dict]:
        """Get all correlations for a specific event."""
        if event_id not in self.correlation_graph:
            return []
        
        correlations = []
        for neighbor in self.correlation_graph.neighbors(event_id):
            edge_data = self.correlation_graph.get_edge_data(event_id, neighbor)
            correlations.append({
                "event_id": neighbor,
                "correlation_score": edge_data.get("weight", 0),
                "event_summary": self.events.get(neighbor, {}),
            })
        
        # Sort by correlation score
        correlations.sort(key=lambda x: x["correlation_score"], reverse=True)
        
        return correlations
