"""
 cto-task-goaldesign-and-implement-the-initial-architecture-and-core-m
ShadowHawk Platform - Correlation Engine

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import List, Dict, Any, Set, Optional
from datetime import datetime, timedelta
from uuid import UUID
import logging

from ...domain.models.detection import Detection

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
 main

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
 cto-task-goaldesign-and-implement-the-initial-architecture-and-core-m
    Correlation Engine for event correlation.
    
    Correlates security events across time and tools to identify patterns.
    """
    
    def __init__(self, time_window_seconds: int = 300):
        """
        Initialize the correlation engine.
        
        Args:
            time_window_seconds: Time window for correlation in seconds (default 5 minutes)
        """
        self.time_window = timedelta(seconds=time_window_seconds)
    
    def correlate_by_time(
        self,
        detections: List[Detection],
        time_window: Optional[timedelta] = None
    ) -> List[List[Detection]]:
        """
        Correlate detections within a time window.
        
        Args:
            detections: List of detections to correlate
            time_window: Optional custom time window
            
        Returns:
            List of correlated detection groups
        """
        window = time_window or self.time_window
        
        sorted_detections = sorted(detections, key=lambda d: d.detected_at)
        
        groups = []
        current_group = []
        group_start = None
        
        for detection in sorted_detections:
            if not current_group:
                current_group.append(detection)
                group_start = detection.detected_at
            elif detection.detected_at - group_start <= window:
                current_group.append(detection)
            else:
                if len(current_group) > 1:
                    groups.append(current_group)
                current_group = [detection]
                group_start = detection.detected_at
        
        if len(current_group) > 1:
            groups.append(current_group)
        
        logger.info(f"Found {len(groups)} correlated groups from {len(detections)} detections")
        return groups
    
    def correlate_by_indicators(
        self,
        detections: List[Detection]
    ) -> List[List[Detection]]:
        """
        Correlate detections by shared indicators.
        
        Args:
            detections: List of detections to correlate
            
        Returns:
            List of correlated detection groups
        """
        indicator_map: Dict[str, List[Detection]] = {}
        
        for detection in detections:
            for indicator in detection.indicators:
                if indicator not in indicator_map:
                    indicator_map[indicator] = []
                indicator_map[indicator].append(detection)
        
        groups = []
        processed: Set[UUID] = set()
        
        for detection in detections:
            if detection.id in processed:
                continue
            
            related = self._find_related_by_indicators(
                detection,
                detections,
                indicator_map
            )
            
            if len(related) > 1:
                groups.append(related)
                for d in related:
                    processed.add(d.id)
        
        logger.info(
            f"Found {len(groups)} indicator-based correlations from {len(detections)} detections"
        )
        return groups
    
    def _find_related_by_indicators(
        self,
        detection: Detection,
        all_detections: List[Detection],
        indicator_map: Dict[str, List[Detection]]
    ) -> List[Detection]:
        """Find all detections related by shared indicators."""
        related: Set[UUID] = {detection.id}
        queue = [detection]
        
        while queue:
            current = queue.pop(0)
            
            for indicator in current.indicators:
                for related_detection in indicator_map.get(indicator, []):
                    if related_detection.id not in related:
                        related.add(related_detection.id)
                        queue.append(related_detection)
        
        return [d for d in all_detections if d.id in related]
    
    def correlate_by_source(
        self,
        detections: List[Detection]
    ) -> Dict[str, List[Detection]]:
        """
        Group detections by source.
        
        Args:
            detections: List of detections
            
        Returns:
            Dictionary mapping sources to detections
        """
        source_map: Dict[str, List[Detection]] = {}
        
        for detection in detections:
            source = detection.source or "unknown"
            if source not in source_map:
                source_map[source] = []
            source_map[source].append(detection)
        
        return source_map
    
    def find_attack_chains(
        self,
        detections: List[Detection]
    ) -> List[Dict[str, Any]]:
        """
        Identify potential attack chains from detections.
        
        Args:
            detections: List of detections
            
        Returns:
            List of potential attack chains
        """
        time_groups = self.correlate_by_time(detections)
        
        attack_chains = []
        
        for group in time_groups:
            techniques = set()
            for detection in group:
                techniques.update(detection.mitre_techniques)
            
            if len(techniques) >= 2:
                attack_chain = {
                    "detections": [d.id for d in group],
                    "start_time": min(d.detected_at for d in group),
                    "end_time": max(d.detected_at for d in group),
                    "techniques": sorted(list(techniques)),
                    "severity": self._calculate_chain_severity(group),
                    "indicators": self._extract_chain_indicators(group),
                }
                attack_chains.append(attack_chain)
        
        logger.info(f"Identified {len(attack_chains)} potential attack chains")
        return attack_chains
    
    def _calculate_chain_severity(self, detections: List[Detection]) -> str:
        """Calculate overall severity for an attack chain."""
        severity_weights = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }
        
        max_weight = max(
            severity_weights.get(d.severity, 0) for d in detections
        )
        
        if max_weight >= 4:
            return "critical"
        elif max_weight >= 3:
            return "high"
        elif max_weight >= 2:
            return "medium"
        else:
            return "low"
    
    def _extract_chain_indicators(self, detections: List[Detection]) -> List[str]:
        """Extract unique indicators from a chain of detections."""
        indicators = set()
        for detection in detections:
            indicators.update(detection.indicators)
        return sorted(list(indicators))
    
    def generate_correlation_report(
        self,
        detections: List[Detection]
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive correlation report.
        
        Args:
            detections: List of detections
            
        Returns:
            Correlation report
        """
        time_groups = self.correlate_by_time(detections)
        indicator_groups = self.correlate_by_indicators(detections)
        source_groups = self.correlate_by_source(detections)
        attack_chains = self.find_attack_chains(detections)
        
        return {
            "total_detections": len(detections),
            "time_based_correlations": len(time_groups),
            "indicator_based_correlations": len(indicator_groups),
            "sources": list(source_groups.keys()),
            "attack_chains": len(attack_chains),
            "time_window_seconds": self.time_window.total_seconds(),
            "attack_chain_details": attack_chains,
        }
    
    def update_detection_correlations(
        self,
        detections: List[Detection]
    ) -> None:
        """
        Update detections with correlation information.
        
        Args:
            detections: List of detections to update
        """
        indicator_groups = self.correlate_by_indicators(detections)
        
        for group in indicator_groups:
            detection_ids = [d.id for d in group]
            for detection in group:
                for related_id in detection_ids:
                    if related_id != detection.id:
                        detection.correlate_with(related_id)
        
        logger.info(f"Updated correlation information for {len(detections)} detections")

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
 main
