"""
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

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
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
