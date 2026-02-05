"""
ML-powered MITRE ATT&CK Mapping Engine for ShadowHawk Platform.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import logging
from typing import Any, Dict, List, Optional, Set

from shadowhawk.core.config.settings import settings
from shadowhawk.core.utils.metrics import PerformanceTracker, timed_prediction
from shadowhawk.ml.inference.engine import InferenceEngine

logger = logging.getLogger(__name__)


class MitreMappingEngine:
    """
    ML-powered MITRE ATT&CK technique mapping engine.
    
    Uses NLP models to automatically extract and map security events
    to MITRE ATT&CK techniques with confidence scoring.
    """
    
    ENGINE_NAME = "mitre_mapping"
    
    # Technique metadata cache
    TECHNIQUE_METADATA = {
        "T1003": {
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "description": "Adversaries may attempt to dump credentials",
        },
        "T1055": {
            "name": "Process Injection",
            "tactic": "Defense Evasion",
            "description": "Adversaries may inject code into processes",
        },
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "Adversaries may abuse command and script interpreters",
        },
        "T1071": {
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "description": "Adversaries may communicate using application layer protocols",
        },
        "T1083": {
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "description": "Adversaries may enumerate files and directories",
        },
        "T1105": {
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "description": "Adversaries may transfer tools or files from an external system",
        },
        "T1110": {
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Adversaries may use brute force techniques",
        },
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": "Adversaries may attempt to exploit a vulnerability",
        },
        "T1204": {
            "name": "User Execution",
            "tactic": "Execution",
            "description": "Adversaries may rely on user interaction",
        },
        "T1547": {
            "name": "Boot or Logon Autostart Execution",
            "tactic": "Persistence",
            "description": "Adversaries may configure system settings",
        },
        "T1557": {
            "name": "Man-in-the-Middle",
            "tactic": "Credential Access",
            "description": "Adversaries may attempt to position themselves",
        },
        "T1566": {
            "name": "Phishing",
            "tactic": "Initial Access",
            "description": "Adversaries may send phishing messages",
        },
        "T1567": {
            "name": "Exfiltration Over Web Service",
            "tactic": "Exfiltration",
            "description": "Adversaries may exfiltrate data over web services",
        },
        "T1574": {
            "name": "Hijack Execution Flow",
            "tactic": "Persistence",
            "description": "Adversaries may execute their own malicious payloads",
        },
    }
    
    def __init__(self):
        self.inference_engine = InferenceEngine()
        self.performance_tracker = PerformanceTracker(self.ENGINE_NAME)
        
        # Technique statistics
        self.technique_frequency: Dict[str, int] = {}
        self.mapping_history: List[Dict] = []
    
    def map_event(
        self, 
        event: Dict[str, Any],
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Map a security event to MITRE ATT&CK techniques.
        
        Args:
            event: Security event data
            context: Additional context for mapping
        
        Returns:
            Mapping result with techniques and confidence scores
        """
        with timed_prediction(self.ENGINE_NAME):
            # Extract text from event
            event_text = self._extract_event_text(event)
            
            # Extract techniques using ML
            ml_techniques = self._extract_ml_techniques(event_text)
            
            # Rule-based extraction as supplement
            rule_techniques = self._extract_rule_based_techniques(event, context)
            
            # Merge and rank techniques
            techniques = self._merge_techniques(ml_techniques, rule_techniques)
            
            # Build tactic coverage
            tactic_coverage = self._build_tactic_coverage(techniques)
            
            # Build mapping result
            mapping = {
                "event_id": event.get("id", "unknown"),
                "techniques": techniques,
                "primary_technique": techniques[0] if techniques else None,
                "tactic_coverage": tactic_coverage,
                "confidence_score": self._calculate_confidence(techniques),
                "mapping_quality": self._assess_mapping_quality(techniques),
            }
            
            # Update statistics
            self._update_statistics(techniques)
            self.mapping_history.append(mapping)
            
            return mapping
    
    def map_events_batch(
        self, 
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Map multiple events to MITRE ATT&CK techniques."""
        return [self.map_event(event) for event in events]
    
    def _extract_event_text(self, event: Dict) -> str:
        """Extract descriptive text from event."""
        text_parts = []
        
        # Description
        if event.get("description"):
            text_parts.append(event["description"])
        
        # Event type and category
        if event.get("type"):
            text_parts.append(event["type"])
        if event.get("category"):
            text_parts.append(event["category"])
        
        # Alert details
        if event.get("alert"):
            text_parts.append(str(event["alert"]))
        
        # Indicators
        if event.get("indicators"):
            for indicator in event["indicators"]:
                if isinstance(indicator, dict):
                    text_parts.append(indicator.get("description", ""))
                    text_parts.append(indicator.get("type", ""))
        
        return " ".join(filter(None, text_parts))
    
    def _extract_ml_techniques(self, text: str) -> List[Dict]:
        """Extract techniques using ML NLP models."""
        try:
            techniques = self.inference_engine.extract_techniques(
                text,
                min_confidence=0.4
            )
            
            # Enrich with metadata
            enriched = []
            for tech in techniques:
                tech_id = tech["technique_id"]
                metadata = self.TECHNIQUE_METADATA.get(tech_id, {})
                
                enriched.append({
                    "technique_id": tech_id,
                    "name": metadata.get("name", tech_id),
                    "tactic": metadata.get("tactic", "Unknown"),
                    "confidence": tech["confidence"],
                    "source": tech.get("source", "ml"),
                    "context": tech.get("context", ""),
                })
            
            return enriched
        
        except Exception as e:
            logger.warning(f"ML technique extraction failed: {e}")
            return []
    
    def _extract_rule_based_techniques(
        self, 
        event: Dict, 
        context: Optional[Dict]
    ) -> List[Dict]:
        """Extract techniques using rule-based matching."""
        techniques = []
        
        # Check event type
        event_type = event.get("type", "").lower()
        event_category = event.get("category", "").lower()
        
        # Map event types to techniques
        type_mapping = {
            "authentication": ["T1110", "T1003", "T1557"],
            "network": ["T1071", "T1105", "T1041"],
            "file": ["T1083", "T1567", "T1005"],
            "process": ["T1055", "T1059", "T1204"],
            "email": ["T1566", "T1204"],
            "web": ["T1190", "T1071"],
            "malware": ["T1055", "T1204", "T1547"],
        }
        
        matched_techniques = type_mapping.get(event_type, [])
        
        for tech_id in matched_techniques:
            metadata = self.TECHNIQUE_METADATA.get(tech_id, {})
            techniques.append({
                "technique_id": tech_id,
                "name": metadata.get("name", tech_id),
                "tactic": metadata.get("tactic", "Unknown"),
                "confidence": 0.5,  # Lower confidence for rule-based
                "source": "rule",
                "context": f"Matched event type: {event_type}",
            })
        
        # Check indicators
        indicators = event.get("indicators", [])
        for indicator in indicators:
            indicator_type = indicator.get("type", "").lower()
            
            indicator_mapping = {
                "credential": ["T1003", "T1110"],
                "malware": ["T1204", "T1055"],
                "suspicious_process": ["T1059", "T1055"],
                "network_connection": ["T1071", "T1105"],
                "file_modification": ["T1083", "T1565"],
            }
            
            matched = indicator_mapping.get(indicator_type, [])
            for tech_id in matched:
                if tech_id not in [t["technique_id"] for t in techniques]:
                    metadata = self.TECHNIQUE_METADATA.get(tech_id, {})
                    techniques.append({
                        "technique_id": tech_id,
                        "name": metadata.get("name", tech_id),
                        "tactic": metadata.get("tactic", "Unknown"),
                        "confidence": 0.45,
                        "source": "indicator",
                        "context": f"Matched indicator: {indicator_type}",
                    })
        
        return techniques
    
    def _merge_techniques(
        self, 
        ml_techniques: List[Dict], 
        rule_techniques: List[Dict]
    ) -> List[Dict]:
        """Merge techniques from different sources."""
        merged = {}
        
        # Add ML techniques
        for tech in ml_techniques:
            tech_id = tech["technique_id"]
            merged[tech_id] = tech
        
        # Add or boost rule techniques
        for tech in rule_techniques:
            tech_id = tech["technique_id"]
            if tech_id in merged:
                # Boost confidence if both sources agree
                merged[tech_id]["confidence"] = min(
                    merged[tech_id]["confidence"] + 0.15, 0.95
                )
                merged[tech_id]["source"] = "hybrid"
            else:
                merged[tech_id] = tech
        
        # Sort by confidence
        techniques = sorted(merged.values(), key=lambda x: x["confidence"], reverse=True)
        
        # Filter by confidence threshold
        return [t for t in techniques if t["confidence"] >= 0.4]
    
    def _build_tactic_coverage(self, techniques: List[Dict]) -> Dict:
        """Build coverage map of MITRE tactics."""
        tactics: Dict[str, List[str]] = {}
        
        for tech in techniques:
            tactic = tech.get("tactic", "Unknown")
            tech_id = tech["technique_id"]
            
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append(tech_id)
        
        # Calculate coverage metrics
        coverage = {
            "tactics_covered": list(tactics.keys()),
            "tactic_counts": {k: len(v) for k, v in tactics.items()},
            "total_techniques": len(techniques),
            "coverage_score": len(tactics) / 14.0,  # 14 main tactics
        }
        
        return coverage
    
    def _calculate_confidence(self, techniques: List[Dict]) -> float:
        """Calculate overall confidence for the mapping."""
        if not techniques:
            return 0.0
        
        # Average confidence weighted by technique rank
        weights = [1.0 / (i + 1) for i in range(len(techniques))]
        confidences = [t["confidence"] for t in techniques]
        
        weighted_avg = sum(c * w for c, w in zip(confidences, weights)) / sum(weights)
        
        return round(weighted_avg, 3)
    
    def _assess_mapping_quality(self, techniques: List[Dict]) -> str:
        """Assess the quality of the technique mapping."""
        if not techniques:
            return "poor"
        
        high_conf_count = sum(1 for t in techniques if t["confidence"] >= 0.7)
        medium_conf_count = sum(1 for t in techniques if 0.5 <= t["confidence"] < 0.7)
        
        if high_conf_count >= 2:
            return "excellent"
        elif high_conf_count == 1 or medium_conf_count >= 2:
            return "good"
        elif medium_conf_count >= 1:
            return "fair"
        else:
            return "poor"
    
    def _update_statistics(self, techniques: List[Dict]) -> None:
        """Update technique frequency statistics."""
        for tech in techniques:
            tech_id = tech["technique_id"]
            self.technique_frequency[tech_id] = (
                self.technique_frequency.get(tech_id, 0) + 1
            )
    
    def get_technique_statistics(self) -> Dict:
        """Get statistics about technique mappings."""
        total_mappings = len(self.mapping_history)
        
        if not total_mappings:
            return {"total_mappings": 0}
        
        # Calculate coverage
        all_techniques: Set[str] = set()
        for mapping in self.mapping_history:
            for tech in mapping.get("techniques", []):
                all_techniques.add(tech["technique_id"])
        
        # Top techniques
        top_techniques = sorted(
            self.technique_frequency.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            "total_mappings": total_mappings,
            "unique_techniques": len(all_techniques),
            "top_techniques": [
                {"technique_id": t[0], "count": t[1]}
                for t in top_techniques
            ],
            "average_confidence": sum(
                m.get("confidence_score", 0) for m in self.mapping_history
            ) / total_mappings,
        }
    
    def get_related_techniques(self, technique_id: str) -> List[Dict]:
        """Get techniques commonly seen with the given technique."""
        # Count co-occurrences
        co_occurrences: Dict[str, int] = {}
        
        for mapping in self.mapping_history:
            techniques = [t["technique_id"] for t in mapping.get("techniques", [])]
            
            if technique_id in techniques:
                for tech in techniques:
                    if tech != technique_id:
                        co_occurrences[tech] = co_occurrences.get(tech, 0) + 1
        
        # Sort by frequency
        related = sorted(
            co_occurrences.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return [
            {
                "technique_id": t[0],
                "co_occurrence_count": t[1],
                **self.TECHNIQUE_METADATA.get(t[0], {})
            }
            for t in related
        ]
