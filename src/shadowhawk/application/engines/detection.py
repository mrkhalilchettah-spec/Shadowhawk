"""
ML-powered Detection Logic Engine for ShadowHawk Platform.

Copyright (c) 2024 ShadowHawk Team
SPDX-License-Identifier: MIT
"""

import logging
from typing import Any, Dict, List, Optional

import numpy as np

from shadowhawk.core.config.settings import settings
from shadowhawk.core.utils.metrics import PerformanceTracker, timed_prediction
from shadowhawk.ml.inference.engine import InferenceEngine

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    ML-powered detection engine with anomaly detection and behavioral analysis.
    
    Uses ensemble ML models to detect threats, anomalies, and suspicious
    behavior patterns in security event data.
    """
    
    ENGINE_NAME = "detection"
    
    def __init__(self):
        self.inference_engine = InferenceEngine()
        self.performance_tracker = PerformanceTracker(self.ENGINE_NAME)
        
        # Detection thresholds
        self.anomaly_threshold = settings.confidence_threshold
        self.behavioral_baseline: Dict[str, Any] = {}
        self.detection_history: List[Dict] = []
    
    def analyze_event(
        self, 
        event: Dict[str, Any],
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Analyze a security event using ML models.
        
        Args:
            event: Security event data
            context: Additional context about the event
        
        Returns:
            Detection result with alerts and confidence scores
        """
        with timed_prediction(self.ENGINE_NAME):
            # Extract features
            features = self._extract_event_features(event)
            
            # Run anomaly detection
            anomaly_result = self._detect_anomaly(features, event)
            
            # Run behavioral analysis
            behavioral_result = self._analyze_behavior(event, context)
            
            # Classify threat type
            classification_result = self._classify_threat(features, event)
            
            # Combine results
            detection_result = self._combine_detections(
                event,
                anomaly_result,
                behavioral_result,
                classification_result
            )
            
            # Store detection
            self.detection_history.append(detection_result)
            
            return detection_result
    
    def analyze_events_batch(
        self, 
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze multiple events in batch."""
        return [self.analyze_event(event) for event in events]
    
    def _extract_event_features(self, event: Dict) -> np.ndarray:
        """Extract features from a security event."""
        # Numeric features
        features = [
            event.get("severity", 5) / 10.0,
            event.get("confidence", 0.5),
            hash(event.get("source_ip", "")) % 1000 / 1000.0,
            hash(event.get("dest_ip", "")) % 1000 / 1000.0,
            hash(event.get("user", "")) % 1000 / 1000.0,
            len(event.get("indicators", [])),
            len(event.get("affected_assets", [])),
        ]
        
        return np.array(features)
    
    def _detect_anomaly(
        self, 
        features: np.ndarray, 
        event: Dict
    ) -> Dict:
        """Detect anomalies in the event."""
        try:
            # Use inference engine for anomaly detection
            anomalies = self.inference_engine.detect_anomalies(
                features.reshape(1, -1),
                threshold=self.anomaly_threshold
            )
            
            if anomalies:
                anomaly = anomalies[0]
                return {
                    "is_anomaly": True,
                    "anomaly_score": anomaly.get("anomaly_score", 0.0),
                    "confidence": anomaly.get("confidence", 0.0),
                    "severity": anomaly.get("severity", "low"),
                }
            else:
                return {
                    "is_anomaly": False,
                    "anomaly_score": 0.0,
                    "confidence": 1.0,
                    "severity": "none",
                }
        
        except Exception as e:
            logger.warning(f"Anomaly detection failed: {e}")
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "error": str(e),
            }
    
    def _analyze_behavior(
        self, 
        event: Dict, 
        context: Optional[Dict]
    ) -> Dict:
        """Analyze behavioral patterns."""
        user = event.get("user", "unknown")
        source_ip = event.get("source_ip", "unknown")
        
        # Check against behavioral baseline
        baseline = self.behavioral_baseline.get(user, {})
        
        anomalies = []
        
        # Check for unusual time of activity
        if "time_profile" in baseline:
            event_time = event.get("timestamp")
            if event_time and not self._is_normal_time(event_time, baseline["time_profile"]):
                anomalies.append("unusual_time_of_activity")
        
        # Check for unusual location/source
        if "common_sources" in baseline:
            if source_ip not in baseline["common_sources"]:
                anomalies.append("unusual_source_location")
        
        # Check for unusual volume
        if "volume_profile" in baseline:
            event_volume = event.get("data_volume", 0)
            if not self._is_normal_volume(event_volume, baseline["volume_profile"]):
                anomalies.append("unusual_data_volume")
        
        # Calculate behavioral score
        behavioral_score = min(len(anomalies) * 0.25, 1.0)
        
        return {
            "behavioral_score": behavioral_score,
            "anomalies_detected": anomalies,
            "confidence": 0.7 + (0.2 * behavioral_score),
            "is_deviant": len(anomalies) > 0,
        }
    
    def _is_normal_time(
        self, 
        timestamp: Any, 
        time_profile: Dict
    ) -> bool:
        """Check if timestamp is within normal time profile."""
        import pandas as pd
        
        hour = pd.to_datetime(timestamp).hour
        normal_hours = time_profile.get("active_hours", list(range(9, 18)))
        
        return hour in normal_hours
    
    def _is_normal_volume(
        self, 
        volume: float, 
        volume_profile: Dict
    ) -> bool:
        """Check if volume is within normal range."""
        mean = volume_profile.get("mean", volume)
        std = volume_profile.get("std", 1.0)
        
        # Within 3 standard deviations is normal
        return abs(volume - mean) <= (3 * std)
    
    def _classify_threat(
        self, 
        features: np.ndarray, 
        event: Dict
    ) -> Dict:
        """Classify the threat type."""
        try:
            # Get event description for text features
            description = event.get("description", "")
            
            # Use inference engine for classification
            classifications = self.inference_engine.classify_threats(
                features.reshape(1, -1),
                [description] if description else None,
                top_k=3
            )
            
            if classifications:
                classification = classifications[0]
                return {
                    "threat_class": classification.get("predicted_class", "unknown"),
                    "confidence": classification.get("confidence", 0.0),
                    "top_predictions": classification.get("top_predictions", []),
                    "is_high_confidence": classification.get("is_high_confidence", False),
                }
            else:
                return {
                    "threat_class": "unknown",
                    "confidence": 0.0,
                    "top_predictions": [],
                    "is_high_confidence": False,
                }
        
        except Exception as e:
            logger.warning(f"Threat classification failed: {e}")
            return {
                "threat_class": "unknown",
                "confidence": 0.0,
                "error": str(e),
            }
    
    def _combine_detections(
        self,
        event: Dict,
        anomaly: Dict,
        behavioral: Dict,
        classification: Dict
    ) -> Dict:
        """Combine detection results into a unified alert."""
        # Calculate overall threat score
        scores = []
        
        if anomaly.get("is_anomaly"):
            scores.append(anomaly.get("anomaly_score", 0) * anomaly.get("confidence", 0))
        
        if behavioral.get("is_deviant"):
            scores.append(behavioral.get("behavioral_score", 0) * behavioral.get("confidence", 0))
        
        if classification.get("is_high_confidence"):
            scores.append(classification.get("confidence", 0))
        
        overall_score = max(scores) if scores else 0.0
        
        # Determine alert level
        alert_level = self._score_to_alert_level(overall_score)
        
        # Generate alert
        detection = {
            "event_id": event.get("id", "unknown"),
            "timestamp": event.get("timestamp"),
            "alert_level": alert_level,
            "overall_confidence": overall_score,
            "anomaly_detection": anomaly,
            "behavioral_analysis": behavioral,
            "threat_classification": classification,
            "requires_investigation": overall_score >= self.anomaly_threshold,
            "indicators": event.get("indicators", []),
        }
        
        return detection
    
    def _score_to_alert_level(self, score: float) -> str:
        """Convert threat score to alert level."""
        if score >= 0.9:
            return "critical"
        elif score >= 0.75:
            return "high"
        elif score >= 0.5:
            return "medium"
        elif score >= 0.25:
            return "low"
        return "info"
    
    def update_baseline(
        self, 
        user: str, 
        events: List[Dict]
    ) -> None:
        """Update behavioral baseline for a user."""
        import pandas as pd
        
        if not events:
            return
        
        # Extract time profile
        timestamps = [pd.to_datetime(e.get("timestamp")) for e in events if e.get("timestamp")]
        if timestamps:
            hours = [t.hour for t in timestamps]
            hour_counts = {}
            for h in hours:
                hour_counts[h] = hour_counts.get(h, 0) + 1
            
            # Most active hours
            sorted_hours = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)
            active_hours = [h[0] for h in sorted_hours[:8]]  # Top 8 hours
        else:
            active_hours = list(range(9, 18))
        
        # Extract source profile
        sources = [e.get("source_ip") for e in events if e.get("source_ip")]
        source_counts = {}
        for s in sources:
            source_counts[s] = source_counts.get(s, 0) + 1
        
        # Most common sources (80% of activity)
        sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
        total = sum(s[1] for s in sorted_sources)
        cumulative = 0
        common_sources = []
        for s in sorted_sources:
            common_sources.append(s[0])
            cumulative += s[1]
            if cumulative / total >= 0.8:
                break
        
        # Volume profile
        volumes = [e.get("data_volume", 0) for e in events]
        if volumes:
            volume_profile = {
                "mean": np.mean(volumes),
                "std": np.std(volumes),
            }
        else:
            volume_profile = {"mean": 0, "std": 1}
        
        # Store baseline
        self.behavioral_baseline[user] = {
            "time_profile": {"active_hours": active_hours},
            "common_sources": common_sources,
            "volume_profile": volume_profile,
        }
    
    def get_detection_stats(self) -> Dict:
        """Get detection statistics."""
        if not self.detection_history:
            return {"total_detections": 0}
        
        total = len(self.detection_history)
        critical = sum(1 for d in self.detection_history if d["alert_level"] == "critical")
        high = sum(1 for d in self.detection_history if d["alert_level"] == "high")
        anomalies = sum(1 for d in self.detection_history if d["anomaly_detection"]["is_anomaly"])
        
        return {
            "total_detections": total,
            "critical_alerts": critical,
            "high_alerts": high,
            "anomalies_detected": anomalies,
            "average_confidence": np.mean([d["overall_confidence"] for d in self.detection_history]),
        }
