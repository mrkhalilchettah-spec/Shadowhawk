"""
ShadowHawk Platform - Detection Logic Engine

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import List, Dict, Any, Optional
import re
import logging
from datetime import datetime

from ...domain.models.detection import Detection, DetectionRule, RuleFormat, DetectionStatus

logger = logging.getLogger(__name__)


class DetectionLogicEngine:
    """
    Detection Logic Engine for rule-based security detection.
    
    Supports multiple rule formats and log normalization.
    """
    
    def __init__(self):
        """Initialize the detection logic engine."""
        self.active_rules: List[DetectionRule] = []
    
    def load_rules(self, rules: List[DetectionRule]) -> None:
        """
        Load detection rules into the engine.
        
        Args:
            rules: List of detection rules to load
        """
        self.active_rules = [rule for rule in rules if rule.enabled]
        logger.info(f"Loaded {len(self.active_rules)} active detection rules")
    
    def normalize_log(self, raw_log: Dict[str, Any], source: str) -> Dict[str, Any]:
        """
        Normalize log data to a common format.
        
        Args:
            raw_log: Raw log data
            source: Source of the log (e.g., 'syslog', 'windows', 'firewall')
            
        Returns:
            Normalized log data
        """
        normalized = {
            "timestamp": self._extract_timestamp(raw_log),
            "source": source,
            "event_type": raw_log.get("event_type", "unknown"),
            "severity": raw_log.get("severity", "info"),
            "message": raw_log.get("message", ""),
            "source_ip": self._extract_ip(raw_log, "source"),
            "destination_ip": self._extract_ip(raw_log, "destination"),
            "user": raw_log.get("user") or raw_log.get("username"),
            "process": raw_log.get("process") or raw_log.get("process_name"),
            "command": raw_log.get("command") or raw_log.get("command_line"),
            "file_path": raw_log.get("file_path") or raw_log.get("file"),
            "raw": raw_log,
        }
        
        return {k: v for k, v in normalized.items() if v is not None}
    
    def _extract_timestamp(self, log: Dict[str, Any]) -> str:
        """Extract and normalize timestamp from log."""
        timestamp = log.get("timestamp") or log.get("time") or log.get("@timestamp")
        if timestamp:
            if isinstance(timestamp, datetime):
                return timestamp.isoformat()
            return str(timestamp)
        return datetime.utcnow().isoformat()
    
    def _extract_ip(self, log: Dict[str, Any], ip_type: str) -> Optional[str]:
        """Extract IP address from log."""
        keys = [
            f"{ip_type}_ip",
            f"{ip_type}_addr",
            f"{ip_type}_address",
            f"{ip_type}IP",
        ]
        
        for key in keys:
            value = log.get(key)
            if value:
                return str(value)
        
        return None
    
    def analyze_log(
        self,
        raw_log: Dict[str, Any],
        source: str = "unknown"
    ) -> Optional[Detection]:
        """
        Analyze a log entry against detection rules.
        
        Args:
            raw_log: Raw log data
            source: Source of the log
            
        Returns:
            Detection if a rule matches, None otherwise
        """
        normalized_log = self.normalize_log(raw_log, source)
        
        for rule in self.active_rules:
            if self._check_rule_match(rule, normalized_log):
                return self._create_detection(rule, raw_log, normalized_log)
        
        return None
    
    def _check_rule_match(
        self,
        rule: DetectionRule,
        normalized_log: Dict[str, Any]
    ) -> bool:
        """
        Check if a normalized log matches a detection rule.
        
        Args:
            rule: Detection rule to check
            normalized_log: Normalized log data
            
        Returns:
            True if rule matches, False otherwise
        """
        if rule.rule_format == RuleFormat.CUSTOM:
            return self._check_custom_rule(rule, normalized_log)
        elif rule.rule_format == RuleFormat.SIGMA:
            return self._check_sigma_rule(rule, normalized_log)
        else:
            logger.warning(f"Unsupported rule format: {rule.rule_format}")
            return False
    
    def _check_custom_rule(
        self,
        rule: DetectionRule,
        normalized_log: Dict[str, Any]
    ) -> bool:
        """Check if log matches a custom rule (simplified pattern matching)."""
        patterns = rule.metadata.get("patterns", [])
        
        message = normalized_log.get("message", "")
        command = normalized_log.get("command", "")
        process = normalized_log.get("process", "")
        
        search_text = f"{message} {command} {process}".lower()
        
        for pattern in patterns:
            if isinstance(pattern, str):
                if re.search(pattern.lower(), search_text):
                    return True
        
        return False
    
    def _check_sigma_rule(
        self,
        rule: DetectionRule,
        normalized_log: Dict[str, Any]
    ) -> bool:
        """Check if log matches a Sigma rule (simplified)."""
        return False
    
    def _create_detection(
        self,
        rule: DetectionRule,
        raw_log: Dict[str, Any],
        normalized_log: Dict[str, Any]
    ) -> Detection:
        """Create a detection from a matched rule."""
        detection = Detection(
            rule_id=rule.id,
            title=f"Detection: {rule.name}",
            description=rule.description,
            severity=rule.severity,
            source=normalized_log.get("source", "unknown"),
            raw_log=raw_log,
            normalized_log=normalized_log,
            mitre_techniques=rule.mitre_techniques,
        )
        
        self._extract_indicators(detection, normalized_log)
        
        logger.info(f"Created detection: {detection.title}")
        return detection
    
    def _extract_indicators(
        self,
        detection: Detection,
        normalized_log: Dict[str, Any]
    ) -> None:
        """Extract indicators of compromise from the log."""
        if normalized_log.get("source_ip"):
            detection.add_indicator(f"source_ip:{normalized_log['source_ip']}")
        
        if normalized_log.get("destination_ip"):
            detection.add_indicator(f"dest_ip:{normalized_log['destination_ip']}")
        
        if normalized_log.get("file_path"):
            detection.add_indicator(f"file:{normalized_log['file_path']}")
        
        if normalized_log.get("process"):
            detection.add_indicator(f"process:{normalized_log['process']}")
        
        if normalized_log.get("user"):
            detection.add_indicator(f"user:{normalized_log['user']}")
    
    def analyze_batch(
        self,
        logs: List[Dict[str, Any]],
        source: str = "unknown"
    ) -> List[Detection]:
        """
        Analyze a batch of logs.
        
        Args:
            logs: List of raw log entries
            source: Source of the logs
            
        Returns:
            List of detections
        """
        detections = []
        
        for log in logs:
            detection = self.analyze_log(log, source)
            if detection:
                detections.append(detection)
        
        logger.info(f"Analyzed {len(logs)} logs, created {len(detections)} detections")
        return detections
    
    def create_custom_rule(
        self,
        name: str,
        description: str,
        patterns: List[str],
        severity: str = "medium",
        mitre_techniques: Optional[List[str]] = None
    ) -> DetectionRule:
        """
        Create a custom detection rule.
        
        Args:
            name: Rule name
            description: Rule description
            patterns: List of regex patterns to match
            severity: Severity level
            mitre_techniques: Associated MITRE ATT&CK techniques
            
        Returns:
            Created detection rule
        """
        rule = DetectionRule(
            name=name,
            description=description,
            rule_format=RuleFormat.CUSTOM,
            rule_content="",
            severity=severity,
            mitre_techniques=mitre_techniques or [],
            metadata={"patterns": patterns},
        )
        
        logger.info(f"Created custom rule: {name}")
        return rule
    
    def get_detection_statistics(self, detections: List[Detection]) -> Dict[str, Any]:
        """
        Generate statistics from detections.
        
        Args:
            detections: List of detections
            
        Returns:
            Detection statistics
        """
        severity_counts = {}
        status_counts = {}
        source_counts = {}
        
        for detection in detections:
            severity_counts[detection.severity] = severity_counts.get(detection.severity, 0) + 1
            status_counts[detection.status.value] = status_counts.get(detection.status.value, 0) + 1
            source_counts[detection.source] = source_counts.get(detection.source, 0) + 1
        
        return {
            "total_detections": len(detections),
            "severity_distribution": severity_counts,
            "status_distribution": status_counts,
            "source_distribution": source_counts,
            "unique_rules": len(set(d.rule_id for d in detections if d.rule_id)),
        }
