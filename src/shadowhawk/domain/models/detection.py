"""
ShadowHawk Platform - Detection Domain Model

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from uuid import UUID, uuid4
from dataclasses import dataclass, field


class DetectionStatus(str, Enum):
    """Status of a detection."""
    
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class RuleFormat(str, Enum):
    """Detection rule formats."""
    
    SIGMA = "sigma"
    YARA = "yara"
    SNORT = "snort"
    SURICATA = "suricata"
    CUSTOM = "custom"


@dataclass
class DetectionRule:
    """
    Domain model representing a detection rule.
    """
    
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    description: str = ""
    rule_format: RuleFormat = RuleFormat.CUSTOM
    rule_content: str = ""
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate rule data after initialization."""
        if not self.name:
            raise ValueError("Rule name cannot be empty")
        if not self.rule_content:
            raise ValueError("Rule content cannot be empty")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary representation."""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "rule_format": self.rule_format.value,
            "rule_content": self.rule_content,
            "severity": self.severity,
            "tags": self.tags,
            "mitre_techniques": self.mitre_techniques,
            "enabled": self.enabled,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class Detection:
    """
    Domain model representing a security detection event.
    """
    
    id: UUID = field(default_factory=uuid4)
    rule_id: Optional[UUID] = None
    title: str = ""
    description: str = ""
    status: DetectionStatus = DetectionStatus.ACTIVE
    severity: str = "medium"
    source: str = ""
    raw_log: Dict[str, Any] = field(default_factory=dict)
    normalized_log: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    related_detections: List[UUID] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate detection data after initialization."""
        if not self.title:
            raise ValueError("Detection title cannot be empty")
    
    def update_status(self, status: DetectionStatus) -> None:
        """Update detection status."""
        self.status = status
        self.updated_at = datetime.utcnow()
    
    def add_indicator(self, indicator: str) -> None:
        """Add an indicator to the detection."""
        if indicator not in self.indicators:
            self.indicators.append(indicator)
            self.updated_at = datetime.utcnow()
    
    def correlate_with(self, detection_id: UUID) -> None:
        """Correlate this detection with another."""
        if detection_id not in self.related_detections:
            self.related_detections.append(detection_id)
            self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert detection to dictionary representation."""
        return {
            "id": str(self.id),
            "rule_id": str(self.rule_id) if self.rule_id else None,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "severity": self.severity,
            "source": self.source,
            "raw_log": self.raw_log,
            "normalized_log": self.normalized_log,
            "indicators": self.indicators,
            "mitre_techniques": self.mitre_techniques,
            "related_detections": [str(d) for d in self.related_detections],
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
