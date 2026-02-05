"""
ShadowHawk Platform - Finding Domain Model

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from uuid import UUID, uuid4
from dataclasses import dataclass, field


class FindingSeverity(str, Enum):
    """Severity levels for findings."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Status of a finding."""
    
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    REOPENED = "reopened"


@dataclass
class Finding:
    """
    Domain model representing a security finding.
    
    Findings are security issues discovered through analysis.
    """
    
    id: UUID = field(default_factory=uuid4)
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    status: FindingStatus = FindingStatus.OPEN
    asset_id: Optional[UUID] = None
    detection_id: Optional[UUID] = None
    threat_id: Optional[UUID] = None
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Validate finding data after initialization."""
        if not self.title:
            raise ValueError("Finding title cannot be empty")
    
    def update_status(self, status: FindingStatus) -> None:
        """Update finding status."""
        self.status = status
        self.updated_at = datetime.utcnow()
        
        if status == FindingStatus.RESOLVED:
            self.resolved_at = datetime.utcnow()
    
    def add_evidence(self, evidence: Dict[str, Any]) -> None:
        """Add evidence to the finding."""
        self.evidence.append(evidence)
        self.updated_at = datetime.utcnow()
    
    def add_mitre_technique(self, technique_id: str) -> None:
        """Add a MITRE ATT&CK technique."""
        if technique_id not in self.mitre_techniques:
            self.mitre_techniques.append(technique_id)
            self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "detection_id": str(self.detection_id) if self.detection_id else None,
            "threat_id": str(self.threat_id) if self.threat_id else None,
            "cvss_score": self.cvss_score,
            "cve_ids": self.cve_ids,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "references": self.references,
            "tags": self.tags,
            "metadata": self.metadata,
            "discovered_at": self.discovered_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }
