"""
ShadowHawk Platform - Threat Domain Model

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4
from dataclasses import dataclass, field


class StrideCategory(str, Enum):
    """STRIDE threat classification categories."""
    
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ThreatCategory(str, Enum):
    """General threat categories."""
    
    MALWARE = "malware"
    PHISHING = "phishing"
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHIC = "cryptographic"
    DATA_EXPOSURE = "data_exposure"
    CONFIGURATION = "configuration"
    NETWORK = "network"
    PHYSICAL = "physical"
    OTHER = "other"


@dataclass
class Threat:
    """
    Domain model representing a security threat.
    
    Threats are identified risks to assets that need to be mitigated.
    """
    
    id: UUID = field(default_factory=uuid4)
    title: str = ""
    description: str = ""
    asset_id: Optional[UUID] = None
    stride_categories: List[StrideCategory] = field(default_factory=list)
    threat_categories: List[ThreatCategory] = field(default_factory=list)
    impact: str = ""
    likelihood: str = ""
    mitigations: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate threat data after initialization."""
        if not self.title:
            raise ValueError("Threat title cannot be empty")
        if not self.description:
            raise ValueError("Threat description cannot be empty")
    
    def add_stride_category(self, category: StrideCategory) -> None:
        """Add a STRIDE category to the threat."""
        if category not in self.stride_categories:
            self.stride_categories.append(category)
            self.updated_at = datetime.utcnow()
    
    def add_mitigation(self, mitigation: str) -> None:
        """Add a mitigation strategy."""
        if mitigation not in self.mitigations:
            self.mitigations.append(mitigation)
            self.updated_at = datetime.utcnow()
    
    def add_mitre_technique(self, technique_id: str) -> None:
        """Add a MITRE ATT&CK technique."""
        if technique_id not in self.mitre_techniques:
            self.mitre_techniques.append(technique_id)
            self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert threat to dictionary representation."""
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "stride_categories": [cat.value for cat in self.stride_categories],
            "threat_categories": [cat.value for cat in self.threat_categories],
            "impact": self.impact,
            "likelihood": self.likelihood,
            "mitigations": self.mitigations,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
