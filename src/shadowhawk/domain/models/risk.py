"""
ShadowHawk Platform - Risk Domain Model

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from uuid import UUID, uuid4
from dataclasses import dataclass, field


class RiskLevel(str, Enum):
    """Risk level classifications."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


@dataclass
class Risk:
    """
    Domain model representing a calculated risk.
    
    Risks are assessed based on threats, vulnerabilities, and context.
    """
    
    id: UUID = field(default_factory=uuid4)
    title: str = ""
    description: str = ""
    asset_id: Optional[UUID] = None
    finding_id: Optional[UUID] = None
    threat_id: Optional[UUID] = None
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    cvss_score: Optional[float] = None
    impact_score: float = 0.0
    likelihood_score: float = 0.0
    exploitability: Optional[float] = None
    contextual_factors: Dict[str, Any] = field(default_factory=dict)
    mitigation_status: str = "pending"
    owner: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate risk data after initialization."""
        if not self.title:
            raise ValueError("Risk title cannot be empty")
        if not 0 <= self.risk_score <= 10:
            raise ValueError("Risk score must be between 0 and 10")
    
    def calculate_risk_level(self) -> None:
        """Calculate risk level based on risk score."""
        if self.risk_score >= 9.0:
            self.risk_level = RiskLevel.CRITICAL
        elif self.risk_score >= 7.0:
            self.risk_level = RiskLevel.HIGH
        elif self.risk_score >= 4.0:
            self.risk_level = RiskLevel.MEDIUM
        elif self.risk_score >= 1.0:
            self.risk_level = RiskLevel.LOW
        else:
            self.risk_level = RiskLevel.NEGLIGIBLE
        
        self.updated_at = datetime.utcnow()
    
    def update_score(self, score: float) -> None:
        """Update risk score and recalculate level."""
        if not 0 <= score <= 10:
            raise ValueError("Risk score must be between 0 and 10")
        
        self.risk_score = score
        self.calculate_risk_level()
    
    def add_contextual_factor(self, key: str, value: Any) -> None:
        """Add a contextual factor that affects risk."""
        self.contextual_factors[key] = value
        self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert risk to dictionary representation."""
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "finding_id": str(self.finding_id) if self.finding_id else None,
            "threat_id": str(self.threat_id) if self.threat_id else None,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "cvss_score": self.cvss_score,
            "impact_score": self.impact_score,
            "likelihood_score": self.likelihood_score,
            "exploitability": self.exploitability,
            "contextual_factors": self.contextual_factors,
            "mitigation_status": self.mitigation_status,
            "owner": self.owner,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
