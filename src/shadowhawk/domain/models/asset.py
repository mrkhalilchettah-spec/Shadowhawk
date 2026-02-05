"""
ShadowHawk Platform - Asset Domain Model

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from uuid import UUID, uuid4
from dataclasses import dataclass, field


class AssetType(str, Enum):
    """Types of assets that can be modeled."""
    
    APPLICATION = "application"
    DATABASE = "database"
    SERVER = "server"
    NETWORK = "network"
    API = "api"
    ENDPOINT = "endpoint"
    CLOUD_SERVICE = "cloud_service"
    CONTAINER = "container"
    IOT_DEVICE = "iot_device"
    OTHER = "other"


class Criticality(str, Enum):
    """Asset criticality levels."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Asset:
    """
    Domain model representing a security asset.
    
    Assets are targets of threat modeling and risk assessment.
    """
    
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    asset_type: AssetType = AssetType.OTHER
    description: Optional[str] = None
    criticality: Criticality = Criticality.MEDIUM
    owner: Optional[str] = None
    location: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate asset data after initialization."""
        if not self.name:
            raise ValueError("Asset name cannot be empty")
    
    def update_metadata(self, key: str, value: Any) -> None:
        """Update asset metadata."""
        self.metadata[key] = value
        self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert asset to dictionary representation."""
        return {
            "id": str(self.id),
            "name": self.name,
            "asset_type": self.asset_type.value,
            "description": self.description,
            "criticality": self.criticality.value,
            "owner": self.owner,
            "location": self.location,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
