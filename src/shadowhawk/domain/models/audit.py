"""
ShadowHawk Platform - Audit Log Domain Model

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from uuid import UUID, uuid4
from dataclasses import dataclass, field


class AuditAction(str, Enum):
    """Audit log action types."""
    
    # Authentication
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    
    # User management
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    
    # Asset operations
    ASSET_CREATED = "asset_created"
    ASSET_UPDATED = "asset_updated"
    ASSET_DELETED = "asset_deleted"
    
    # Threat operations
    THREAT_CREATED = "threat_created"
    THREAT_UPDATED = "threat_updated"
    THREAT_DELETED = "threat_deleted"
    
    # Detection operations
    DETECTION_CREATED = "detection_created"
    DETECTION_UPDATED = "detection_updated"
    DETECTION_RESOLVED = "detection_resolved"
    
    # Analysis operations
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_FAILED = "analysis_failed"
    
    # Report operations
    REPORT_GENERATED = "report_generated"
    REPORT_DOWNLOADED = "report_downloaded"
    
    # Configuration
    CONFIG_UPDATED = "config_updated"
    
    # Other
    OTHER = "other"


@dataclass
class AuditLog:
    """
    Domain model representing an audit log entry.
    
    Audit logs provide a traceable record of all system actions.
    """
    
    id: UUID = field(default_factory=uuid4)
    user_id: Optional[UUID] = None
    username: Optional[str] = None
    action: AuditAction = AuditAction.OTHER
    resource_type: Optional[str] = None
    resource_id: Optional[UUID] = None
    description: str = ""
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate audit log data after initialization."""
        if not self.action:
            raise ValueError("Action cannot be empty")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit log to dictionary representation."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "username": self.username,
            "action": self.action.value,
            "resource_type": self.resource_type,
            "resource_id": str(self.resource_id) if self.resource_id else None,
            "description": self.description,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "success": self.success,
            "error_message": self.error_message,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }
