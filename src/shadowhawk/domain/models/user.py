"""
ShadowHawk Platform - User Domain Model

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4
from dataclasses import dataclass, field


class Role(str, Enum):
    """User roles for RBAC."""
    
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


@dataclass
class User:
    """
    Domain model representing a user.
    """
    
    id: UUID = field(default_factory=uuid4)
    username: str = ""
    email: str = ""
    hashed_password: str = ""
    full_name: Optional[str] = None
    roles: List[Role] = field(default_factory=lambda: [Role.VIEWER])
    is_active: bool = True
    is_superuser: bool = False
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate user data after initialization."""
        if not self.username:
            raise ValueError("Username cannot be empty")
        if not self.email:
            raise ValueError("Email cannot be empty")
    
    def has_role(self, role: Role) -> bool:
        """Check if user has a specific role."""
        return role in self.roles or self.is_superuser
    
    def add_role(self, role: Role) -> None:
        """Add a role to the user."""
        if role not in self.roles:
            self.roles.append(role)
            self.updated_at = datetime.utcnow()
    
    def remove_role(self, role: Role) -> None:
        """Remove a role from the user."""
        if role in self.roles:
            self.roles.remove(role)
            self.updated_at = datetime.utcnow()
    
    def record_login(self) -> None:
        """Record a successful login."""
        self.last_login = datetime.utcnow()
        self.failed_login_attempts = 0
        self.updated_at = datetime.utcnow()
    
    def record_failed_login(self) -> None:
        """Record a failed login attempt."""
        self.failed_login_attempts += 1
        self.updated_at = datetime.utcnow()
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert user to dictionary representation."""
        data = {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "roles": [role.value for role in self.roles],
            "is_active": self.is_active,
            "is_superuser": self.is_superuser,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        
        if include_sensitive:
            data["hashed_password"] = self.hashed_password
            data["failed_login_attempts"] = self.failed_login_attempts
        
        return data
