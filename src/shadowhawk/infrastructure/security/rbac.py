"""
ShadowHawk Platform - Role-Based Access Control Service

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import List, Dict, Set
import logging

from ...domain.models.user import User, Role

logger = logging.getLogger(__name__)


class RBACService:
    """
    Role-Based Access Control (RBAC) service.
    
    Manages permissions and access control based on user roles.
    """
    
    def __init__(self):
        """Initialize RBAC service with permission mappings."""
        self.role_permissions = self._initialize_permissions()
    
    def _initialize_permissions(self) -> Dict[Role, Set[str]]:
        """Initialize role-to-permission mappings."""
        return {
            Role.ADMIN: {
                # User management
                "user:create",
                "user:read",
                "user:update",
                "user:delete",
                "user:manage_roles",
                
                # Asset management
                "asset:create",
                "asset:read",
                "asset:update",
                "asset:delete",
                
                # Threat management
                "threat:create",
                "threat:read",
                "threat:update",
                "threat:delete",
                
                # Detection management
                "detection:create",
                "detection:read",
                "detection:update",
                "detection:delete",
                
                # Finding management
                "finding:create",
                "finding:read",
                "finding:update",
                "finding:delete",
                
                # Analysis
                "analysis:run",
                "analysis:read",
                
                # Reports
                "report:generate",
                "report:read",
                "report:delete",
                
                # Configuration
                "config:read",
                "config:update",
                
                # Audit logs
                "audit:read",
            },
            Role.ANALYST: {
                # User - limited
                "user:read",
                
                # Asset management
                "asset:create",
                "asset:read",
                "asset:update",
                
                # Threat management
                "threat:create",
                "threat:read",
                "threat:update",
                
                # Detection management
                "detection:create",
                "detection:read",
                "detection:update",
                
                # Finding management
                "finding:create",
                "finding:read",
                "finding:update",
                
                # Analysis
                "analysis:run",
                "analysis:read",
                
                # Reports
                "report:generate",
                "report:read",
                
                # Configuration - read only
                "config:read",
                
                # Audit logs - read only
                "audit:read",
            },
            Role.VIEWER: {
                # Read-only access
                "user:read",
                "asset:read",
                "threat:read",
                "detection:read",
                "finding:read",
                "analysis:read",
                "report:read",
                "config:read",
            },
        }
    
    def check_permission(self, user: User, permission: str) -> bool:
        """
        Check if a user has a specific permission.
        
        Args:
            user: User to check
            permission: Permission string (e.g., "asset:create")
            
        Returns:
            True if user has permission, False otherwise
        """
        if user.is_superuser:
            return True
        
        for role in user.roles:
            if permission in self.role_permissions.get(role, set()):
                logger.debug(f"User {user.username} has permission {permission} via role {role.value}")
                return True
        
        logger.warning(f"User {user.username} denied permission {permission}")
        return False
    
    def get_user_permissions(self, user: User) -> Set[str]:
        """
        Get all permissions for a user.
        
        Args:
            user: User to get permissions for
            
        Returns:
            Set of permission strings
        """
        if user.is_superuser:
            all_permissions = set()
            for permissions in self.role_permissions.values():
                all_permissions.update(permissions)
            return all_permissions
        
        user_permissions = set()
        for role in user.roles:
            user_permissions.update(self.role_permissions.get(role, set()))
        
        return user_permissions
    
    def can_access_resource(
        self,
        user: User,
        resource_type: str,
        action: str
    ) -> bool:
        """
        Check if user can perform an action on a resource type.
        
        Args:
            user: User to check
            resource_type: Type of resource (e.g., "asset", "threat")
            action: Action to perform (e.g., "read", "create", "update", "delete")
            
        Returns:
            True if user has access, False otherwise
        """
        permission = f"{resource_type}:{action}"
        return self.check_permission(user, permission)
    
    def require_permission(self, user: User, permission: str) -> None:
        """
        Require a permission or raise an exception.
        
        Args:
            user: User to check
            permission: Required permission
            
        Raises:
            PermissionError: If user lacks permission
        """
        if not self.check_permission(user, permission):
            raise PermissionError(
                f"User {user.username} lacks required permission: {permission}"
            )
    
    def require_role(self, user: User, required_role: Role) -> None:
        """
        Require a specific role or raise an exception.
        
        Args:
            user: User to check
            required_role: Required role
            
        Raises:
            PermissionError: If user lacks role
        """
        if not user.has_role(required_role) and not user.is_superuser:
            raise PermissionError(
                f"User {user.username} lacks required role: {required_role.value}"
            )
    
    def filter_by_permission(
        self,
        user: User,
        items: List[Any],
        permission: str
    ) -> List[Any]:
        """
        Filter items based on user permission.
        
        Args:
            user: User to check
            items: List of items to filter
            permission: Permission to check
            
        Returns:
            Filtered list of items
        """
        if self.check_permission(user, permission):
            return items
        return []
