"""
ShadowHawk Platform - Audit Logging Service

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import Optional, Dict, Any
from uuid import UUID
import logging

from ...domain.models.audit import AuditLog, AuditAction
from ...domain.models.user import User

logger = logging.getLogger(__name__)


class AuditService:
    """
    Audit logging service for tracking system actions.
    """
    
    def __init__(self):
        """Initialize audit service."""
        self.logs = []
    
    def log_action(
        self,
        action: AuditAction,
        user: Optional[User] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[UUID] = None,
        description: str = "",
        success: bool = True,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """
        Log an audit event.
        
        Args:
            action: Action being performed
            user: User performing the action
            resource_type: Type of resource being acted upon
            resource_id: ID of the resource
            description: Human-readable description
            success: Whether the action succeeded
            error_message: Error message if action failed
            metadata: Additional metadata
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Created audit log entry
        """
        audit_log = AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else "system",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            success=success,
            error_message=error_message,
            metadata=metadata or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        self.logs.append(audit_log)
        
        log_level = logging.INFO if success else logging.WARNING
        logger.log(
            log_level,
            f"Audit: {action.value} by {audit_log.username} - {description}"
        )
        
        return audit_log
    
    def log_authentication(
        self,
        username: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> AuditLog:
        """
        Log an authentication attempt.
        
        Args:
            username: Username attempting to authenticate
            success: Whether authentication succeeded
            ip_address: IP address of the request
            user_agent: User agent string
            error_message: Error message if failed
            
        Returns:
            Created audit log entry
        """
        action = AuditAction.LOGIN if success else AuditAction.LOGIN_FAILED
        description = f"User {username} {'logged in' if success else 'failed to log in'}"
        
        return self.log_action(
            action=action,
            description=description,
            success=success,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"username": username}
        )
    
    def log_user_action(
        self,
        action: AuditAction,
        user: User,
        target_user_id: UUID,
        description: str,
        success: bool = True
    ) -> AuditLog:
        """
        Log a user management action.
        
        Args:
            action: User action type
            user: User performing the action
            target_user_id: ID of user being acted upon
            description: Action description
            success: Whether action succeeded
            
        Returns:
            Created audit log entry
        """
        return self.log_action(
            action=action,
            user=user,
            resource_type="user",
            resource_id=target_user_id,
            description=description,
            success=success
        )
    
    def log_resource_action(
        self,
        action: AuditAction,
        user: User,
        resource_type: str,
        resource_id: UUID,
        description: str,
        success: bool = True
    ) -> AuditLog:
        """
        Log a resource action (create, update, delete).
        
        Args:
            action: Action type
            user: User performing the action
            resource_type: Type of resource
            resource_id: ID of resource
            description: Action description
            success: Whether action succeeded
            
        Returns:
            Created audit log entry
        """
        return self.log_action(
            action=action,
            user=user,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            success=success
        )
    
    def log_analysis(
        self,
        action: AuditAction,
        user: User,
        analysis_type: str,
        success: bool = True,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        """
        Log an analysis operation.
        
        Args:
            action: Analysis action
            user: User running the analysis
            analysis_type: Type of analysis
            success: Whether analysis succeeded
            error_message: Error message if failed
            metadata: Analysis metadata
            
        Returns:
            Created audit log entry
        """
        return self.log_action(
            action=action,
            user=user,
            resource_type="analysis",
            description=f"{analysis_type} analysis",
            success=success,
            error_message=error_message,
            metadata=metadata
        )
    
    def get_logs_by_user(self, user_id: UUID) -> list:
        """Get all audit logs for a specific user."""
        return [log for log in self.logs if log.user_id == user_id]
    
    def get_logs_by_action(self, action: AuditAction) -> list:
        """Get all audit logs for a specific action type."""
        return [log for log in self.logs if log.action == action]
    
    def get_failed_actions(self) -> list:
        """Get all failed actions."""
        return [log for log in self.logs if not log.success]
