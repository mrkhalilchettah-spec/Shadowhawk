"""
ShadowHawk Platform - Audit Logging Middleware

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import logging

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware for auditing API requests.
    """
    
    async def dispatch(self, request: Request, call_next):
        """Process request and log audit information."""
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "unknown")
        
        logger.info(
            f"API Request - Method: {request.method}, "
            f"Path: {request.url.path}, "
            f"IP: {client_ip}, "
            f"User-Agent: {user_agent}"
        )
        
        response = await call_next(request)
        
        return response
