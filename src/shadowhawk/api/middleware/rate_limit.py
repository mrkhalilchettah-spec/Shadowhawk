"""
ShadowHawk Platform - Rate Limiting Middleware

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import time
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware to prevent abuse.
    """
    
    def __init__(self, app, calls: int = 100, period: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            app: FastAPI application
            calls: Maximum number of calls allowed
            period: Time period in seconds
        """
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.client_requests = defaultdict(list)
    
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting."""
        client_ip = request.client.host
        
        current_time = time.time()
        
        self.client_requests[client_ip] = [
            req_time for req_time in self.client_requests[client_ip]
            if current_time - req_time < self.period
        ]
        
        if len(self.client_requests[client_ip]) >= self.calls:
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Please try again later."
                }
            )
        
        self.client_requests[client_ip].append(current_time)
        
        response = await call_next(request)
        return response
