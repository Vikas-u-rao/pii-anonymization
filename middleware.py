"""
Middleware components for the PII Gateway.
Includes rate limiting, logging, and request tracking.
"""

import logging
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Rate limiter instance
limiter = Limiter(key_func=get_remote_address)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log all requests with timing and correlation ID.
    
    Features:
        - Generates unique correlation ID for request tracing
        - Measures request processing time
        - Adds X-Correlation-ID and X-Response-Time headers
        - Logs request start and completion with status code
    """
    
    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        # Generate correlation ID
        correlation_id = str(uuid.uuid4())[:8]
        request.state.correlation_id = correlation_id
        
        # Start timing
        start_time = time.time()
        
        # Log request
        logger.info(
            f"[{correlation_id}] {request.method} {request.url.path} - Started"
        )
        
        # Process request
        response: Response = await call_next(request)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Add headers
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Response-Time"] = f"{duration:.3f}s"
        
        # Log response
        logger.info(
            f"[{correlation_id}] {request.method} {request.url.path} - "
            f"{response.status_code} ({duration:.3f}s)"
        )
        
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.
    
    Headers added:
        - X-Content-Type-Options: Prevents MIME type sniffing
        - X-Frame-Options: Prevents clickjacking attacks
        - X-XSS-Protection: Enables browser XSS filtering
        - Strict-Transport-Security: Enforces HTTPS
        - Content-Security-Policy: Restricts resource loading
        - Cache-Control: Prevents sensitive data caching
        - Referrer-Policy: Controls referrer information
        - Permissions-Policy: Restricts browser features
    """
    
    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        response: Response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'"
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        
        return response
