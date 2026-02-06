"""
ShadowHawk Platform - FastAPI Main Application

Copyright (c) 2026 ShadowHawk Platform
Licensed under the Apache License
See LICENSE file in the project root for full license information.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import time

from .routes import auth, threat_modeling, detection, mitre, correlation, risk, analysis
from .middleware.rate_limit import RateLimitMiddleware
from .middleware.audit_middleware import AuditMiddleware

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="ShadowHawk Platform",
    description="Enterprise-Grade Cyber Security Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RateLimitMiddleware, calls=100, period=60)
app.add_middleware(AuditMiddleware)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests."""
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Duration: {process_time:.3f}s"
    )
    
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "ShadowHawk Platform",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": time.time()
    }


app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(threat_modeling.router, prefix="/api/v1/threat-modeling", tags=["Threat Modeling"])
app.include_router(detection.router, prefix="/api/v1/detection", tags=["Detection"])
app.include_router(mitre.router, prefix="/api/v1/mitre", tags=["MITRE ATT&CK"])
app.include_router(correlation.router, prefix="/api/v1/correlation", tags=["Correlation"])
app.include_router(risk.router, prefix="/api/v1/risk", tags=["Risk Scoring"])
app.include_router(analysis.router, prefix="/api/v1/analysis", tags=["AI Analysis"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
