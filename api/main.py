"""SMB Replay REST API.

FastAPI application that provides a REST interface to the SMB2ReplaySystem.
Enables Next.js and other clients to interact with SMB replay functionality.
"""

import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Add smbreplay package to path before importing routes
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "smbreplay_package")
)

from api.routes import config, health, replay, sessions, traces
from api.services.smbreplay_service import SMBReplayServiceError, get_smbreplay_service

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown."""
    # Startup
    logger.info("Starting SMB Replay API...")

    # Initialize the service to verify system setup
    service = get_smbreplay_service()
    health_status = service.health_check()

    if health_status["status"] == "error":
        logger.warning("Service started with errors - health check failed")
    elif health_status["status"] == "degraded":
        logger.warning("Service started in degraded mode - tshark unavailable, some features may be limited")
    else:
        logger.info("Service started successfully")

    yield

    # Shutdown
    logger.info("Shutting down SMB Replay API...")


# Create FastAPI app
app = FastAPI(
    title="SMB Replay API",
    description="""
REST API for the SMB2 Replay System.

Provides endpoints for:
- **Health**: API health checks and system information
- **Configuration**: Manage system and replay configuration
- **Traces**: List and ingest PCAP files
- **Sessions**: List and analyze SMB2 sessions
- **Replay**: Validate, setup, and execute SMB2 replay operations

## Authentication

This API is designed for trusted environments and does not require authentication.

## Rate Limiting

No rate limiting is implemented. Consider adding rate limiting for production deployments.
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Add CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handler for service errors
@app.exception_handler(SMBReplayServiceError)
async def service_error_handler(request: Request, exc: SMBReplayServiceError):
    """Handle SMBReplayServiceError exceptions."""
    return JSONResponse(
        status_code=400,
        content={
            "error": exc.message,
            "code": exc.code,
        },
    )


# Global exception handler for unexpected errors
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.exception(f"Unexpected error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if os.getenv("DEBUG") else None,
        },
    )


# Include routers
app.include_router(health.router)
app.include_router(config.router)
app.include_router(traces.router)
app.include_router(sessions.router)
app.include_router(replay.router)


# Root endpoint
@app.get("/", tags=["root"])
def root():
    """Root endpoint with API information."""
    return {
        "name": "SMB Replay API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "3004"))
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=port,
        reload=os.getenv("DEBUG", "false").lower() == "true",
    )
