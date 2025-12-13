"""SMB Replay REST API.

FastAPI application that provides a REST interface to the SMB2ReplaySystem.
Enables Next.js and other clients to interact with SMB replay functionality.
"""

import logging
import os
import secrets
import sys
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

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

# =============================================================================
# Security Configuration
# =============================================================================

# API Key Authentication (optional - set API_KEY env var to enable)
API_KEY: Optional[str] = os.getenv("API_KEY")
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: Optional[str] = Security(API_KEY_HEADER)) -> bool:
    """Verify API key if authentication is enabled.

    If API_KEY environment variable is not set, authentication is disabled
    and all requests are allowed (for backward compatibility).

    Returns:
        True if authenticated or auth disabled

    Raises:
        HTTPException: 401 if API key is invalid or missing when auth is enabled
    """
    # If no API_KEY configured, auth is disabled
    if API_KEY is None:
        return True

    # API key is required but not provided
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Provide X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Validate API key using constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return True


# CORS Configuration
def get_cors_origins() -> list[str]:
    """Get allowed CORS origins from environment.

    Set CORS_ORIGINS env var as comma-separated list of origins.
    Examples:
        - CORS_ORIGINS=http://localhost:3000,https://myapp.com
        - CORS_ORIGINS=* (allow all - NOT recommended for production)

    Defaults to localhost development origins if not set.
    """
    origins_env = os.getenv("CORS_ORIGINS")

    if origins_env:
        return [origin.strip() for origin in origins_env.split(",")]

    # Default: common development origins
    return [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
    ]


CORS_ORIGINS = get_cors_origins()
# Don't allow credentials with wildcard origin (browsers reject this anyway)
CORS_ALLOW_CREDENTIALS = "*" not in CORS_ORIGINS


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

    # Log security configuration
    if API_KEY:
        logger.info("API key authentication ENABLED")
    else:
        logger.warning("API key authentication DISABLED - set API_KEY env var to enable")

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

API key authentication is **optional** and controlled via the `API_KEY` environment variable:

- **Disabled (default)**: If `API_KEY` is not set, all requests are allowed
- **Enabled**: Set `API_KEY=your-secret-key` to require authentication

When enabled, clients must include the `X-API-Key` header with every request:
```
X-API-Key: your-secret-key
```

## CORS

Cross-Origin Resource Sharing is configurable via `CORS_ORIGINS` environment variable:
- Set as comma-separated list: `CORS_ORIGINS=http://localhost:3000,https://app.example.com`
- Default: Common localhost development origins (3000, 3001, 5173)

## Rate Limiting

No rate limiting is implemented. Consider adding rate limiting for production deployments.
    """,
    version="1.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Add CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)
logger.info(f"CORS configured for origins: {CORS_ORIGINS}")


# Validation error handler - logs request body for debugging 422 errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors with detailed logging."""
    # Log the request body to help debug validation failures
    try:
        body = await request.body()
        body_str = body.decode("utf-8") if body else "(empty)"
    except Exception:
        body_str = "(could not read body)"

    logger.warning(
        f"Validation error on {request.method} {request.url.path}: "
        f"body={body_str}, errors={exc.errors()}"
    )

    return JSONResponse(
        status_code=422,
        content={
            "detail": exc.errors(),
            "body": body_str[:500] if len(body_str) > 500 else body_str,
        },
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
# Health endpoint is public (no auth required for monitoring)
app.include_router(health.router)

# Protected routes require API key when authentication is enabled
app.include_router(config.router, dependencies=[Depends(verify_api_key)])
app.include_router(traces.router, dependencies=[Depends(verify_api_key)])
app.include_router(sessions.router, dependencies=[Depends(verify_api_key)])
app.include_router(replay.router, dependencies=[Depends(verify_api_key)])


# Root endpoint (public - provides basic API info)
@app.get("/", tags=["root"])
def root():
    """Root endpoint with API information."""
    return {
        "name": "SMB Replay API",
        "version": "1.1.0",
        "docs": "/docs",
        "health": "/health",
        "auth_enabled": API_KEY is not None,
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
