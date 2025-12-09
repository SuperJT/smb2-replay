# SMB Replay API Dockerfile
# Multi-stage build with UV for faster dependency installation

# ============================================================================
# Builder stage - Install dependencies with UV
# ============================================================================
FROM python:3.12-slim as builder

# Install system dependencies (git for GitHub install, curl for UV installer)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install UV from official Docker image (fastest method)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set UV environment variables for optimal Docker usage
ENV UV_SYSTEM_PYTHON=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Create virtual environment in a known location
ENV VIRTUAL_ENV=/opt/venv
RUN uv venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install smbreplay from GitHub using UV (10-100x faster than pip)
# UV can install from git repositories directly
RUN uv pip install --no-cache git+https://github.com/SuperJT/smb2-replay.git

# Install API dependencies using UV
# Use uv pip install for speed (10-100x faster than regular pip)
RUN uv pip install --no-cache \
    fastapi \
    "uvicorn[standard]" \
    pydantic

# Clone repo to get the API module (not included in pip package)
RUN git clone --depth 1 https://github.com/SuperJT/smb2-replay.git /tmp/smbreplay


# ============================================================================
# Runtime stage - Minimal image with only runtime dependencies
# ============================================================================
FROM python:3.12-slim

# Install tshark and runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    libpcap0.8 \
    wget \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy API module from cloned repo
COPY --from=builder /tmp/smbreplay/api ./api/

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app \
    && mkdir -p /sessions \
    && chown -R appuser:appuser /sessions
USER appuser

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PORT=3004 \
    TRACES_FOLDER=/stingray \
    SESSION_OUTPUT_DIR=/sessions

# Expose port
EXPOSE 3004

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3004/health || exit 1

# Run the application
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "3004"]
