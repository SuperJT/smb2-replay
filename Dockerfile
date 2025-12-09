# SMB Replay API Dockerfile
# Multi-stage build for smaller image size

FROM python:3.12-slim as builder

# Install build dependencies (including git for pip install from GitHub)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install smbreplay from GitHub
RUN pip install --no-cache-dir git+https://github.com/SuperJT/smb2-replay.git

# Install API dependencies (FastAPI, uvicorn, etc.)
RUN pip install --no-cache-dir \
    fastapi>=0.109.0 \
    "uvicorn[standard]>=0.27.0" \
    pydantic>=2.5.0

# Clone repo to get the API module (not included in pip package)
RUN git clone --depth 1 https://github.com/SuperJT/smb2-replay.git /tmp/smbreplay


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
ENV PYTHONUNBUFFERED=1
ENV PORT=3004
ENV TRACES_FOLDER=/stingray
ENV SESSION_OUTPUT_DIR=/sessions

# Expose port
EXPOSE 3004

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3004/health || exit 1

# Run the application
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "3004"]
