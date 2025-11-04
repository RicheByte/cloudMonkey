# Multi-stage Docker build for Cloud Security Scanner
# Optimized for small image size and security

# Stage 1: Builder
FROM python:3.11-slim as builder

LABEL maintainer="RicheByte"
LABEL description="Cloud Misconfiguration Scanner - Enterprise Edition"

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY cloud-pro.py .
COPY db_manager.py .
COPY rules_engine.py .
COPY rules/ ./rules/

# Create directories for data persistence
RUN mkdir -p /data /reports && \
    chmod 755 /data /reports

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SCAN_DB_PATH=/data/scan_history.db \
    PYTHONPATH=/app

# Create non-root user for security
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app /data /reports

USER scanner

# Default command
ENTRYPOINT ["python", "cloud-pro.py"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Expose port for future API server
EXPOSE 8080

# Labels for metadata
LABEL version="7.0-ENTERPRISE"
LABEL org.opencontainers.image.source="https://github.com/RicheByte/cloudMonkey"
LABEL org.opencontainers.image.description="Enterprise cloud security misconfiguration scanner"
LABEL org.opencontainers.image.licenses="MIT"
