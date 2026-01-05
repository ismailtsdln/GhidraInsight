FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python package
COPY . .

# Install package and dependencies
RUN pip install --no-cache-dir -e .

# Create non-root user
RUN useradd -m ghidrainsight && \
    chown -R ghidrainsight:ghidrainsight /app

USER ghidrainsight

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/api/status')" || exit 1

# Expose port
EXPOSE 8000

# Start server
CMD ["ghidrainsight-server", "--host", "0.0.0.0", "--port", "8000"]
