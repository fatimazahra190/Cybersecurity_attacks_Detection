FROM python:3.11-slim-bookworm

LABEL description="CyberSec Serving Layer — Flask REST API"

# curl needed for Docker healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY app.py hbase_service.py cassandra_service.py threat_fusion.py ./

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE 8080

HEALTHCHECK --interval=20s --timeout=5s --start-period=40s --retries=5 \
    CMD curl -sf http://localhost:8080/health || exit 1

CMD ["python", "app.py"]
