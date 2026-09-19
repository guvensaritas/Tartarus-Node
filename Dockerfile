# ========================
# Build Stage (Minimal size + security)
# ========================
FROM python:3.10-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ========================
# Runtime Stage (Non-root execution)
# ========================
FROM python:3.10-slim-bookworm

# === SECURITY: Strict Directory Permissions ===
# 755 ensures directories are readable for deception but NEVER world-writable
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/state_memory /app/quarantine /app/logs && \
    chown -R appuser:appuser /app && \
    chmod 755 /app/state_memory /app/quarantine /app/logs

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.10/site-packages/ /usr/local/lib/python3.10/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Application files 
COPY --chown=appuser:appuser main.py .
COPY --chown=appuser:appuser tartarus_core/rate_limiter.py ./tartarus_core/
COPY --chown=appuser:appuser network_trap/ ./network_trap/
COPY --chown=appuser:appuser tartarus_core/ ./tartarus_core/
COPY --chown=appuser:appuser config.json .

# Native Python Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/stats', timeout=3)" || exit 1

EXPOSE 2222 8080

USER appuser

ENV OLLAMA_API_URL=http://ollama:11434/api/generate
ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]