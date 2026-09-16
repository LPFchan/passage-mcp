FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000

# age does all encryption and decryption; the server only shells out to it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends age \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN useradd --uid 1001 --create-home --shell /usr/sbin/nologin appuser

COPY pyproject.toml /app/
COPY src /app/src

RUN python -m pip install --no-cache-dir .

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/healthz',timeout=3)"

CMD ["python", "-m", "vaultwarden_mcp.server", "--config", "/config/config.json"]
