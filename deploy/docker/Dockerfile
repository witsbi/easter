# EASTER gateway, containerized (GATEWAY-0).
#
# Build context is the repository root:
#   docker build -f deploy/docker/Dockerfile .
#
# The gateway spawns mcp_server.py as a subprocess via sys.executable,
# so the image carries the full runtime: kernel.py, mcp_server.py,
# gateway.py, initialize.py, and schema.sql.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 easter

WORKDIR /app

COPY requirements-mcp.txt ./requirements-mcp.txt
# The gateway's own manifest includes requirements-mcp.txt by relative
# path, so both files are copied in a layout that preserves that
# relationship (repo-root file at ./, deploy-local file at
# ./deploy/docker/). requirements-mcp.txt itself stays lean for the
# stdio (mcp_server.py) path, which needs no web stack.
COPY deploy/docker/requirements-gateway.txt ./deploy/docker/requirements-gateway.txt
RUN pip install --no-cache-dir -r deploy/docker/requirements-gateway.txt

COPY kernel.py mcp_server.py gateway.py initialize.py schema.sql ./
COPY deploy/docker/entrypoint.sh /usr/local/bin/easter-entrypoint
RUN chmod +x /usr/local/bin/easter-entrypoint \
    && mkdir -p /data && chown -R easter:easter /app /data

USER easter

# /data holds the kernel DB, the session store, and the TLS cert/key.
# It is expected to be a persistent volume (see docker-compose.yml).
ENV KERNEL_DB_PATH=/data/kernel.db

EXPOSE 8443

# /health is public (no auth); the cert is self-signed on first run,
# so the check skips verification. This only proves the server is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import ssl,urllib.request;ctx=ssl._create_unverified_context();urllib.request.urlopen('https://127.0.0.1:8443/health',timeout=5,context=ctx)"

ENTRYPOINT ["easter-entrypoint"]
