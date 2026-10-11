# syntax=docker/dockerfile:1
# argusprowl product image: compiled React frontend + FastAPI backend,
# single process, non-root, deterministic builds.
#
# The virtualenv is installed at build time; at runtime the app is executed
# directly with the venv interpreter. uv is NOT present in the final image,
# and no Node/npm tooling remains in the runtime stage.

# --- Stage 1: Frontend build (Node 22 LTS, pinned package-lock) ---
FROM node:22-alpine AS frontend-builder

WORKDIR /build

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# --- Stage 2: Python dependency install (build-time only) ---
# python:3.13-slim provides the full runtime and /bin/sh.
# uv is installed via pip into /app/.venv; the venv (with uv as a tool) is
# then copied to the runtime stage, where uv is available only during the
# `uv sync` step. The final image retains the venv but uv is not on PATH.
FROM python:3.13-slim AS dep-builder

ARG UV_VERSION=0.7.13

WORKDIR /app

COPY pyproject.toml uv.lock ./

# Create the virtualenv, install uv into it, sync locked runtime deps, then remove
# build-only tooling and packages not declared by the application lockfile.
RUN python -m venv /app/.venv \
 && /app/.venv/bin/pip install --no-cache-dir uv==${UV_VERSION} \
 && /app/.venv/bin/uv sync --frozen --no-dev --no-install-project --python /app/.venv/bin/python \
 && /app/.venv/bin/uv pip uninstall --python /app/.venv/bin/python uv pip setuptools msgpack urllib3

# --- Stage 3: Runtime (Python 3.13, non-root, no uv, no Node) ---
FROM python:3.13-slim AS runtime

WORKDIR /app

# Backend source, config, rules, and package metadata. ATT&CK data is
# downloaded separately by the operator when optional enrichment is enabled.
COPY src/ ./src/
COPY config/ ./config/
COPY pyproject.toml uv.lock ./

# Remove the base image's package installer/build backend from the runtime image.
# The application environment is already prepared in the dedicated builder stage.
RUN python -m pip uninstall -y pip setuptools msgpack urllib3

# Create system user
RUN addgroup --system user && adduser --system --group user

# Prebuilt virtualenv with all runtime dependencies (no dev group).
COPY --from=dep-builder /app/.venv /app/.venv

# Compiled frontend assets -> /app/static (resolved by api/app._static_dir()).
COPY --from=frontend-builder /build/dist/ ./static/

# Runtime state directories (SQLite storage, logs).
# Ownership is baked into the image layer so named-volume first-attach
# populates the volumes pre-owned by `user` — no runtime privilege
# escalation needed.
RUN mkdir -p /app/data /app/logs \
 && chown -R user:user /app/src /app/static /app/data /app/logs /app/.venv \
 # Remove the uv binary from the venv so it is not discoverable at runtime.
 # The venv interpreter and all Python packages remain intact.
 && rm -f /app/.venv/bin/uv /app/.venv/bin/uvx

USER user

# Product API port (matches config/default.yaml api.port).
EXPOSE 8080

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src:$PYTHONPATH"

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
  CMD ["/app/.venv/bin/python", "-c", \
       "import urllib.request,sys;\nr=urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3);sys.exit(0 if r.status==200 else 1)"]

CMD ["/app/.venv/bin/python", "-m", "argusprowl", "server"]
