# Dockerfile for running the DataFence authorization API.
#
# DataFence is an authorization library.  The image ships the library and its
# optional API extra (FastAPI/uvicorn).  It does NOT include a database, a
# built-in connector, or pre-configured credentials — those belong to the
# application layer.
#
# To run a DataFence authorization server you must supply:
#   1. A Python entrypoint that builds DataFenceBoundary, registers a
#      principal_resolver, and calls create_api() from datafence.api.
#   2. A policy YAML (or inline policy) for your resources.
#   3. A signing key (from a secrets manager, NOT hardcoded here).
#
# Example application entrypoint:
#   COPY my_app/ /app/my_app/
#   CMD ["uvicorn", "my_app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ── Builder stage ────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[api]"

# ── Production stage ─────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# No database runtime libraries needed — DataFence does not own connectors.
# Add only Python packages.
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY src/ src/
COPY pyproject.toml .
COPY policies/ policies/

# Non-root user for security
RUN useradd -m -u 1000 datafence && \
    chown -R datafence:datafence /app

USER datafence

EXPOSE 8000

# Default: print help.  Replace CMD in your application layer with a real
# server entrypoint that provides boundary + principal resolver.
CMD ["python", "-m", "datafence.cli", "--help"]
