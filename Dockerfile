# ── Stage 1: CSS Build ────────────────────────────────────────────────────────
FROM node:18-alpine AS css-builder

WORKDIR /app
COPY frontend/package.json frontend/tailwind.config.js ./
COPY yads/api/templates ./yads/api/templates
COPY yads/api/static/css/input.css ./yads/api/static/css/input.css

RUN npm install
RUN npm run build:css


# ── Stage 2: Python base — API-only dependencies ──────────────────────────────
# Lightweight base with only what the API server needs.
# No scanner tools (Playwright, Nuclei, Nmap) — those live in Dockerfile.tools.
FROM python:3.11-slim AS base-api

ARG YADS_GIT_SHA
LABEL YADS_GIT_SHA=${YADS_GIT_SHA}

RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    graphviz \
    postgresql-client \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements-api.txt .
RUN pip install --no-cache-dir -r requirements-api.txt


# ── Stage 3: Scanner-tools layer ──────────────────────────────────────────────
# Extends base-api with Nuclei, Playwright/Chromium and Nmap + full requirements.
# Used for local dev builds (docker-compose.yml --target dev).
# Production worker builds use Dockerfile.worker + pre-baked yads-tools image.
# Nuclei templates are NOT baked in — provided via volume (nuclei_templates:/root/nuclei-templates).
FROM base-api AS base-scanner

RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    unzip \
    && rm -rf /var/lib/apt/lists/*
# NOTE: Nmap is not bundled. Install via the admin UI (Settings → Tools) if needed.
# When absent, nmap_scanner falls back to socket-based port scanning automatically.

# Nuclei binary only — templates come from the nuclei_templates Docker volume
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.4/nuclei_3.3.4_linux_amd64.zip \
    && unzip nuclei_3.3.4_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.3.4_linux_amd64.zip

# Full worker deps (imagehash, mmh3, ipwhois, Pillow, psutil, etc.) + Playwright/Chromium
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium


# ── Stage 4: API image (production, no scanner tools) ─────────────────────────
# Small image for the FastAPI server — ~600-800 MB vs 5+ GB previously.
# Screenshots directory must be provided as a Docker volume at runtime:
#   volumes: - yads_screenshots:/app/yads/api/static/screenshots
FROM base-api AS api

COPY --from=css-builder /app/yads/api/static/css/main.css ./yads/api/static/css/main.css
COPY . .

CMD ["uvicorn", "yads.api.main:app", "--host", "0.0.0.0", "--port", "8000"]


# ── Stage 5: Worker image (production, with scanner tools) ────────────────────
# Full image for the Celery worker — includes Playwright, Nuclei, Nmap.
# Only needs to be redeployed when tool versions or Python deps change.
FROM base-scanner AS worker

COPY --from=css-builder /app/yads/api/static/css/main.css ./yads/api/static/css/main.css
COPY . .

CMD ["python", "scripts/start_worker.py"]


# ── Stage 6: Development (all-in-one, hot-reload) ─────────────────────────────
FROM base-scanner AS dev

COPY --from=css-builder /app/yads/api/static/css/main.css ./yads/api/static/css/main.css
COPY . .

CMD ["uvicorn", "yads.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


# ── Stage 7: Production combined (legacy / single-node fallback) ──────────────
# Backwards-compatible all-in-one image. Use api+worker split for new deployments.
FROM base-scanner AS prod

COPY --from=css-builder /app/yads/api/static/css/main.css ./yads/api/static/css/main.css
COPY . .

CMD ["uvicorn", "yads.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
