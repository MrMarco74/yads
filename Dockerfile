# ── Stage 1: CSS Build ────────────────────────────────────────────────────────
FROM node:20-alpine AS css-builder

WORKDIR /app
COPY frontend ./frontend
COPY yads/api/templates ./yads/api/templates
COPY yads/api/static/css/input.css ./yads/api/static/css/input.css

WORKDIR /app/frontend
RUN npm install
RUN npm run build:css


# ── Stage 2: Python base — API-only dependencies ──────────────────────────────
# Lightweight base with only what the API server needs.
# No scanner tools (Playwright, Nuclei, Nmap) — those live in Dockerfile.tools.
FROM python:3.11-slim AS base-api

ARG YADS_GIT_SHA
ARG YADS_BUILD_TIME
LABEL YADS_GIT_SHA=${YADS_GIT_SHA}
LABEL YADS_BUILD_TIME=${YADS_BUILD_TIME}
ENV YADS_GIT_SHA=${YADS_GIT_SHA}
ENV YADS_BUILD_TIME=${YADS_BUILD_TIME}

RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    graphviz \
    postgresql-client \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Install the FULL Python dependency set in the base image shared by BOTH the
# api and worker targets. The api image used to install a slim
# requirements-api.txt subset that omitted scanner-module deps (beautifulsoup4,
# etc.); any code path the API loaded that imported a scanner module then
# crash-looped the api container with ModuleNotFoundError (see the bs4 incident
# 2026-08-24). Sharing one requirements.txt eliminates that whole asymmetry.
# Only the *heavy binaries* (Chromium browser, Nuclei, Nmap) remain worker-only
# in base-scanner below — the api never executes those, it dispatches to the
# worker — so the api image stays free of the multi-GB Chromium download.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip==25.3 wheel==0.46.2 && \
    pip install --no-cache-dir "jaraco.context>=6.1.0" && \
    pip install --no-cache-dir -r requirements.txt


# ── Stage 3: Scanner-tools layer ──────────────────────────────────────────────
# Extends base-api with the heavy scanner BINARIES only (Python deps are already
# installed in base-api): Nuclei, Nmap, and the Playwright/Chromium browser.
# Used for local dev builds (docker-compose.yml --target dev) and the worker target.
# Nuclei templates are NOT baked in — provided via volume (nuclei_templates:/root/nuclei-templates).
FROM base-api AS base-scanner

RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    unzip \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Nuclei binary only — templates come from the nuclei_templates Docker volume
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.4/nuclei_3.3.4_linux_amd64.zip \
    && unzip nuclei_3.3.4_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.3.4_linux_amd64.zip

# Playwright browser (the pip package itself is already in base-api via
# requirements.txt; this downloads the Chromium binary + its OS deps).
RUN playwright install --with-deps chromium


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
