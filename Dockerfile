# -- Stage 1: Build CSS --
FROM node:18-alpine AS css-builder

WORKDIR /app
COPY frontend/package.json frontend/tailwind.config.js ./
# Create yads directory structure for tailwind content scan
COPY yads/api/templates ./yads/api/templates
COPY yads/api/static/css/input.css ./yads/api/static/css/input.css

RUN npm install
RUN npm run build:css

# -- Stage 2: Base Image (Common Deps) --
FROM python:3.11-slim AS base

# Install system dependencies
RUN apt-get clean && apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    nmap \
    graphviz \
    postgresql-client \
    unzip \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (ProjectDiscovery)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.4/nuclei_3.3.4_linux_amd64.zip \
    && unzip nuclei_3.3.4_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.3.4_linux_amd64.zip \
    && nuclei -ut

WORKDIR /app

COPY requirements.txt .

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Browsers
RUN playwright install --with-deps chromium

# -- Stage 3: Development (Source Code) --
FROM base AS dev
COPY . .
# Copy built CSS from builder
COPY --from=css-builder /app/yads/api/static/css/main.css ./yads/api/static/css/main.css
CMD ["uvicorn", "yads.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# -- Stage 4: Compilation Builder --
FROM base AS code-builder
# Install build tools for Nuitka
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    patchelf \
    ccache \
    && rm -rf /var/lib/apt/lists/*

RUN pip install nuitka

COPY . .

# Compile 'yads' package
# We exclude tests and migration scripts from compilation, keeping them as scripts if needed?
# Actually migrate_db.py is outside yads/. It needs to be kept as source or compiled separately.
# For simplicity, we compile the 'yads' package and keep top-level scripts as source.
RUN python -m nuitka \
    --module \
    --include-package=yads \
    --output-dir=/build \
    --remove-output \
    yads

# -- Stage 5: Production (Standard) --
FROM base AS prod
# Copy source code directly (skipping Nuitka compilation for reliability)
COPY . .
# Copy built CSS (overwrite static/css/main.css)
COPY --from=css-builder /app/yads/api/static/css/main.css ./yads/api/static/css/main.css

# Production Command (No reload)
CMD ["uvicorn", "yads.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# -- Stage 6: Release (Compiled) --
FROM base AS release
WORKDIR /app
# Copy compiled application (yads package)
COPY --from=code-builder /build .

# Copy scripts for maintenance and startup
COPY scripts/maintenance ./scripts/maintenance
COPY scripts/backup_db.sh ./scripts/backup_db.sh
COPY scripts/start_worker.py ./scripts/start_worker.py

# Copy built CSS (overwrite static/css/main.css if it exists in compiled output, ensuring it's fresh)
# Note: Nuitka might not include non-python resource files unless specified, so we explicitly copy CSS.
COPY --from=css-builder /app/yads/api/static/css/main.css ./yads/api/static/css/main.css

# Production Command
CMD ["uvicorn", "yads.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
