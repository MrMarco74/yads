# -- Stage 1: Build CSS --
FROM node:18-alpine as builder

WORKDIR /app
COPY package.json tailwind.config.js ./
# Create yads directory structure for tailwind content scan
COPY yads/api/templates ./yads/api/templates
COPY yads/api/static/css/input.css ./yads/api/static/css/input.css

RUN npm install
RUN npm run build:css

# -- Stage 2: Run App --
FROM python:3.11-slim

# Install system dependencies for Playwright
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    nmap \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Browsers
RUN playwright install --with-deps chromium

COPY . .

# Copy built CSS from builder
COPY --from=builder /app/yads/api/static/css/main.css ./yads/api/static/css/main.css

# Default command (can be overridden by compose)
CMD ["uvicorn", "yads.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
