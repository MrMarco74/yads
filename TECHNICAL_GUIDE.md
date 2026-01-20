# YADS - Technical & Installation Guide

## Overview

This guide describes the technical architecture and installation process of the YADS platform. It is intended for System Administrators and DevOps Engineers responsible for deploying and maintaining the YADS infrastructure.

---

## 1. Stack Service Architecture

The YADS platform consists of several microservices orchestrated via Docker Compose.

### Services

| Service | Image | Description |
| :--- | :--- | :--- |
| **yads-api** | `registry.example.com/yads/yads:latest` | The core FastAPI backend application. Handles API requests, database interactions, and orchestrates scans. |
| **yads-worker** | `registry.example.com/yads/yads:latest` | Background worker process. Consumes scan tasks from Redis and executes them using scanner modules (Nuclei, Chrome, etc.). |
| **db** | `postgres:15-alpine` | Primary data store. Persists users, targets, scan results, and system configuration. |
| **redis** | `redis:7-alpine` | In-memory data store used for the Task Queue (Celery) and Result Cache. configured with AOF persistence. |

### Network

All services communicate over an internal bridge network `yads-net`. The API service exposes port `8000` to the host (or reverse proxy).

---

## 2. Installation via Docker

### Prerequisites

*   Docker Engine (v24.0+)
*   Docker Compose (v2.20+)
*   **YADS Registry Access** (Credentials provided by support)

### Installation Steps

1.  **Authenticate with Registry**
    Login to the secure YADS container registry using the credentials provided with your license:
    ```bash
    docker login registry.example.com
    # Username: <your-license-id>
    # Password: <your-access-token>
    ```

2.  **Create Directory Structure**
    Create a project folder (e.g., `/opt/yads`) and ensure the following structure:
    ```bash
    yads/
    ├── docker-compose.yml
    └── .env
    ```

2.  **Configuration (.env)**
    Create a `.env` file with your environment secrets:
    ```ini
    POSTGRES_PASSWORD=your_secure_db_password
    SECRET_KEY=your_random_secret_string_for_tokens
    API_KEY=your_optional_api_key
    ```

3.  **Docker Compose File**
    Save the following content as `docker-compose.yml` (based on the Production Stack):

    ```yaml
    version: '3.8'

    services:
      # --- Backend Services ---
      yads-api:
        image: registry.example.com/yads/yads:latest
        command: sh -c "/app/scripts/backup_db.sh && python migrate_db.py && uvicorn yads.api.main:app --host 0.0.0.0 --port 8000"
        restart: always
        ports:
          - "8000:8000"
        environment:
          - DATABASE_URL=postgresql://yads:${POSTGRES_PASSWORD}@db:5432/yads
          - REDIS_URL=redis://redis:6379/0
          - CHROME_BIN=/usr/bin/google-chrome
          - LOG_DIR=/app/logs
          - SECRET_KEY=${SECRET_KEY}
        networks:
          - yads-net

      yads-worker:
        image: registry.example.com/yads/yads:latest
        command: python /app/scripts/start_worker.py
        restart: always
        environment:
          - DATABASE_URL=postgresql://yads:${POSTGRES_PASSWORD}@db:5432/yads
          - REDIS_URL=redis://redis:6379/0
          - CHROME_BIN=/usr/bin/google-chrome
          - LOG_DIR=/app/logs
        depends_on:
          - db
          - redis
        networks:
          - yads-net

      # --- Infrastructure ---
      db:
        image: postgres:15-alpine
        restart: always
        environment:
          - POSTGRES_USER=yads
          - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
          - POSTGRES_DB=yads
        volumes:
          - postgres_data:/var/lib/postgresql/data
        networks:
          - yads-net

      redis:
        image: redis:7-alpine
        command: redis-server --appendonly yes
        restart: always
        volumes:
          - redis_data:/data
        networks:
          - yads-net

    volumes:
      postgres_data:
      redis_data:

    networks:
      yads-net:
        driver: bridge
    ```

3.  **Start the Stack**
    Run the following command to pull images and start services:
    ```bash
    docker compose up -d
    ```

4.  **Verify Installation**
    Check that all containers are running:
    ```bash
    docker compose ps
    ```
    You should see `yads-api`, `yads-worker`, `db`, and `redis` in the `Up` state.

---

## 3. Data Persistence & Backup

### Volumes

*   **postgres_data**: Stores the entire relational database state. This is the **most critical** volume.
*   **redis_data**: Stores the Redis AOF file, ensuring the task queue and scan cache survive restarts.

### Backup Strategy

YADS includes built-in backup tools.
*   **Automated**: The API container runs a script `/app/scripts/backup_db.sh` on startup.
*   **Manual**: You can trigger a full system backup (Database + Screenshots) from the Web UI under `Settings > Backup & Restore`. The resulting ZIP file is encrypted and password-protected.
