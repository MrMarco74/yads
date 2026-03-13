#!/usr/bin/env python3
"""
Distributed Worker Startup Script

This script starts a secondary worker node that connects to a central YADS manager.
It handles:
- Registration with the manager using a pre-shared token
- Heartbeat background thread
- Celery worker process management

Environment Variables:
    MANAGER_URL: URL of the YADS API manager (e.g., http://yads-api:8000)
    WORKER_REGISTRATION_TOKEN: Pre-shared token for registration
    WORKER_MODE: Set to "secondary" (this script sets it automatically)
    WORKER_CAPABILITIES: Comma-separated list of scan types (default: all)
    WORKER_MAX_TASKS: Maximum concurrent tasks (default: 4)
    WORKER_MAX_NETWORK_MBPS: Network bandwidth limit (default: 100)
    DATABASE_URL: PostgreSQL connection string (required)
    REDIS_URL: Redis connection string (required)

Usage:
    # Set environment variables first
    export MANAGER_URL=http://yads-api:8000
    export WORKER_REGISTRATION_TOKEN=your_token_here
    export DATABASE_URL=postgresql://user:pass@host:5432/yads
    export REDIS_URL=redis://redis:6379/0

    # Run the script
    python scripts/start_distributed_worker.py

    # Or with Docker
    docker run -e MANAGER_URL=... -e WORKER_REGISTRATION_TOKEN=... yads-worker
"""

import os
import sys

# Ensure /app is in path so we can import yads
sys.path.insert(0, '/app')

import time
import signal
import logging
import threading
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
)
logger = logging.getLogger("distributed-worker")


def check_environment():
    """Verify required environment variables are set."""
    required_vars = ["MANAGER_URL", "WORKER_REGISTRATION_TOKEN", "DATABASE_URL", "REDIS_URL"]
    missing = [var for var in required_vars if not os.getenv(var)]

    if missing:
        logger.error(f"Missing required environment variables: {', '.join(missing)}")
        logger.error("Please set these variables before starting the worker.")
        sys.exit(1)

    # Set worker mode to secondary
    os.environ["WORKER_MODE"] = "secondary"
    logger.info("Environment validated. Worker mode set to 'secondary'.")


def wait_for_manager(max_attempts=30, delay=5):
    """Wait for the manager API to become available."""
    import requests

    manager_url = os.getenv("MANAGER_URL")
    health_url = f"{manager_url}/docs"  # FastAPI docs endpoint as health check

    logger.info(f"Waiting for manager at {manager_url}...")

    for attempt in range(max_attempts):
        try:
            response = requests.get(health_url, timeout=5)
            if response.status_code == 200:
                logger.info("Manager is available.")
                return True
        except requests.exceptions.RequestException:
            pass

        logger.info(f"Manager not ready, retrying in {delay}s... ({attempt + 1}/{max_attempts})")
        time.sleep(delay)

    logger.error("Manager did not become available in time.")
    return False


def wait_for_redis(max_attempts=30, delay=2):
    """Wait for Redis to become available."""
    import redis

    redis_url = os.getenv("REDIS_URL")
    logger.info(f"Waiting for Redis at {redis_url}...")

    for attempt in range(max_attempts):
        try:
            client = redis.from_url(redis_url)
            client.ping()
            logger.info("Redis is available.")
            return True
        except redis.exceptions.ConnectionError:
            pass

        logger.info(f"Redis not ready, retrying in {delay}s... ({attempt + 1}/{max_attempts})")
        time.sleep(delay)

    logger.error("Redis did not become available in time.")
    return False


def wait_for_database(max_attempts=30, delay=2):
    """Wait for PostgreSQL to become available."""
    from sqlalchemy import create_engine, text

    db_url = os.getenv("DATABASE_URL")
    logger.info(f"Waiting for database...")

    for attempt in range(max_attempts):
        try:
            engine = create_engine(db_url)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Database is available.")
            return True
        except Exception:
            pass

        logger.info(f"Database not ready, retrying in {delay}s... ({attempt + 1}/{max_attempts})")
        time.sleep(delay)

    logger.error("Database did not become available in time.")
    return False


def register_with_manager():
    """Register this worker with the central manager."""
    from yads.core.worker_client import create_worker_client

    logger.info("Registering with manager...")

    client = create_worker_client()

    if not client.register():
        logger.error("Failed to register with manager. Check your registration token.")
        return None

    logger.info(f"Successfully registered as: {client.node_id}")
    return client


def _capabilities_to_queues(capabilities: list) -> str:
    """
    Map WORKER_CAPABILITIES to Celery queue list.

    Recognised capability → queue mappings:
      all        → celery,discovery  (handle everything)
      discovery  → discovery         (dedicated discovery worker)
      (anything else) → celery       (standard scan worker, no discovery)

    Callers can also set WORKER_QUEUES directly to override this logic.
    """
    if "WORKER_QUEUES" in os.environ:
        return os.environ["WORKER_QUEUES"]

    queues = {"celery"}  # always include the default scan queue
    if "all" in capabilities or "discovery" in capabilities:
        queues.add("discovery")

    return ",".join(sorted(queues))


def start_celery_worker():
    """Start the Celery worker process."""
    from yads.worker import celery_app

    # Get concurrency from environment
    concurrency = int(os.getenv("WORKER_MAX_TASKS", 4))

    # Derive queue list from capabilities
    capabilities_str = os.getenv("WORKER_CAPABILITIES", "all")
    capabilities = [c.strip() for c in capabilities_str.split(",")]
    queues = _capabilities_to_queues(capabilities)

    logger.info(f"Starting Celery worker with concurrency={concurrency}, queues={queues}")

    # Run worker in current process
    celery_app.worker_main([
        "worker",
        f"--concurrency={concurrency}",
        "--loglevel=INFO",
        "--hostname=distributed-worker@%h",
        "-Q", queues,
        "--without-gossip",
        "--without-mingle",
        "--without-heartbeat"
    ])


class GracefulKiller:
    """Handle shutdown signals gracefully."""

    def __init__(self, worker_client):
        self.kill_now = False
        self.worker_client = worker_client
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        logger.info("Received shutdown signal. Stopping worker...")
        self.kill_now = True

        if self.worker_client:
            self.worker_client.stop_heartbeat()

        # Give time for current tasks to complete
        logger.info("Waiting for current tasks to complete...")
        time.sleep(5)

        logger.info("Worker stopped.")
        sys.exit(0)


def main():
    """Main entry point for distributed worker."""
    logger.info("=" * 60)
    logger.info("YADS Distributed Worker Starting")
    logger.info("=" * 60)

    # Check environment
    check_environment()

    # Wait for dependencies
    if not wait_for_database():
        sys.exit(1)

    if not wait_for_redis():
        sys.exit(1)

    if not wait_for_manager():
        sys.exit(1)

    # Register with manager
    worker_client = register_with_manager()
    if not worker_client:
        sys.exit(1)

    # Start heartbeat
    worker_client.start_heartbeat()
    logger.info("Heartbeat thread started.")

    # Setup signal handler
    killer = GracefulKiller(worker_client)

    # Start Celery worker
    logger.info("Starting task processor...")
    try:
        start_celery_worker()
    except KeyboardInterrupt:
        logger.info("Worker interrupted.")
    finally:
        worker_client.stop_heartbeat()


if __name__ == "__main__":
    main()
