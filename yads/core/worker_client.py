"""
Worker Client Service

Worker-side component for communication with the WorkerManager.
Handles registration, heartbeats, and task status reporting.
"""

import os
import socket
import sys
import threading
import time
import logging
import requests
import psutil
from typing import Optional, List, Callable
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger("yads-worker-client")


class WorkerMode(Enum):
    """Worker operating mode."""
    PRIMARY = "primary"
    SECONDARY = "secondary"
    STANDALONE = "standalone"  # No distributed coordination


@dataclass
class WorkerState:
    """Current worker state."""
    node_id: Optional[str] = None
    auth_token: Optional[str] = None
    is_registered: bool = False
    heartbeat_interval: int = 30
    manager_url: Optional[str] = None
    mode: WorkerMode = WorkerMode.STANDALONE


class WorkerClient:
    """
    Client for worker-to-manager communication.

    In PRIMARY mode:
        - Uses local database directly via WorkerManager
        - No HTTP communication needed

    In SECONDARY mode:
        - Communicates with manager via HTTP API
        - Requires manager_url and registration_token

    In STANDALONE mode:
        - No distributed coordination (backwards compatible)
    """

    def __init__(self, mode: WorkerMode = WorkerMode.STANDALONE,
                 manager_url: str = None,
                 registration_token: str = None,
                 capabilities: List[str] = None):
        self.state = WorkerState(mode=mode, manager_url=manager_url)
        self._registration_token = registration_token
        self._capabilities = capabilities or ["all"]
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_heartbeat = threading.Event()
        self._current_tasks: List[str] = []
        self._task_callbacks: dict = {}

        # Get hostname and IP
        self._hostname = socket.gethostname()
        try:
            self._ip_address = socket.gethostbyname(self._hostname)
        except:
            self._ip_address = "127.0.0.1"

        # For primary mode, import WorkerManager
        if mode == WorkerMode.PRIMARY:
            from yads.core.worker_manager import worker_manager
            self._manager = worker_manager
        else:
            self._manager = None

    @property
    def is_distributed(self) -> bool:
        """Check if running in distributed mode."""
        return self.state.mode != WorkerMode.STANDALONE

    @property
    def node_id(self) -> Optional[str]:
        """Get current node ID."""
        return self.state.node_id

    # =========================================================================
    # Registration
    # =========================================================================

    def register(self) -> bool:
        """
        Register this worker with the manager.

        Returns:
            True if registration successful
        """
        if self.state.mode == WorkerMode.STANDALONE:
            logger.info("Worker running in standalone mode, no registration needed")
            return True

        if self.state.mode == WorkerMode.PRIMARY:
            return self._register_primary()
        else:
            return self._register_secondary()

    def _register_primary(self) -> bool:
        """Register as primary worker using local database."""
        try:
            node_id = self._manager.register_primary_worker()
            if node_id:
                self.state.node_id = node_id
                self.state.is_registered = True
                logger.info(f"Registered as primary worker: {node_id}")
                return True
        except Exception as e:
            logger.error(f"Failed to register primary worker: {e}")
        return False

    def _register_secondary(self) -> bool:
        """Register as secondary worker via HTTP API."""
        if not self.state.manager_url or not self._registration_token:
            logger.error("Manager URL and registration token required for secondary worker")
            return False

        try:
            # Get system info
            cpu_count = psutil.cpu_count()
            memory_mb = psutil.virtual_memory().total // (1024 * 1024)

            from yads.config import settings
            version = settings.VERSION

            response = requests.post(
                f"{self.state.manager_url}/api/workers/register",
                json={
                    "hostname": self._hostname,
                    "ip_address": self._ip_address,
                    "registration_token": self._registration_token,
                    "capabilities": self._capabilities,
                    "max_concurrent_tasks": int(os.getenv("WORKER_MAX_TASKS", 4)),
                    "max_network_mbps": float(os.getenv("WORKER_MAX_NETWORK_MBPS", 100)),
                    "version": version,
                    "cpu_count": cpu_count,
                    "memory_mb": memory_mb
                },
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                self.state.node_id = data["node_id"]
                self.state.auth_token = data["auth_token"]
                self.state.heartbeat_interval = data.get("heartbeat_interval", 30)
                self.state.is_registered = True
                logger.info(f"Registered as secondary worker: {self.state.node_id}")
                return True
            else:
                logger.error(f"Registration failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to register secondary worker: {e}")
            return False

    # =========================================================================
    # Heartbeat
    # =========================================================================

    def start_heartbeat(self):
        """Start the heartbeat background thread."""
        if self.state.mode == WorkerMode.STANDALONE:
            return

        if not self.state.is_registered:
            logger.warning("Cannot start heartbeat: not registered")
            return

        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return

        self._stop_heartbeat.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="worker-heartbeat"
        )
        self._heartbeat_thread.start()
        logger.info("Heartbeat thread started")

    def stop_heartbeat(self):
        """Stop the heartbeat thread."""
        self._stop_heartbeat.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
        logger.info("Heartbeat thread stopped")

    def _heartbeat_loop(self):
        """Background heartbeat loop."""
        while not self._stop_heartbeat.is_set():
            try:
                self._send_heartbeat()
            except Exception as e:
                logger.error(f"Heartbeat failed: {e}")

            # Wait for next interval or stop signal
            self._stop_heartbeat.wait(timeout=self.state.heartbeat_interval)

    def _send_heartbeat(self):
        """Send a single heartbeat."""
        # Collect metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        load = cpu_percent / 100.0

        metrics = {
            "current_tasks": len(self._current_tasks),
            "current_load": load,
            "memory_used_mb": memory.used // (1024 * 1024),
            "cpu_percent": cpu_percent,
            "active_scan_types": []  # TODO: Track active scan types
        }

        if self.state.mode == WorkerMode.PRIMARY:
            # Use local manager
            from yads.core.worker_manager import WorkerMetrics
            action = self._manager.process_heartbeat(
                self.state.node_id,
                "",  # No auth needed for primary
                WorkerMetrics(**metrics)
            )
            if action:
                self._handle_manager_action(action)
        else:
            # HTTP API
            try:
                response = requests.post(
                    f"{self.state.manager_url}/api/workers/{self.state.node_id}/heartbeat",
                    json=metrics,
                    headers={"Authorization": f"Bearer {self.state.auth_token}"},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    action = data.get("action")
                    if action:
                        self._handle_manager_action(action)
                else:
                    logger.warning(f"Heartbeat returned {response.status_code}")
            except Exception as e:
                logger.error(f"Failed to send HTTP heartbeat: {e}")

    def _handle_manager_action(self, action: str):
        """Handle an action requested by the manager."""
        logger.info(f"Received action request from manager: {action}")

        if action == "stop":
            logger.warning("Manager requested STOP. Shutting down worker...")
            # Give a small delay for the response to be sent before exiting
            threading.Timer(2.0, lambda: sys.exit(0)).start()

        elif action == "restart":
            logger.warning("Manager requested RESTART. Restarting worker...")
            # Instruction for "restart" is to simply exit;
            # orchestrator (Docker/Swarm) will restart the container.
            threading.Timer(2.0, lambda: sys.exit(1)).start()

        else:
            logger.warning(f"Unknown manager action: {action}")

    # =========================================================================
    # Task Management
    # =========================================================================

    def report_task_started(self, task_id: str):
        """Report that a task has started."""
        if not self.is_distributed:
            return

        self._current_tasks.append(task_id)

        if self.state.mode == WorkerMode.PRIMARY:
            self._manager.report_task_started(task_id, self.state.node_id)
        else:
            try:
                requests.post(
                    f"{self.state.manager_url}/api/workers/tasks/{task_id}/started",
                    headers={"Authorization": f"Bearer {self.state.auth_token}"},
                    json={"worker_node_id": self.state.node_id},
                    timeout=10
                )
            except Exception as e:
                logger.error(f"Failed to report task start: {e}")

    def report_task_completed(self, task_id: str, success: bool = True,
                               error_message: str = None):
        """Report that a task has completed."""
        if task_id in self._current_tasks:
            self._current_tasks.remove(task_id)

        if not self.is_distributed:
            return

        if self.state.mode == WorkerMode.PRIMARY:
            self._manager.report_task_completed(task_id, success, error_message)
        else:
            try:
                requests.post(
                    f"{self.state.manager_url}/api/workers/tasks/{task_id}/completed",
                    headers={"Authorization": f"Bearer {self.state.auth_token}"},
                    json={
                        "success": success,
                        "error_message": error_message
                    },
                    timeout=10
                )
            except Exception as e:
                logger.error(f"Failed to report task completion: {e}")

    def update_task_progress(self, task_id: str, progress_percent: int,
                              current_module: str = None):
        """Update task progress."""
        if not self.is_distributed:
            return

        if self.state.mode == WorkerMode.PRIMARY:
            self._manager.update_task_progress(task_id, progress_percent, current_module)
        else:
            try:
                requests.patch(
                    f"{self.state.manager_url}/api/workers/tasks/{task_id}/progress",
                    headers={"Authorization": f"Bearer {self.state.auth_token}"},
                    json={
                        "progress_percent": progress_percent,
                        "current_module": current_module
                    },
                    timeout=10
                )
            except Exception as e:
                logger.debug(f"Failed to update task progress: {e}")

    # =========================================================================
    # Task Assignment (for distributed queue)
    # =========================================================================

    def claim_task(self, task_id: str, target_id: int,
                   scan_types: List[str], tenant_id: int = None) -> bool:
        """
        Attempt to claim a task for this worker.

        Used when processing tasks from Celery queue to register
        them with the worker manager.
        """
        if not self.is_distributed:
            return True

        if self.state.mode == WorkerMode.PRIMARY:
            assigned_node = self._manager.assign_task_to_worker(
                task_id, target_id, scan_types, tenant_id
            )
            return assigned_node is not None
        else:
            # Secondary workers don't claim tasks directly
            # They receive pre-assigned tasks
            return True

    # =========================================================================
    # Utility
    # =========================================================================

    def get_status(self) -> dict:
        """Get current worker client status."""
        return {
            "mode": self.state.mode.value,
            "node_id": self.state.node_id,
            "is_registered": self.state.is_registered,
            "manager_url": self.state.manager_url,
            "current_tasks": len(self._current_tasks),
            "hostname": self._hostname,
            "ip_address": self._ip_address
        }


# =========================================================================
# Factory Function
# =========================================================================

def create_worker_client() -> WorkerClient:
    """
    Create a WorkerClient based on environment configuration.

    Environment variables:
        WORKER_MODE: primary, secondary, or standalone (default)
        MANAGER_URL: URL of the manager API (required for secondary)
        WORKER_REGISTRATION_TOKEN: Token for registration (required for secondary)
        WORKER_CAPABILITIES: Comma-separated list of scan types
    """
    mode_str = os.getenv("WORKER_MODE", "standalone").lower()

    if mode_str == "primary":
        mode = WorkerMode.PRIMARY
    elif mode_str == "secondary":
        mode = WorkerMode.SECONDARY
    else:
        mode = WorkerMode.STANDALONE

    manager_url = os.getenv("MANAGER_URL")
    registration_token = os.getenv("WORKER_REGISTRATION_TOKEN")

    capabilities_str = os.getenv("WORKER_CAPABILITIES", "all")
    capabilities = [c.strip() for c in capabilities_str.split(",")]

    client = WorkerClient(
        mode=mode,
        manager_url=manager_url,
        registration_token=registration_token,
        capabilities=capabilities
    )

    return client


# Global worker client instance (lazy initialized)
_worker_client: Optional[WorkerClient] = None


def get_worker_client() -> WorkerClient:
    """Get or create the global worker client instance."""
    global _worker_client
    if _worker_client is None:
        _worker_client = create_worker_client()
    return _worker_client


def initialize_worker_client():
    """Initialize and register the worker client."""
    client = get_worker_client()
    if client.register():
        client.start_heartbeat()
    return client
