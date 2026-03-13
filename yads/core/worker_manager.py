"""
Worker Manager Service

Central coordinator for distributed worker management.
Handles worker registration, heartbeat processing, task routing,
and resource limit enforcement.
"""

import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

from sqlmodel import Session, select, text
from passlib.context import CryptContext

from yads.models import WorkerNode, WorkerTask, ResourceQuota, Target, SystemConfig
from yads.database import engine

logger = logging.getLogger("yads-worker-manager")

# Token hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Constants
HEARTBEAT_INTERVAL_SECONDS = 30
OFFLINE_THRESHOLD_SECONDS = 180  # Mark offline after 3 missed heartbeats
MAX_LOAD_THRESHOLD = 0.8  # 80% load threshold for routing


@dataclass
class WorkerMetrics:
    """Metrics reported by worker during heartbeat."""
    current_tasks: int
    current_load: float
    memory_used_mb: int
    cpu_percent: float
    active_scan_types: List[str]


@dataclass
class RegistrationRequest:
    """Request to register a new worker node."""
    hostname: str
    ip_address: str
    registration_token: str
    capabilities: List[str]
    max_concurrent_tasks: int = 4
    max_network_mbps: float = 100.0
    version: Optional[str] = None
    cpu_count: Optional[int] = None
    memory_mb: Optional[int] = None


@dataclass
class RegistrationResponse:
    """Response after successful worker registration."""
    node_id: str
    auth_token: str
    heartbeat_interval: int


class WorkerManager:
    """
    Central coordinator for distributed worker management.

    Responsibilities:
    - Worker registration with token validation
    - Heartbeat processing and health monitoring
    - Task routing with load balancing
    - Resource limit enforcement
    - Orphaned task requeuing on worker failure
    """

    def __init__(self, session: Session = None):
        self._session = session

    def _get_session(self) -> Session:
        """Get or create a database session."""
        if self._session:
            return self._session
        return Session(engine)

    def _should_close_session(self) -> bool:
        """Check if we created the session and should close it."""
        return self._session is None

    # =========================================================================
    # Registration Token Management
    # =========================================================================

    def get_registration_token(self) -> str:
        """Get the current registration token from SystemConfig."""
        with self._get_session() as session:
            config = session.get(SystemConfig, "WORKER_REGISTRATION_TOKEN")
            if config:
                return config.value
            return ""

    def generate_registration_token(self) -> str:
        """Generate and store a new registration token."""
        token = secrets.token_urlsafe(32)
        with self._get_session() as session:
            config = session.get(SystemConfig, "WORKER_REGISTRATION_TOKEN")
            if config:
                config.value = token
            else:
                config = SystemConfig(
                    key="WORKER_REGISTRATION_TOKEN",
                    value=token,
                    description="Pre-shared token for worker registration"
                )
            session.add(config)
            session.commit()
        logger.info("Generated new worker registration token")
        return token

    def _validate_registration_token(self, token: str) -> bool:
        """Validate a registration token against stored value."""
        stored_token = self.get_registration_token()
        if not stored_token:
            return False
        return secrets.compare_digest(token, stored_token)

    # =========================================================================
    # Worker Registration
    # =========================================================================

    def register_worker(self, request: RegistrationRequest) -> Optional[RegistrationResponse]:
        """
        Register a new worker node.

        Args:
            request: Registration details from the worker

        Returns:
            RegistrationResponse with node_id and auth_token, or None if failed
        """
        # Validate registration token
        if not self._validate_registration_token(request.registration_token):
            logger.warning(f"Invalid registration token from {request.hostname}")
            return None

        # Generate unique node_id
        node_id = self._generate_node_id(request.hostname)

        # Generate auth token for this worker
        auth_token = secrets.token_urlsafe(48)
        auth_token_hash = pwd_context.hash(auth_token)

        with self._get_session() as session:
            # Check if worker already exists
            existing = session.exec(
                select(WorkerNode).where(WorkerNode.node_id == node_id)
            ).first()

            if existing:
                # Update existing worker
                existing.ip_address = request.ip_address
                existing.auth_token_hash = auth_token_hash
                existing.status = "active"
                existing.is_active = True
                existing.last_heartbeat = datetime.utcnow()
                existing.capabilities = request.capabilities
                existing.max_concurrent_tasks = request.max_concurrent_tasks
                existing.max_network_mbps = request.max_network_mbps
                existing.version = request.version
                existing.cpu_count = request.cpu_count
                existing.memory_mb = request.memory_mb
                session.add(existing)
                session.commit()
                logger.info(f"Re-registered worker: {node_id}")
            else:
                # Create new worker
                worker = WorkerNode(
                    node_id=node_id,
                    hostname=request.hostname,
                    ip_address=request.ip_address,
                    auth_token_hash=auth_token_hash,
                    status="active",
                    is_active=True,
                    capabilities=request.capabilities,
                    max_concurrent_tasks=request.max_concurrent_tasks,
                    max_network_mbps=request.max_network_mbps,
                    version=request.version,
                    cpu_count=request.cpu_count,
                    memory_mb=request.memory_mb
                )
                session.add(worker)
                session.commit()
                logger.info(f"Registered new worker: {node_id}")

        return RegistrationResponse(
            node_id=node_id,
            auth_token=auth_token,
            heartbeat_interval=HEARTBEAT_INTERVAL_SECONDS
        )

    def register_primary_worker(self) -> Optional[str]:
        """
        Auto-register the primary worker (runs on API node).
        Returns the node_id of the primary worker.
        """
        import socket
        hostname = socket.gethostname()

        # Get local IP
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = "127.0.0.1"

        node_id = self._generate_node_id(hostname, is_primary=True)

        with self._get_session() as session:
            # Atomic upsert — safe against race conditions when multiple
            # Celery worker processes start simultaneously.
            session.exec(text("""
                INSERT INTO workernode
                    (node_id, hostname, ip_address, is_primary, is_active,
                     registered_at, last_heartbeat, max_concurrent_tasks,
                     max_network_mbps, current_load, current_tasks,
                     auth_token_hash, status, capabilities, assigned_tenant_ids)
                VALUES
                    (:node_id, :hostname, :ip_address, true, true,
                     now(), now(), 4,
                     100.0, 0.0, 0,
                     :token_hash, 'active', '["all"]'::jsonb, '[]'::jsonb)
                ON CONFLICT (node_id) DO UPDATE SET
                    status        = 'active',
                    is_active     = true,
                    last_heartbeat = now(),
                    ip_address    = EXCLUDED.ip_address
            """).bindparams(
                node_id=node_id,
                hostname=hostname,
                ip_address=ip_address,
                token_hash=pwd_context.hash("primary-worker-no-auth")
            ))
            session.commit()
            logger.info(f"Registered primary worker: {node_id}")

        return node_id

    def _generate_node_id(self, hostname: str, is_primary: bool = False) -> str:
        """Generate a unique node ID from hostname."""
        if is_primary:
            return f"primary-{hostname}"

        # Hash hostname to create consistent ID
        hash_input = f"{hostname}-{secrets.token_hex(4)}"
        hash_val = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        return f"worker-{hostname}-{hash_val}"

    # =========================================================================
    # Heartbeat & Health Monitoring
    # =========================================================================

    def process_heartbeat(self, node_id: str, auth_token: str,
                          metrics: WorkerMetrics) -> Optional[str]:
        """
        Process a heartbeat from a worker.

        Args:
            node_id: The worker's unique ID
            auth_token: The worker's auth token
            metrics: Current worker metrics

        Returns:
            Requested action (stop, restart) if any, else None.
            Returns empty string if unauthorized (for backwards compat, effectively falsey).
        """
        with self._get_session() as session:
            worker = session.exec(
                select(WorkerNode).where(WorkerNode.node_id == node_id)
            ).first()

            if not worker:
                logger.warning(f"Heartbeat from unknown worker: {node_id}")
                return ""

            # Validate auth token (skip for primary)
            if not worker.is_primary:
                if not pwd_context.verify(auth_token, worker.auth_token_hash):
                    logger.warning(f"Invalid auth token for worker: {node_id}")
                    return ""

            # Update worker state
            worker.last_heartbeat = datetime.utcnow()
            worker.current_load = metrics.current_load
            worker.current_tasks = metrics.current_tasks

            # Update status based on metrics
            if worker.status == "draining" and metrics.current_tasks == 0:
                worker.status = "offline"
                worker.is_active = False
            elif worker.status not in ["suspended", "draining"]:
                worker.status = "active"
                worker.is_active = True

            # Check for requested actions
            action = worker.requested_action
            if action:
                worker.requested_action = None
                logger.info(f"Worker {node_id} heartbeat: returning requested action '{action}'")

            session.add(worker)
            session.commit()

        return action

    def check_worker_health(self) -> Dict[str, Any]:
        """
        Check health of all workers and mark stale ones as offline.

        Returns:
            Summary of health check results
        """
        now = datetime.utcnow()
        threshold = now - timedelta(seconds=OFFLINE_THRESHOLD_SECONDS)

        marked_offline = 0
        requeued_tasks = 0

        with self._get_session() as session:
            # Find stale workers
            stale_workers = session.exec(
                select(WorkerNode).where(
                    WorkerNode.is_active == True,
                    WorkerNode.last_heartbeat < threshold,
                    WorkerNode.is_primary == False  # Don't auto-offline primary
                )
            ).all()

            for worker in stale_workers:
                logger.warning(f"Worker {worker.node_id} marked offline (no heartbeat)")
                worker.status = "offline"
                worker.is_active = False
                session.add(worker)
                marked_offline += 1

                # Requeue orphaned tasks
                requeued = self._requeue_worker_tasks(session, worker.id)
                requeued_tasks += requeued

            session.commit()

        return {
            "workers_marked_offline": marked_offline,
            "tasks_requeued": requeued_tasks
        }

    def _requeue_worker_tasks(self, session: Session, worker_id: int) -> int:
        """Requeue tasks from a failed worker."""
        tasks = session.exec(
            select(WorkerTask).where(
                WorkerTask.worker_node_id == worker_id,
                WorkerTask.status.in_(["assigned", "running"])
            )
        ).all()

        requeued = 0
        for task in tasks:
            task.status = "queued"
            task.worker_node_id = None
            task.started_at = None
            task.error_message = "Worker went offline, task requeued"
            session.add(task)
            requeued += 1
            logger.info(f"Requeued task {task.task_id} from offline worker")

        return requeued

    # =========================================================================
    # Task Routing
    # =========================================================================

    def select_worker_for_task(self, scan_types: List[str],
                                tenant_id: Optional[int] = None) -> Optional[WorkerNode]:
        """
        Select the best worker for a given task.

        Algorithm:
        1. Check tenant quota not exceeded
        2. Get active workers with capacity (load < 80%)
        3. Filter by capability (supported scan types)
        4. Sort by load (least-loaded first)
        5. Return best worker or None
        """
        with self._get_session() as session:
            # Check tenant quota
            if tenant_id and not self._check_tenant_quota(session, tenant_id):
                logger.info(f"Tenant {tenant_id} quota exceeded, task will wait")
                return None

            # Get active workers
            workers = session.exec(
                select(WorkerNode).where(
                    WorkerNode.is_active == True,
                    WorkerNode.status == "active",
                    WorkerNode.current_load < MAX_LOAD_THRESHOLD
                )
            ).all()

            if not workers:
                return None

            # Filter by capacity, capability, and tenant assignment
            eligible = []
            for worker in workers:
                # Check task capacity
                if worker.current_tasks >= worker.max_concurrent_tasks:
                    continue

                # Check capabilities (empty = all, or specific types)
                if worker.capabilities and "all" not in worker.capabilities:
                    if not all(st in worker.capabilities for st in scan_types):
                        continue

                # Check tenant assignment (empty = all tenants, otherwise must match)
                if worker.assigned_tenant_ids and len(worker.assigned_tenant_ids) > 0:
                    if tenant_id not in worker.assigned_tenant_ids:
                        continue

                eligible.append(worker)

            if not eligible:
                return None

            # Sort by load (least loaded first)
            eligible.sort(key=lambda w: (w.current_load, w.current_tasks))

            return eligible[0]

    def assign_task_to_worker(self, task_id: str, target_id: int,
                               scan_types: List[str],
                               tenant_id: Optional[int] = None) -> Optional[str]:
        """
        Assign a task to an available worker.

        Returns:
            node_id of assigned worker, or None if no worker available
        """
        with self._get_session() as session:
            worker = self.select_worker_for_task(scan_types, tenant_id)

            if not worker:
                # Create task record in queued state
                task = WorkerTask(
                    task_id=task_id,
                    target_id=target_id,
                    tenant_id=tenant_id,
                    scan_types=scan_types,
                    status="queued"
                )
                session.add(task)
                session.commit()
                return None

            # Create task record assigned to worker
            task = WorkerTask(
                task_id=task_id,
                target_id=target_id,
                tenant_id=tenant_id,
                worker_node_id=worker.id,
                scan_types=scan_types,
                status="assigned",
                started_at=datetime.utcnow()
            )
            session.add(task)

            # Update worker load
            worker.current_tasks += 1
            session.add(worker)

            # Update tenant quota
            if tenant_id:
                self._increment_tenant_quota(session, tenant_id)

            session.commit()
            logger.info(f"Assigned task {task_id} to worker {worker.node_id}")
            return worker.node_id

    def report_task_started(self, task_id: str, worker_node_id: str) -> bool:
        """Report that a task has started execution."""
        with self._get_session() as session:
            task = session.exec(
                select(WorkerTask).where(WorkerTask.task_id == task_id)
            ).first()

            if task:
                task.status = "running"
                task.started_at = datetime.utcnow()
                session.add(task)
                session.commit()
                return True
            return False

    def report_task_completed(self, task_id: str, success: bool = True,
                               error_message: str = None) -> bool:
        """Report that a task has completed."""
        with self._get_session() as session:
            task = session.exec(
                select(WorkerTask).where(WorkerTask.task_id == task_id)
            ).first()

            if not task:
                return False

            task.status = "completed" if success else "failed"
            task.completed_at = datetime.utcnow()
            task.error_message = error_message
            session.add(task)

            # Decrement worker task count
            if task.worker_node_id:
                worker = session.get(WorkerNode, task.worker_node_id)
                if worker:
                    worker.current_tasks = max(0, worker.current_tasks - 1)
                    session.add(worker)

            # Decrement tenant quota
            if task.tenant_id:
                self._decrement_tenant_quota(session, task.tenant_id)

            session.commit()
            return True

    def update_task_progress(self, task_id: str, progress_percent: int,
                              current_module: str = None) -> bool:
        """Update task progress."""
        with self._get_session() as session:
            task = session.exec(
                select(WorkerTask).where(WorkerTask.task_id == task_id)
            ).first()

            if task:
                task.progress_percent = progress_percent
                task.current_module = current_module
                session.add(task)
                session.commit()
                return True
            return False

    # =========================================================================
    # Resource Quota Management
    # =========================================================================

    def _check_tenant_quota(self, session: Session, tenant_id: int) -> bool:
        """Check if tenant is within quota limits."""
        quota = session.exec(
            select(ResourceQuota).where(ResourceQuota.tenant_id == tenant_id)
        ).first()

        if not quota:
            # No specific quota, check global
            quota = session.exec(
                select(ResourceQuota).where(ResourceQuota.tenant_id == None)
            ).first()

        if not quota:
            return True  # No limits defined

        # Check concurrent scan limit
        if quota.current_concurrent_scans >= quota.max_concurrent_scans:
            return False

        # Check daily limit
        if quota.scans_today >= quota.max_daily_scans:
            return False

        return True

    def _increment_tenant_quota(self, session: Session, tenant_id: int):
        """Increment quota counters when task starts."""
        quota = session.exec(
            select(ResourceQuota).where(ResourceQuota.tenant_id == tenant_id)
        ).first()

        if quota:
            quota.current_concurrent_scans += 1
            quota.scans_today += 1
            session.add(quota)

    def _decrement_tenant_quota(self, session: Session, tenant_id: int):
        """Decrement concurrent quota when task completes."""
        quota = session.exec(
            select(ResourceQuota).where(ResourceQuota.tenant_id == tenant_id)
        ).first()

        if quota:
            quota.current_concurrent_scans = max(0, quota.current_concurrent_scans - 1)
            session.add(quota)

    def reset_daily_quotas(self):
        """Reset daily scan counters (should run at midnight)."""
        with self._get_session() as session:
            quotas = session.exec(select(ResourceQuota)).all()
            for quota in quotas:
                quota.scans_today = 0
                quota.last_reset_date = datetime.utcnow()
                session.add(quota)
            session.commit()
        logger.info("Reset daily quotas for all tenants")

    # =========================================================================
    # Worker Management Actions
    # =========================================================================

    def suspend_worker(self, node_id: str) -> bool:
        """Suspend a worker (stops accepting new tasks)."""
        with self._get_session() as session:
            worker = session.exec(
                select(WorkerNode).where(WorkerNode.node_id == node_id)
            ).first()

            if worker:
                worker.status = "suspended"
                session.add(worker)
                session.commit()
                logger.info(f"Suspended worker: {node_id}")
                return True
            return False

    def resume_worker(self, node_id: str) -> bool:
        """Resume a suspended worker."""
        with self._get_session() as session:
            worker = session.exec(
                select(WorkerNode).where(WorkerNode.node_id == node_id)
            ).first()

            if worker and worker.status == "suspended":
                worker.status = "active"
                worker.is_active = True
                session.add(worker)
                session.commit()
                logger.info(f"Resumed worker: {node_id}")
                return True
            return False

    def drain_worker(self, node_id: str) -> bool:
        """
        Drain a worker (finish current tasks, then go offline).
        """
        with self._get_session() as session:
            worker = session.exec(
                select(WorkerNode).where(WorkerNode.node_id == node_id)
            ).first()

            if worker:
                worker.status = "draining"
                session.add(worker)
                session.commit()
                logger.info(f"Draining worker: {node_id}")
                return True
            return False

    def request_worker_action(self, node_id: str, action: str) -> bool:
        """
        Request an action (stop, restart) to be picked up by the worker
        during its next heartbeat.
        """
        if action not in ["stop", "restart"]:
            return False

        with self._get_session() as session:
            worker = session.exec(
                select(WorkerNode).where(WorkerNode.node_id == node_id)
            ).first()

            if worker:
                worker.requested_action = action
                session.add(worker)
                session.commit()
                logger.info(f"Requested action '{action}' for worker: {node_id}")
                return True
            return False

    def remove_worker(self, node_id: str) -> bool:
        """Remove a worker from the cluster."""
        with self._get_session() as session:
            worker = session.exec(
                select(WorkerNode).where(WorkerNode.node_id == node_id)
            ).first()

            if worker:
                # Requeue any tasks
                self._requeue_worker_tasks(session, worker.id)

                # Delete worker
                session.delete(worker)
                session.commit()
                logger.info(f"Removed worker: {node_id}")
                return True
            return False

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get overall cluster statistics."""
        with self._get_session() as session:
            workers = session.exec(select(WorkerNode)).all()
            tasks = session.exec(
                select(WorkerTask).where(
                    WorkerTask.status.in_(["queued", "assigned", "running"])
                )
            ).all()

            active_workers = [w for w in workers if w.is_active]
            total_capacity = sum(w.max_concurrent_tasks for w in active_workers)
            total_running = sum(w.current_tasks for w in active_workers)

            return {
                "total_workers": len(workers),
                "active_workers": len(active_workers),
                "offline_workers": len([w for w in workers if w.status == "offline"]),
                "suspended_workers": len([w for w in workers if w.status == "suspended"]),
                "total_capacity": total_capacity,
                "total_running_tasks": total_running,
                "queued_tasks": len([t for t in tasks if t.status == "queued"]),
                "utilization_percent": (total_running / total_capacity * 100) if total_capacity > 0 else 0
            }

    def get_metrics_snapshot(self) -> Dict[str, Any]:
        """
        Get a snapshot of metrics for Prometheus collection.

        Returns a dict optimized for metrics collection, including:
        - Worker counts by status
        - Queue depth
        - Capacity and utilization
        - Active scan count
        """
        with self._get_session() as session:
            workers = session.exec(select(WorkerNode)).all()
            tasks = session.exec(
                select(WorkerTask).where(
                    WorkerTask.status.in_(["queued", "assigned", "running"])
                )
            ).all()

            # Count workers by status
            workers_by_status = {
                "online": 0,
                "offline": 0,
                "suspended": 0,
                "draining": 0
            }
            for w in workers:
                if w.is_active and w.status == "active":
                    workers_by_status["online"] += 1
                elif w.status == "offline":
                    workers_by_status["offline"] += 1
                elif w.status == "suspended":
                    workers_by_status["suspended"] += 1
                elif w.status == "draining":
                    workers_by_status["draining"] += 1

            active_workers = [w for w in workers if w.is_active and w.status == "active"]
            total_capacity = sum(w.max_concurrent_tasks for w in active_workers)
            total_running = sum(w.current_tasks or 0 for w in active_workers)

            return {
                "workers_by_status": workers_by_status,
                "total_workers": len(workers),
                "active_workers": len(active_workers),
                "total_capacity": total_capacity,
                "total_running_tasks": total_running,
                "queued_tasks": len([t for t in tasks if t.status == "queued"]),
                "running_tasks": len([t for t in tasks if t.status == "running"]),
                "utilization_percent": (total_running / total_capacity * 100) if total_capacity > 0 else 0
            }

    def get_worker_list(self) -> List[Dict[str, Any]]:
        """Get list of all workers with details."""
        with self._get_session() as session:
            workers = session.exec(
                select(WorkerNode).order_by(WorkerNode.registered_at.desc())
            ).all()

            return [
                {
                    "id": w.id,
                    "node_id": w.node_id,
                    "hostname": w.hostname,
                    "ip_address": w.ip_address,
                    "is_primary": w.is_primary,
                    "status": w.status,
                    "current_tasks": w.current_tasks,
                    "max_concurrent_tasks": w.max_concurrent_tasks,
                    "max_network_mbps": w.max_network_mbps,
                    "max_daily_scans": w.max_daily_scans,
                    "current_load": round(w.current_load * 100, 1),
                    "last_heartbeat": w.last_heartbeat.isoformat() if w.last_heartbeat else None,
                    "registered_at": w.registered_at.isoformat() if w.registered_at else None,
                    "version": w.version,
                    "capabilities": w.capabilities,
                    "assigned_tenant_ids": w.assigned_tenant_ids or [],
                    "description": w.description
                }
                for w in workers
            ]


# Global instance
worker_manager = WorkerManager()
