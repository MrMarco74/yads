"""
Workers API Router

Endpoints for distributed worker management:
- Worker registration and heartbeat
- Worker listing and status
- Suspend/Resume/Drain operations
- Unified log viewing with tenant filtering
"""

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, Request, Query, Header
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from datetime import datetime

from yads.auth.deps import get_current_user_html, RoleChecker, PlatformAdminChecker
from yads.models import User
from yads.core.worker_manager import (
    worker_manager, RegistrationRequest, WorkerMetrics,
    HEARTBEAT_INTERVAL_SECONDS
)
from yads.core.redis_logger import (
    get_unified_logs, get_tenant_logs, get_worker_logs,
    get_all_workers_network_info, get_worker_network_info
)

router = APIRouter(prefix="/api/workers", tags=["workers"])

# UI Router for pages
ui_router = APIRouter(prefix="/workers", tags=["workers-ui"])

# Templates for HTML fragments
from yads.config import settings

from yads.api.templating import templates
from yads.api.utils.celery_inspect import get_celery_worker_nodes
templates.env.globals['settings'] = settings

def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

# ── Known worker capabilities / queues ────────────────────────────────────────
# Each entry: (capability_key, label, description, celery_queue)
KNOWN_CAPABILITIES = [
    ("all",            "All Tasks",        "Handle every task type (standard scans + discovery)", "celery,discovery"),
    ("scanning",       "Standard Scans",   "DNS, SSL, web, nuclei, OSINT — regular scan queue",   "celery"),
    ("discovery",      "Recursive Discovery", "Dedicated discovery-session worker only",           "discovery"),
]

# Expose to templates
templates.env.globals['KNOWN_CAPABILITIES'] = KNOWN_CAPABILITIES


# =============================================================================
# Pydantic Models for Request/Response
# =============================================================================

class WorkerRegistrationRequest(BaseModel):
    """Request body for worker registration."""
    hostname: str
    ip_address: str
    registration_token: str
    capabilities: List[str] = ["all"]
    max_concurrent_tasks: int = 4
    max_network_mbps: float = 100.0
    version: Optional[str] = None
    cpu_count: Optional[int] = None
    memory_mb: Optional[int] = None


class WorkerRegistrationResponse(BaseModel):
    """Response after successful registration."""
    node_id: str
    auth_token: str
    heartbeat_interval: int


class HeartbeatRequest(BaseModel):
    """Request body for heartbeat."""
    current_tasks: int
    current_load: float
    memory_used_mb: int = 0
    cpu_percent: float = 0.0
    active_scan_types: List[str] = []


class TaskStartedRequest(BaseModel):
    """Request body for task started notification."""
    worker_node_id: str


class TaskCompletedRequest(BaseModel):
    """Request body for task completion notification."""
    success: bool = True
    error_message: Optional[str] = None


class TaskProgressRequest(BaseModel):
    """Request body for task progress update."""
    progress_percent: int
    current_module: Optional[str] = None


class ResourceQuotaUpdate(BaseModel):
    """Request body for updating resource quotas."""
    max_concurrent_scans: Optional[int] = None
    max_daily_scans: Optional[int] = None
    max_network_throughput_mbps: Optional[float] = None


class WorkerConfigUpdate(BaseModel):
    """Request body for updating worker configuration."""
    max_concurrent_tasks: Optional[int] = None
    max_network_mbps: Optional[float] = None
    max_daily_scans: Optional[int] = None
    capabilities: Optional[List[str]] = None
    assigned_tenant_ids: Optional[List[int]] = None
    description: Optional[str] = None


# =============================================================================
# Worker Registration (Public endpoint - uses registration token)
# =============================================================================

@router.post("/register", response_model=WorkerRegistrationResponse)
async def register_worker(request: WorkerRegistrationRequest):
    """
    Register a new worker node with the cluster.

    Requires a valid registration token (pre-shared).
    Returns node_id and auth_token for subsequent heartbeats.
    """
    reg_request = RegistrationRequest(
        hostname=request.hostname,
        ip_address=request.ip_address,
        registration_token=request.registration_token,
        capabilities=request.capabilities,
        max_concurrent_tasks=request.max_concurrent_tasks,
        max_network_mbps=request.max_network_mbps,
        version=request.version,
        cpu_count=request.cpu_count,
        memory_mb=request.memory_mb
    )

    result = worker_manager.register_worker(reg_request)

    if not result:
        raise HTTPException(status_code=401, detail="Invalid registration token")

    return WorkerRegistrationResponse(
        node_id=result.node_id,
        auth_token=result.auth_token,
        heartbeat_interval=result.heartbeat_interval
    )


# =============================================================================
# Heartbeat (Uses worker auth token)
# =============================================================================

@router.post("/{node_id}/heartbeat")
async def worker_heartbeat(
    node_id: str,
    request: HeartbeatRequest,
    authorization: str = Header(None)
):
    """
    Process heartbeat from a worker.

    Requires Authorization header with worker's auth_token.
    """
    # Extract token from header
    auth_token = ""
    if authorization and authorization.startswith("Bearer "):
        auth_token = authorization[7:]

    metrics = WorkerMetrics(
        current_tasks=request.current_tasks,
        current_load=request.current_load,
        memory_used_mb=request.memory_used_mb,
        cpu_percent=request.cpu_percent,
        active_scan_types=request.active_scan_types
    )

    action = worker_manager.process_heartbeat(node_id, auth_token, metrics)

    if action == "": # Unauthorized
        raise HTTPException(status_code=401, detail="Invalid worker or auth token")

    return {"status": "ok", "action": action}


# =============================================================================
# Task Reporting (Uses worker auth token)
# =============================================================================

@router.post("/tasks/{task_id}/started")
async def report_task_started(
    task_id: str,
    request: TaskStartedRequest,
    authorization: str = Header(None)
):
    """Report that a task has started execution."""
    success = worker_manager.report_task_started(task_id, request.worker_node_id)
    if not success:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"status": "ok"}


@router.post("/tasks/{task_id}/completed")
async def report_task_completed(
    task_id: str,
    request: TaskCompletedRequest,
    authorization: str = Header(None)
):
    """Report that a task has completed."""
    success = worker_manager.report_task_completed(
        task_id, request.success, request.error_message
    )
    if not success:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"status": "ok"}


@router.patch("/tasks/{task_id}/progress")
async def update_task_progress(
    task_id: str,
    request: TaskProgressRequest,
    authorization: str = Header(None)
):
    """Update task progress."""
    worker_manager.update_task_progress(
        task_id, request.progress_percent, request.current_module
    )
    return {"status": "ok"}


# =============================================================================
# Worker Management (Admin only)
# =============================================================================

@router.get("/")
async def list_workers(
    request: Request,
    user: User = Depends(PlatformAdminChecker())
):
    """List all registered workers."""
    workers = worker_manager.get_worker_list()
    
    # Check if HTMX request
    if request.headers.get("HX-Request"):
        if not workers:
            return HTMLResponse('''
                <div class="text-center py-4 text-gray-500">
                    <svg class="w-8 h-8 mx-auto mb-2 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                    </svg>
                    <p class="text-xs">No workers registered</p>
                    <p class="text-[10px] mt-1">Workers will appear here when they connect.</p>
                </div>
            ''')

        # Build HTML for each worker
        html_parts = []
        for w in workers:
            status_color = {
                "active": "bg-green-500",
                "offline": "bg-red-500",
                "suspended": "bg-yellow-500",
                "draining": "bg-amber-500",
                "pending": "bg-gray-500"
            }.get(w["status"], "bg-gray-500")

            primary_badge = '<span class="ml-1 px-1 py-0.5 text-[8px] bg-indigo-600 text-white rounded">PRIMARY</span>' if w["is_primary"] else ""

            # Configure button (always shown)
            config_btn = f'''
                <button hx-get="/api/workers/{w["node_id"]}/config"
                        hx-target="#worker-config-modal-content"
                        hx-swap="innerHTML"
                        onclick="document.getElementById('worker-config-modal').classList.remove('hidden')"
                        class="text-[9px] text-blue-400 hover:text-blue-300">Configure</button>
            '''

            actions = config_btn
            if not w["is_primary"]:
                if w["status"] == "active":
                    actions += f'''
                        <span class="text-gray-600">|</span>
                        <button hx-post="/api/workers/{w["node_id"]}/suspend" hx-swap="none" hx-confirm="Suspend worker {w["hostname"]}?"
                                class="text-[9px] text-yellow-400 hover:text-yellow-300">Suspend</button>
                        <span class="text-gray-600">|</span>
                        <button hx-post="/api/workers/{w["node_id"]}/drain" hx-swap="none" hx-confirm="Drain worker {w["hostname"]}?"
                                class="text-[9px] text-amber-400 hover:text-amber-300">Drain</button>
                    '''
                elif w["status"] == "suspended":
                    actions += f'''
                        <span class="text-gray-600">|</span>
                        <button hx-post="/api/workers/{w["node_id"]}/resume" hx-swap="none"
                                class="text-[9px] text-green-400 hover:text-green-300">Resume</button>
                    '''
                elif w["status"] in ["offline", "draining", "suspended"]:
                    actions += f'''
                        <span class="text-gray-600">|</span>
                        <button hx-delete="/api/workers/{w["node_id"]}" hx-swap="none" hx-confirm="Remove worker {w["hostname"]}?"
                                class="text-[9px] text-red-400 hover:text-red-300">Remove</button>
                    '''

            # Tenant assignment display
            tenant_info = ""
            assigned_tenants = w.get("assigned_tenant_ids", [])
            if assigned_tenants and len(assigned_tenants) > 0:
                tenant_info = f'<span class="text-[9px] text-cyan-400">{len(assigned_tenants)} tenant(s)</span>'
            else:
                tenant_info = '<span class="text-[9px] text-gray-600">all tenants</span>'

            html_parts.append(f'''
                <div class="flex items-center justify-between p-2 bg-gray-800 rounded border border-gray-700 hover:border-gray-600 transition-colors">
                    <div class="flex items-center gap-2 min-w-0">
                        <div class="w-2 h-2 rounded-full {status_color} flex-shrink-0"></div>
                        <div class="min-w-0">
                            <div class="flex items-center gap-1">
                                <span class="text-xs font-medium text-white truncate">{w["hostname"]}</span>
                                {primary_badge}
                            </div>
                            <div class="flex items-center gap-2 text-[10px] text-gray-500">
                                <span>{w["status"]}</span>
                                <span>•</span>
                                <span>{w["current_tasks"]}/{w["max_concurrent_tasks"]} tasks</span>
                                <span>•</span>
                                <span>{w["current_load"]}% load</span>
                                <span>•</span>
                                {tenant_info}
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center gap-2 flex-shrink-0">
                        {actions}
                    </div>
                </div>
            ''')

        return HTMLResponse(''.join(html_parts))

    return {"workers": workers}


@router.get("/stats")
async def get_cluster_stats(
    request: Request,
    user: User = Depends(PlatformAdminChecker())
):
    """Get cluster-wide statistics."""
    stats = worker_manager.get_cluster_stats()
    
    # Check if HTMX request
    if request.headers.get("HX-Request"):
        utilization = stats.get("utilization_percent", 0)
        util_color = "text-green-400" if utilization < 60 else ("text-yellow-400" if utilization < 80 else "text-red-400")

        return HTMLResponse(f'''
            <div class="grid grid-cols-4 gap-2 text-center">
                <div>
                    <div class="text-lg font-bold text-white">{stats.get("active_workers", 0)}</div>
                    <div class="text-[10px] text-gray-500">Active</div>
                </div>
                <div>
                    <div class="text-lg font-bold text-gray-400">{stats.get("offline_workers", 0)}</div>
                    <div class="text-[10px] text-gray-500">Offline</div>
                </div>
                <div>
                    <div class="text-lg font-bold text-white">{stats.get("total_running_tasks", 0)}/{stats.get("total_capacity", 0)}</div>
                    <div class="text-[10px] text-gray-500">Tasks</div>
                </div>
                <div>
                    <div class="text-lg font-bold {util_color}">{utilization:.0f}%</div>
                    <div class="text-[10px] text-gray-500">Utilization</div>
                </div>
            </div>
            <div class="mt-2 text-center text-[10px] text-gray-500">
                {stats.get("queued_tasks", 0)} tasks queued
            </div>
        ''')
        
    return stats


@router.get("/{node_id}")
async def get_worker_details(
    node_id: str,
    user: User = Depends(PlatformAdminChecker())
):
    """Get details for a specific worker."""
    workers = worker_manager.get_worker_list()
    worker = next((w for w in workers if w["node_id"] == node_id), None)

    if not worker:
        raise HTTPException(status_code=404, detail="Worker not found")

    return worker


@router.post("/{node_id}/suspend")
async def suspend_worker(
    node_id: str,
    user: User = Depends(PlatformAdminChecker())
):
    """Suspend a worker (stops accepting new tasks)."""
    success = worker_manager.suspend_worker(node_id)
    if not success:
        raise HTTPException(status_code=404, detail="Worker not found")
    return {"status": "suspended", "node_id": node_id}


@router.post("/{node_id}/resume")
async def resume_worker(
    node_id: str,
    user: User = Depends(PlatformAdminChecker())
):
    """Resume a suspended worker."""
    success = worker_manager.resume_worker(node_id)
    if not success:
        raise HTTPException(status_code=400, detail="Worker not found or not suspended")
    return {"status": "active", "node_id": node_id}


@router.post("/{node_id}/drain")
async def drain_worker(
    node_id: str,
    user: User = Depends(PlatformAdminChecker())
):
    """Drain a worker (finish current tasks, then go offline)."""
    success = worker_manager.drain_worker(node_id)
    if not success:
        raise HTTPException(status_code=404, detail="Worker not found")
    return {"status": "draining", "node_id": node_id}


@router.post("/{node_id}/stop")
async def stop_worker(
    node_id: str,
    user: User = Depends(PlatformAdminChecker())
):
    """Request a worker to stop/shutdown."""
    success = worker_manager.request_worker_action(node_id, "stop")
    if not success:
        raise HTTPException(status_code=404, detail="Worker not found")
    return {"status": "ok", "action": "stop", "node_id": node_id}


@router.post("/{node_id}/restart")
async def restart_worker(
    node_id: str,
    user: User = Depends(PlatformAdminChecker())
):
    """Request a worker to restart."""
    success = worker_manager.request_worker_action(node_id, "restart")
    if not success:
        raise HTTPException(status_code=404, detail="Worker not found")
    return {"status": "ok", "action": "restart", "node_id": node_id}


@router.delete("/offline/all")
async def remove_all_offline_workers(
    user: User = Depends(PlatformAdminChecker())
):
    """Remove all offline workers from the cluster."""
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import WorkerNode
    with Session(engine) as session:
        offline = session.exec(
            select(WorkerNode).where(WorkerNode.status == "offline")
        ).all()
        count = len(offline)
        for w in offline:
            session.delete(w)
        session.commit()
    return {"status": "removed", "count": count}


@router.delete("/{node_id}")
async def remove_worker(
    node_id: str,
    user: User = Depends(PlatformAdminChecker())
):
    """Remove a worker from the cluster."""
    success = worker_manager.remove_worker(node_id)
    if not success:
        raise HTTPException(status_code=404, detail="Worker not found")
    return {"status": "removed", "node_id": node_id}


@router.get("/{node_id}/config")
async def get_worker_config(
    node_id: str,
    request: Request,
    user: User = Depends(PlatformAdminChecker())
):
    """Get detailed configuration for a worker."""
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import WorkerNode, Tenant

    with Session(engine) as session:
        worker = session.exec(
            select(WorkerNode).where(WorkerNode.node_id == node_id)
        ).first()

        if not worker:
            raise HTTPException(status_code=404, detail="Worker not found")

        # Get tenant names for assigned tenants
        assigned_tenants = []
        if worker.assigned_tenant_ids:
            for tid in worker.assigned_tenant_ids:
                tenant = session.get(Tenant, tid)
                if tenant:
                    assigned_tenants.append({"id": tid, "name": tenant.name})

        # Get all tenants for selection
        all_tenants = session.exec(select(Tenant).order_by(Tenant.name)).all()

        config = {
            "id": worker.id,
            "node_id": worker.node_id,
            "hostname": worker.hostname,
            "ip_address": worker.ip_address,
            "is_primary": worker.is_primary,
            "status": worker.status,
            "max_concurrent_tasks": worker.max_concurrent_tasks,
            "max_network_mbps": worker.max_network_mbps,
            "max_daily_scans": worker.max_daily_scans,
            "capabilities": worker.capabilities or [],
            "assigned_tenant_ids": worker.assigned_tenant_ids or [],
            "assigned_tenants": assigned_tenants,
            "description": worker.description,
            "version": worker.version,
            "cpu_count": worker.cpu_count,
            "memory_mb": worker.memory_mb,
            "registered_at": worker.registered_at.isoformat() if worker.registered_at else None,
            "last_heartbeat": worker.last_heartbeat.isoformat() if worker.last_heartbeat else None,
            "current_tasks": worker.current_tasks,
            "current_load": worker.current_load
        }

        # Check if HTMX request for modal content
        if request.headers.get("HX-Request"):
            return templates.TemplateResponse("components/worker_config_modal.html", {
                "request": request,
                "worker": config,
                "tenants": all_tenants,
                "user": user
            })

        config["all_tenants"] = [{"id": t.id, "name": t.name} for t in all_tenants]
        return config


@router.put("/{node_id}/config")
async def update_worker_config(
    node_id: str,
    config: WorkerConfigUpdate,
    user: User = Depends(PlatformAdminChecker())
):
    """Update worker configuration."""
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import WorkerNode

    with Session(engine) as session:
        worker = session.exec(
            select(WorkerNode).where(WorkerNode.node_id == node_id)
        ).first()

        if not worker:
            raise HTTPException(status_code=404, detail="Worker not found")

        # Update fields if provided
        if config.max_concurrent_tasks is not None:
            worker.max_concurrent_tasks = config.max_concurrent_tasks
        if config.max_network_mbps is not None:
            worker.max_network_mbps = config.max_network_mbps
        if config.max_daily_scans is not None:
            worker.max_daily_scans = config.max_daily_scans if config.max_daily_scans > 0 else None
        if config.capabilities is not None:
            worker.capabilities = config.capabilities
        if config.assigned_tenant_ids is not None:
            worker.assigned_tenant_ids = config.assigned_tenant_ids
        if config.description is not None:
            worker.description = config.description if config.description.strip() else None

        session.add(worker)
        session.commit()
        session.refresh(worker)

        return {
            "status": "ok",
            "message": f"Worker {node_id} configuration updated",
            "node_id": node_id
        }


# =============================================================================
# Registration Token Management (Admin only)
# =============================================================================

@router.get("/token/current")
async def get_registration_token(
    request: Request,
    user: User = Depends(PlatformAdminChecker())
):
    """Get the current worker registration token."""
    token = worker_manager.get_registration_token()
    # Only show last 8 chars for security
    masked = "*" * 24 + token[-8:] if len(token) > 8 else token
    
    # Check if HTMX request
    if request.headers.get("HX-Request"):
        if not token:
            return HTMLResponse('''
                <span class="text-yellow-500">No token set. Click "Regenerate" to create one.</span>
            ''')

        import html as _html
        return HTMLResponse(f'''
            <span class="text-gray-300">{masked}</span>
            <button type="button"
                    data-token="{_html.escape(token)}"
                    onclick="navigator.clipboard.writeText(this.dataset.token).then(()=>this.textContent='Copied!')"
                    class="ml-2 text-[10px] text-emerald-400 hover:text-emerald-300">
                Copy
            </button>
        ''')
        
    return {"token_masked": masked, "is_set": bool(token)}


@router.post("/token/regenerate", response_class=HTMLResponse)
async def regenerate_registration_token(
    request: Request,
    user: User = Depends(PlatformAdminChecker())
):
    """Generate a new worker registration token."""
    token = worker_manager.generate_registration_token()

    # Check if HTMX request
    if request.headers.get("HX-Request"):
        import html as _html
        masked = "*" * 24 + token[-8:] if len(token) > 8 else token
        return HTMLResponse(f'''
            <span class="text-emerald-400">{masked}</span>
            <button type="button"
                    data-token="{_html.escape(token)}"
                    onclick="navigator.clipboard.writeText(this.dataset.token).then(()=>this.textContent='Copied!')"
                    class="ml-2 text-[10px] text-emerald-400 hover:text-emerald-300">
                Copy
            </button>
            <span class="ml-2 text-[10px] text-gray-500">(regenerated)</span>
        ''')

    return JSONResponse({"token": token, "message": "Token regenerated. Existing workers will need to re-register."})


# =============================================================================
# Unified Logs (Filtered by tenant access)
# =============================================================================

@router.get("/logs/unified")
async def get_unified_logs_api(
    limit: int = Query(100, ge=1, le=1000),
    since: Optional[float] = Query(None),
    tenant_id: Optional[int] = Query(None),
    worker_id: Optional[str] = Query(None),
    level: Optional[str] = Query(None),
    user: User = Depends(get_current_user_html)
):
    """
    Get unified logs with optional filtering.

    Platform admins can see all logs.
    Tenant admins can only see logs for their tenants.
    """
    # Enforce tenant filtering for non-admins
    if user.role != "admin" and user.tenant_id:
        tenant_id = user.tenant_id

    logs = get_unified_logs(
        limit=limit,
        since_timestamp=since,
        tenant_id=tenant_id,
        worker_node_id=worker_id,
        level=level
    )

    return {"logs": logs, "count": len(logs)}


@router.get("/logs/tenant/{tenant_id}")
async def get_tenant_logs_api(
    tenant_id: int,
    limit: int = Query(100, ge=1, le=1000),
    since: Optional[float] = Query(None),
    user: User = Depends(get_current_user_html)
):
    """Get logs for a specific tenant."""
    # Check access
    if user.role != "admin" and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    logs = get_tenant_logs(tenant_id, limit=limit, since_timestamp=since)
    return {"logs": logs, "count": len(logs)}


@router.get("/logs/worker/{worker_id}")
async def get_worker_logs_api(
    worker_id: str,
    limit: int = Query(100, ge=1, le=500),
    user: User = Depends(PlatformAdminChecker())
):
    """Get logs for a specific worker (admin only)."""
    logs = get_worker_logs(worker_id, limit=limit)
    return {"logs": logs, "count": len(logs)}


# =============================================================================
# Worker Network Info (Admin only)
# =============================================================================

@router.get("/network-info")
async def get_all_workers_network_info_api(
    user: User = Depends(PlatformAdminChecker())
):
    """
    Get network information (external IP, hostname) for all workers.

    This information is updated each time a worker processes a scan.
    """
    workers = get_all_workers_network_info()
    return {"workers": workers, "count": len(workers)}


@router.get("/network-info/{worker_id}")
async def get_worker_network_info_api(
    worker_id: str,
    user: User = Depends(PlatformAdminChecker())
):
    """Get network information for a specific worker."""
    info = get_worker_network_info(worker_id)
    if not info:
        raise HTTPException(status_code=404, detail="Worker network info not found")
    return {"worker_id": worker_id, "network_info": info}


# =============================================================================
# Health Check (Runs periodically to mark stale workers offline)
# =============================================================================

@router.post("/health-check")
async def run_health_check(user: User = Depends(PlatformAdminChecker())):
    """
    Manually trigger worker health check.

    Marks workers with stale heartbeats as offline and
    requeues their tasks.
    """
    result = worker_manager.check_worker_health()
    return result


# =============================================================================
# Resource Quotas (Admin only)
# =============================================================================

@router.get("/quotas")
async def list_resource_quotas(user: User = Depends(PlatformAdminChecker())):
    """List all resource quotas."""
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import ResourceQuota, Tenant

    with Session(engine) as session:
        quotas = session.exec(select(ResourceQuota)).all()
        result = []
        for q in quotas:
            tenant_name = None
            if q.tenant_id:
                tenant = session.get(Tenant, q.tenant_id)
                tenant_name = tenant.name if tenant else None

            result.append({
                "id": q.id,
                "tenant_id": q.tenant_id,
                "tenant_name": tenant_name,
                "max_concurrent_scans": q.max_concurrent_scans,
                "max_daily_scans": q.max_daily_scans,
                "max_network_throughput_mbps": q.max_network_throughput_mbps,
                "current_concurrent_scans": q.current_concurrent_scans,
                "scans_today": q.scans_today,
                "priority": q.priority
            })

        return {"quotas": result}


@router.post("/quotas/global")
async def set_global_quota(
    quota: ResourceQuotaUpdate,
    user: User = Depends(PlatformAdminChecker())
):
    """Set or update global resource quota."""
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import ResourceQuota

    with Session(engine) as session:
        existing = session.exec(
            select(ResourceQuota).where(ResourceQuota.tenant_id == None)
        ).first()

        if existing:
            if quota.max_concurrent_scans is not None:
                existing.max_concurrent_scans = quota.max_concurrent_scans
            if quota.max_daily_scans is not None:
                existing.max_daily_scans = quota.max_daily_scans
            if quota.max_network_throughput_mbps is not None:
                existing.max_network_throughput_mbps = quota.max_network_throughput_mbps
            session.add(existing)
        else:
            new_quota = ResourceQuota(
                tenant_id=None,
                max_concurrent_scans=quota.max_concurrent_scans or 50,
                max_daily_scans=quota.max_daily_scans or 5000,
                max_network_throughput_mbps=quota.max_network_throughput_mbps or 500
            )
            session.add(new_quota)

        session.commit()
        return {"status": "ok", "message": "Global quota updated"}


@router.post("/quotas/tenant/{tenant_id}")
async def set_tenant_quota(
    tenant_id: int,
    quota: ResourceQuotaUpdate,
    user: User = Depends(PlatformAdminChecker())
):
    """Set or update quota for a specific tenant."""
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import ResourceQuota

    with Session(engine) as session:
        existing = session.exec(
            select(ResourceQuota).where(ResourceQuota.tenant_id == tenant_id)
        ).first()

        if existing:
            if quota.max_concurrent_scans is not None:
                existing.max_concurrent_scans = quota.max_concurrent_scans
            if quota.max_daily_scans is not None:
                existing.max_daily_scans = quota.max_daily_scans
            if quota.max_network_throughput_mbps is not None:
                existing.max_network_throughput_mbps = quota.max_network_throughput_mbps
            session.add(existing)
        else:
            new_quota = ResourceQuota(
                tenant_id=tenant_id,
                max_concurrent_scans=quota.max_concurrent_scans or 10,
                max_daily_scans=quota.max_daily_scans or 1000,
                max_network_throughput_mbps=quota.max_network_throughput_mbps or 50
            )
            session.add(new_quota)

        session.commit()
        return {"status": "ok", "message": f"Quota updated for tenant {tenant_id}"}


@router.post("/quotas/reset-daily")
async def reset_daily_quotas(user: User = Depends(PlatformAdminChecker())):
    """Manually reset daily scan counters."""
    worker_manager.reset_daily_quotas()
    return {"status": "ok", "message": "Daily quotas reset"}


# =============================================================================
# UI Pages
# =============================================================================

@ui_router.get("", response_class=HTMLResponse)
async def worker_monitor_page(
    request: Request,
    user: User = Depends(PlatformAdminChecker())
):
    """Live worker monitor page."""
    import os
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import WorkerTask, WorkerNode, Target

    workers = worker_manager.get_worker_list()
    stats = worker_manager.get_cluster_stats()
    worker_mode = os.getenv("WORKER_MODE", "standalone").lower()

    # Fetch running tasks
    running_tasks = []
    with Session(engine) as session:
        if worker_mode == "standalone":
            import json as _json
            try:
                from redis import Redis as _Redis
                from yads.config import settings as _s
                _rc = _Redis.from_url(_s.REDIS_URL, decode_responses=True)
            except Exception:
                _rc = None

            # Find the primary worker node_id so tasks show up inside its card
            primary_node_id = next(
                (w.get("node_id") for w in workers if w.get("is_primary")),
                "standalone"
            )

            running_targets = session.exec(
                select(Target).where(Target.scan_status == "running")
            ).all()
            for tgt in running_targets:
                current_module = None
                started_at = None
                if _rc:
                    try:
                        status_msg = _rc.get(f"scan:status:{tgt.id}") or ""
                        # Show full status message (module + what it's doing)
                        if status_msg.startswith("[") and "]" in status_msg:
                            bracket_end = status_msg.index("]")
                            mod = status_msg[1:bracket_end]
                            rest = status_msg[bracket_end + 2:].strip()
                            current_module = f"{mod}: {rest[:50]}" if rest else mod
                        elif status_msg:
                            current_module = status_msg[:60]
                        # started_at from oldest log entry
                        first_entry = _rc.lindex(f"scan:logs:{tgt.id}", 0)
                        if first_entry:
                            ts = _json.loads(first_entry).get("ts", "")
                            if ts:
                                started_at = ts[11:19]
                    except Exception:
                        pass
                running_tasks.append({
                    "task_id": None,
                    "target_domain": tgt.domain,
                    "current_module": current_module,
                    "progress_percent": None,
                    "worker_node_id": primary_node_id,
                    "worker_hostname": "standalone",
                    "started_at": started_at,
                })

            # Patch stats for standalone
            n_running = len(running_targets)
            stats = dict(stats)
            stats["total_running_tasks"] = n_running
            # Read actual Celery concurrency from SystemConfig (source of truth)
            import multiprocessing as _mp
            actual_concurrency = max(1, _mp.cpu_count())
            try:
                conf = session.exec(
                    select(SystemConfig).where(SystemConfig.key == "WORKER_CONCURRENCY")
                ).first()
                if conf and conf.value:
                    actual_concurrency = max(1, int(conf.value))
            except Exception:
                pass
            stats["total_capacity"] = actual_concurrency
            cap = actual_concurrency
            stats["utilization_percent"] = round(n_running / cap * 100)
            # Celery queue depth via Redis
            try:
                stats["queued_tasks"] = _rc.llen("celery") if _rc else 0
            except Exception:
                stats["queued_tasks"] = 0

            # Update primary worker card to show real task count
            for w in workers:
                if w.get("node_id") == primary_node_id:
                    w["current_tasks"] = n_running
                    w["max_concurrent_tasks"] = actual_concurrency
                    w["current_load"] = round(n_running / cap * 100)
        else:
            db_tasks = session.exec(
                select(WorkerTask).where(WorkerTask.status == "running")
            ).all()
            for t in db_tasks:
                tgt = session.get(Target, t.target_id) if t.target_id else None
                wnode = session.get(WorkerNode, t.worker_node_id) if t.worker_node_id else None
                running_tasks.append({
                    "task_id": t.task_id,
                    "target_domain": tgt.domain if tgt else None,
                    "current_module": t.current_module,
                    "progress_percent": t.progress_percent,
                    "worker_node_id": wnode.node_id if wnode else None,
                    "worker_hostname": wnode.hostname if wnode else None,
                    "started_at": t.started_at.strftime("%H:%M:%S") if t.started_at else None,
                })

    return templates.TemplateResponse("workers.html", {
        "request": request,
        "user": user,
        "workers": workers,
        "stats": stats,
        "running_tasks": running_tasks,
        "worker_mode": worker_mode,
    })


@ui_router.post("/reset-stuck", response_class=JSONResponse)
async def reset_stuck_targets_now(
    request: Request,
    user: User = Depends(PlatformAdminChecker()),
):
    """Immediately reset all targets stuck in 'running' state (no active Celery task)."""
    from sqlmodel import Session, select, text as sql_text
    from datetime import datetime, timedelta, timezone
    from yads.database import engine
    from yads.models import Target

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=45)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S")

    with Session(engine) as session:
        result = session.execute(sql_text(
            "UPDATE target SET scan_status='idle', scan_progress=NULL "
            "WHERE scan_status = 'running' "
            "AND created_at < :cutoff"
        ), {"cutoff": cutoff_str})
        session.commit()
        reset_count = result.rowcount

    return JSONResponse({"reset": reset_count, "cutoff_minutes": 45})


@ui_router.get("/celery-nodes", response_class=HTMLResponse)
async def celery_nodes_partial(
    request: Request,
    user: User = Depends(PlatformAdminChecker()),
):
    """HTMX partial — Celery worker nodes (slow inspect call, loaded async)."""
    return templates.TemplateResponse("_celery_worker_nodes.html", {
        "request": request,
        "worker_nodes": get_celery_worker_nodes(),
    })


@ui_router.get("/logs", response_class=HTMLResponse)
async def unified_logs_page(
    request: Request,
    user: User = Depends(get_current_user_html)
):
    """Unified log viewer page."""
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant

    # Get tenants for filter dropdown — extract as dicts before session closes
    with Session(engine) as session:
        if user.role == "admin":
            rows = session.exec(select(Tenant).order_by(Tenant.name)).all()
        elif user.tenant_id:
            t = session.get(Tenant, user.tenant_id)
            rows = [t] if t else []
        else:
            rows = []
        tenants = [{"id": t.id, "name": t.name} for t in rows]

    # Get workers for filter dropdown
    workers = worker_manager.get_worker_list() if user.role == "admin" else []

    return templates.TemplateResponse("logs_unified.html", {
        "request": request,
        "user": user,
        "tenants": tenants,
        "workers": workers
    })



