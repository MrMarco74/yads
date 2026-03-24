from fastapi import APIRouter, Depends, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from sqlmodel import Session, select, text
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import csv
import io

from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_user, RoleChecker
from yads.models import (
    User, Target, ScanResult, Tenant,
    ComplianceTrend, RemediationTask, ComplianceTargetStatus
)
import logging
logger = logging.getLogger(__name__)

try:
    from yads.modules.compliance import ComplianceScorer
    from yads.modules.compliance_frameworks import (
        get_framework_scorer, get_all_frameworks, FRAMEWORKS
    )
except ImportError:
    ComplianceScorer = None
    def get_framework_scorer(x):
        raise HTTPException(status_code=501, detail="Compliance Frameworks add-on is not installed.")
    get_all_frameworks = lambda: {}
    FRAMEWORKS = {}
    _compliance_available = False
else:
    _compliance_available = True
from yads.api.utils.date_filter import parse_date_range, get_date_range_display

router = APIRouter(prefix="/compliance", tags=["compliance"])
from yads.api.templating import templates

# Inject Globals
from yads.config import settings
templates.env.globals['settings'] = settings
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")


# Helper for sidebar
def get_all_tenants():
    from yads.database import engine
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()


templates.env.globals['get_available_tenants'] = get_all_tenants


# --- Pydantic Models ---
class RemediationTaskCreate(BaseModel):
    target_id: Optional[int] = None
    framework: str
    control_id: str
    finding_description: str
    title: str
    description: Optional[str] = None
    priority: str = "medium"
    due_date: Optional[datetime] = None
    assignee: Optional[str] = None


class RemediationTaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    due_date: Optional[datetime] = None
    assignee: Optional[str] = None


# --- Helper Functions ---
def get_latest_scan_results(session: Session, user: User, modules: List[str] = None):
    """Fetch latest scan results for compliance calculation."""
    if modules is None:
        modules = [
            'ssl_scanner', 'web_analyzer', 'cve_scanner',
            'infrastructure_scanner', 'port_scanner', 'nmap_scanner',
            'nuclei_scanner', 'content_discovery', 'dns_scanner',
            'subdomain_scanner', 'cloud_scanner'
        ]

    params = {}
    tenant_clause = ""

    if user.tenant_id:
        tenant_clause = "AND t.tenant_id = :tenant_id"
        params["tenant_id"] = user.tenant_id
    elif user.role != "admin":
        tenant_clause = "AND t.tenant_id IS NULL"

    modules_str = ", ".join(f":m_{i}" for i in range(len(modules)))
    for i, m in enumerate(modules):
        params[f"m_{i}"] = m

    query = f"""
        SELECT DISTINCT ON (s.target_id, s.module_name)
            s.target_id, s.module_name, s.data
        FROM scanresult s
        JOIN target t ON s.target_id = t.id
        WHERE s.module_name IN ({modules_str})
        AND t.is_archived = false
    """
    if tenant_clause:
        query += " " + tenant_clause
    query += " ORDER BY s.target_id, s.module_name, s.scanned_at DESC"

    return session.exec(text(query), params=params).all()


def build_target_data(targets: List[Target], scan_results) -> tuple:
    """Build target data structures for compliance scoring."""
    target_data = {t.id: {} for t in targets}
    target_map = {t.id: t.domain for t in targets}

    class MockResult:
        def __init__(self, tid, mod, d):
            self.target_id = tid
            self.module_name = mod
            self.data = d

    for r in scan_results:
        tid, mod, data = r[0], r[1], r[2]
        if tid in target_data:
            if mod not in target_data[tid]:
                target_data[tid][mod] = data

    return target_data, target_map


# --- API Endpoints ---

@router.get("/frameworks", response_class=JSONResponse)
async def list_frameworks():
    """List all available compliance frameworks."""
    return get_all_frameworks()


@router.get("/score/{framework}", response_class=JSONResponse)
async def get_framework_score(
    framework: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    """Get compliance score for a specific framework."""
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Framework {framework} not found")

    # Fetch targets
    targets_query = select(Target).where(Target.is_archived == False)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)

    all_targets = session.exec(targets_query).all()

    # Get scan results
    comp_results = get_latest_scan_results(session, user)
    target_data, target_map = build_target_data(all_targets, comp_results)

    # Calculate score
    scorer = get_framework_scorer(framework)
    stats = scorer.calculate_score(target_data, target_map)

    return {
        "framework": framework,
        "framework_name": scorer.framework_name,
        **stats
    }


@router.get("/target/{target_id}", response_class=JSONResponse)
async def get_target_compliance(
    target_id: int,
    framework: str = Query(default="soc2"),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    """Get per-target compliance breakdown."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Tenant check
    if user.tenant_id and target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Framework {framework} not found")

    # Get scan results for this target
    query = """
        SELECT DISTINCT ON (module_name)
            module_name, data
        FROM scanresult
        WHERE target_id = :target_id
        ORDER BY module_name, scanned_at DESC
    """
    results = session.exec(text(query), params={"target_id": target_id}).all()

    target_data = {target_id: {}}
    for mod, data in results:
        target_data[target_id][mod] = data

    target_map = {target_id: target.domain}

    # Calculate score
    scorer = get_framework_scorer(framework)
    stats = scorer.calculate_score(target_data, target_map)

    return {
        "target_id": target_id,
        "domain": target.domain,
        "framework": framework,
        **stats
    }


@router.get("/trend/{framework}", response_class=JSONResponse)
async def get_framework_trend(
    framework: str,
    days: int = Query(default=30, ge=7, le=365),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    """Get historical trend data for a framework (Chart.js format)."""
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Framework {framework} not found")

    cutoff = datetime.utcnow() - timedelta(days=days)

    query = select(ComplianceTrend).where(
        ComplianceTrend.framework == framework,
        ComplianceTrend.recorded_at >= cutoff
    )

    if user.tenant_id:
        query = query.where(ComplianceTrend.tenant_id == user.tenant_id)

    query = query.order_by(ComplianceTrend.recorded_at)
    trends = session.exec(query).all()

    # Format for Chart.js
    labels = [t.recorded_at.strftime("%Y-%m-%d") for t in trends]
    scores = [t.score for t in trends]
    passing = [t.passing_controls for t in trends]
    failing = [t.failing_controls for t in trends]

    return {
        "labels": labels,
        "datasets": [
            {
                "label": "Score",
                "data": scores,
                "borderColor": "rgb(99, 102, 241)",
                "backgroundColor": "rgba(99, 102, 241, 0.1)",
                "fill": True
            }
        ],
        "controls": {
            "passing": passing,
            "failing": failing
        }
    }


# --- Remediation Task Endpoints ---

@router.get("/remediation", response_class=JSONResponse)
async def list_remediation_tasks(
    framework: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    """List remediation tasks with optional filters."""
    query = select(RemediationTask)

    if user.tenant_id:
        query = query.where(RemediationTask.tenant_id == user.tenant_id)

    if framework:
        query = query.where(RemediationTask.framework == framework)
    if status:
        query = query.where(RemediationTask.status == status)
    if priority:
        query = query.where(RemediationTask.priority == priority)

    query = query.order_by(RemediationTask.created_at.desc())
    tasks = session.exec(query).all()

    # Check SLA breaches
    now = datetime.utcnow()
    result = []
    for task in tasks:
        task_dict = {
            "id": task.id,
            "target_id": task.target_id,
            "framework": task.framework,
            "control_id": task.control_id,
            "title": task.title,
            "description": task.description,
            "finding_description": task.finding_description,
            "priority": task.priority,
            "status": task.status,
            "due_date": task.due_date.isoformat() if task.due_date else None,
            "sla_breached": task.sla_breached or (task.due_date and task.due_date < now and task.status not in ["resolved", "wont_fix"]),
            "assignee": task.assignee,
            "created_at": task.created_at.isoformat(),
            "resolved_at": task.resolved_at.isoformat() if task.resolved_at else None
        }
        result.append(task_dict)

    return result


@router.post("/remediation", response_class=JSONResponse)
async def create_remediation_task(
    task_data: RemediationTaskCreate,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """Create a new remediation task."""
    tenant_id = user.tenant_id

    # If target specified, validate access
    if task_data.target_id:
        target = session.get(Target, task_data.target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        if user.tenant_id and target.tenant_id != user.tenant_id:
            raise HTTPException(status_code=403, detail="Access denied")
        tenant_id = target.tenant_id or tenant_id

    task = RemediationTask(
        tenant_id=tenant_id,
        target_id=task_data.target_id,
        framework=task_data.framework,
        control_id=task_data.control_id,
        finding_description=task_data.finding_description,
        title=task_data.title,
        description=task_data.description,
        priority=task_data.priority,
        due_date=task_data.due_date,
        assignee=task_data.assignee
    )

    session.add(task)
    session.commit()
    session.refresh(task)

    return {"id": task.id, "message": "Task created successfully"}


@router.put("/remediation/{task_id}", response_class=JSONResponse)
async def update_remediation_task(
    task_id: int,
    task_data: RemediationTaskUpdate,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """Update a remediation task."""
    task = session.get(RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if user.tenant_id and task.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Update fields
    if task_data.title is not None:
        task.title = task_data.title
    if task_data.description is not None:
        task.description = task_data.description
    if task_data.priority is not None:
        task.priority = task_data.priority
    if task_data.status is not None:
        old_status = task.status
        task.status = task_data.status
        if task_data.status in ["resolved", "wont_fix"] and old_status not in ["resolved", "wont_fix"]:
            task.resolved_at = datetime.utcnow()
    if task_data.due_date is not None:
        task.due_date = task_data.due_date
    if task_data.assignee is not None:
        task.assignee = task_data.assignee

    # Check SLA breach
    if task.due_date and task.due_date < datetime.utcnow() and task.status not in ["resolved", "wont_fix"]:
        task.sla_breached = True

    session.add(task)
    session.commit()

    return {"message": "Task updated successfully"}


@router.delete("/remediation/{task_id}", response_class=JSONResponse)
async def delete_remediation_task(
    task_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"]))
):
    """Delete a remediation task."""
    task = session.get(RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if user.tenant_id and task.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    session.delete(task)
    session.commit()

    return {"message": "Task deleted successfully"}


# --- Export Endpoints ---

@router.get("/export/csv")
async def export_compliance_csv(
    framework: str = Query(default="soc2"),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    """Export compliance data as CSV."""
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Framework {framework} not found")

    # Fetch targets
    targets_query = select(Target).where(Target.is_archived == False)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)

    all_targets = session.exec(targets_query).all()

    # Get scan results
    comp_results = get_latest_scan_results(session, user)
    target_data, target_map = build_target_data(all_targets, comp_results)

    # Calculate per-target scores
    scorer = get_framework_scorer(framework)
    rows = []

    for target in all_targets:
        tid = target.id
        single_data = {tid: target_data.get(tid, {})}
        single_map = {tid: target.domain}
        stats = scorer.calculate_score(single_data, single_map)

        for finding in stats.get("findings", []):
            rows.append({
                "Domain": target.domain,
                "Framework": framework.upper(),
                "Control ID": finding.get("control_id", ""),
                "Control Name": finding.get("control_name", ""),
                "Finding": finding.get("description", ""),
                "Severity": finding.get("severity", ""),
                "Deduction": finding.get("deduction", 0),
                "Score": stats.get("score", 100),
                "Grade": stats.get("grade", "A")
            })

    # Generate CSV
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    else:
        output.write("No findings detected\n")

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=compliance_{framework}_{datetime.utcnow().strftime('%Y%m%d')}.csv"
        }
    )


@router.get("/export/pdf")
async def export_compliance_pdf(
    framework: str = Query(default="soc2"),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    """Export compliance report as PDF."""
    try:
        from yads.modules.compliance_report_generator import generate_compliance_report
    except ImportError:
        raise HTTPException(status_code=503, detail="Compliance Report Generator module not available.")

    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Framework {framework} not found")

    # Fetch targets
    targets_query = select(Target).where(Target.is_archived == False)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)

    all_targets = session.exec(targets_query).all()

    # Get scan results
    comp_results = get_latest_scan_results(session, user)
    target_data, target_map = build_target_data(all_targets, comp_results)

    # Calculate scores
    scorer = get_framework_scorer(framework)
    overall_stats = scorer.calculate_score(target_data, target_map)

    # Per-target breakdown
    per_target = []
    for target in all_targets:
        tid = target.id
        single_data = {tid: target_data.get(tid, {})}
        single_map = {tid: target.domain}
        stats = scorer.calculate_score(single_data, single_map)
        per_target.append({
            "domain": target.domain,
            "score": stats.get("score", 100),
            "grade": stats.get("grade", "A"),
            "passing": stats.get("passing_controls", 0),
            "failing": stats.get("failing_controls", 0),
            "findings": stats.get("findings", [])
        })

    # Get remediation tasks
    tasks_query = select(RemediationTask).where(
        RemediationTask.framework == framework,
        RemediationTask.status.in_(["open", "in_progress"])
    )
    if user.tenant_id:
        tasks_query = tasks_query.where(RemediationTask.tenant_id == user.tenant_id)

    tasks = session.exec(tasks_query).all()

    # Get tenant name
    tenant_name = "Global"
    if user.tenant_id:
        tenant = session.get(Tenant, user.tenant_id)
        if tenant:
            tenant_name = tenant.name

    # Generate PDF
    pdf_bytes = generate_compliance_report(
        framework=framework,
        framework_name=scorer.framework_name,
        overall_stats=overall_stats,
        per_target=per_target,
        remediation_tasks=tasks,
        tenant_name=tenant_name
    )

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=compliance_{framework}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
        }
    )


# --- HTMX Partials ---

@router.get("/rows", response_class=HTMLResponse)
async def compliance_target_rows(
    request: Request,
    framework: str = Query(default="soc2"),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    """HTMX partial for per-target compliance table rows."""
    if framework not in FRAMEWORKS:
        return HTMLResponse("<tr><td colspan='6'>Invalid framework</td></tr>")

    # Fetch targets
    targets_query = select(Target).where(Target.is_archived == False)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)

    all_targets = session.exec(targets_query).all()

    # Get scan results
    comp_results = get_latest_scan_results(session, user)
    target_data, target_map = build_target_data(all_targets, comp_results)

    # Calculate per-target scores
    scorer = get_framework_scorer(framework)
    target_scores = []

    for target in all_targets:
        tid = target.id
        single_data = {tid: target_data.get(tid, {})}
        single_map = {tid: target.domain}
        stats = scorer.calculate_score(single_data, single_map)

        # Count severity levels
        critical = sum(1 for f in stats.get("findings", []) if f.get("severity") == "critical")
        high = sum(1 for f in stats.get("findings", []) if f.get("severity") == "high")

        target_scores.append({
            "id": target.id,
            "domain": target.domain,
            "score": stats.get("score", 100),
            "grade": stats.get("grade", "A"),
            "passing": stats.get("passing_controls", 0),
            "failing": stats.get("failing_controls", 0),
            "critical": critical,
            "high": high
        })

    # Sort by score ascending (worst first)
    target_scores.sort(key=lambda x: x["score"])

    return templates.TemplateResponse("_compliance_target_rows.html", {
        "request": request,
        "targets": target_scores,
        "framework": framework
    })


# --- Main Dashboard ---

@router.get("/", response_class=HTMLResponse)
async def compliance_dashboard(
    request: Request,
    framework: str = Query(default="soc2"),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    """Enhanced compliance dashboard with multi-framework support."""
    if not _compliance_available:
        return templates.TemplateResponse("addons_locked.html", {
            "request": request,
            "user": user,
            "catalog": [],
        })
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    date_range_display = get_date_range_display(from_dt, to_dt, preset)

    # Validate framework
    if framework not in FRAMEWORKS:
        framework = "soc2"

    # Fetch targets
    targets_query = select(Target).where(Target.is_archived == False)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)

    all_targets = session.exec(targets_query).all()

    # Get scan results
    comp_results = get_latest_scan_results(session, user)
    target_data, target_map = build_target_data(all_targets, comp_results)

    # Calculate score
    scorer = get_framework_scorer(framework)
    stats = scorer.calculate_score(target_data, target_map)

    # Get all frameworks for tabs
    frameworks = get_all_frameworks()

    # Get trend data (last 30 days)
    cutoff = datetime.utcnow() - timedelta(days=30)
    trend_query = select(ComplianceTrend).where(
        ComplianceTrend.framework == framework,
        ComplianceTrend.recorded_at >= cutoff
    )
    if user.tenant_id:
        trend_query = trend_query.where(ComplianceTrend.tenant_id == user.tenant_id)
    trend_query = trend_query.order_by(ComplianceTrend.recorded_at)
    trends = session.exec(trend_query).all()

    trend_labels = [t.recorded_at.strftime("%m/%d") for t in trends]
    trend_scores = [t.score for t in trends]

    # Calculate per-target scores for table
    target_scores = []
    for target in all_targets[:20]:  # Limit initial load
        tid = target.id
        single_data = {tid: target_data.get(tid, {})}
        single_map = {tid: target.domain}
        t_stats = scorer.calculate_score(single_data, single_map)

        critical = sum(1 for f in t_stats.get("findings", []) if f.get("severity") == "critical")
        high = sum(1 for f in t_stats.get("findings", []) if f.get("severity") == "high")

        target_scores.append({
            "id": target.id,
            "domain": target.domain,
            "score": t_stats.get("score", 100),
            "grade": t_stats.get("grade", "A"),
            "passing": t_stats.get("passing_controls", 0),
            "failing": t_stats.get("failing_controls", 0),
            "critical": critical,
            "high": high
        })

    target_scores.sort(key=lambda x: x["score"])

    # Get open remediation tasks
    tasks_query = select(RemediationTask).where(
        RemediationTask.framework == framework,
        RemediationTask.status.in_(["open", "in_progress"])
    )
    if user.tenant_id:
        tasks_query = tasks_query.where(RemediationTask.tenant_id == user.tenant_id)
    tasks_query = tasks_query.order_by(RemediationTask.created_at.desc()).limit(10)
    remediation_tasks = session.exec(tasks_query).all()

    # Check SLA breaches
    now = datetime.utcnow()
    for task in remediation_tasks:
        if task.due_date and task.due_date < now and task.status not in ["resolved", "wont_fix"]:
            task.sla_breached = True

    return templates.TemplateResponse("compliance_dashboard.html", {
        "request": request,
        "user": user,
        "stats": stats,
        "framework": framework,
        "framework_name": scorer.framework_name,
        "frameworks": frameworks,
        "trend_labels": trend_labels,
        "trend_scores": trend_scores,
        "targets": target_scores,
        "total_targets": len(all_targets),
        "remediation_tasks": remediation_tasks,
        "controls": scorer.controls,
        "date_range_display": date_range_display
    })
