import logging
import json
import base64
from typing import Optional, List
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select, func, text
from datetime import datetime

from yads.database import get_session, redis_client
from yads.auth.deps import get_current_user_html, RoleChecker, get_current_active_user
from yads.models import User, Target, ScanResult, ModuleState, SecurityTrend, SystemConfig
from yads.api.templating import templates
from yads.api.utils.update_checker import UpdateService
from yads.modules.compliance import ComplianceScorer
from yads.core.scoring import calculate_target_score, get_grade

logger = logging.getLogger(__name__)


def _get_redis_queue_len(session, tenant_id) -> int:
    """
    Count queued + running tasks for the dashboard.
    - Pending: Redis llen (tasks not yet picked up by a worker)
    - Active:  DB scan_status == 'running' (picked up, currently executing)
    Both are fast operations with no blocking network calls.
    """
    count = 0

    # Use DB as source of truth: queued + running targets
    # This is reliable regardless of Redis state (tasks can be lost/restored during restarts)
    try:
        db_count = session.exec(
            select(func.count()).select_from(Target).where(
                Target.tenant_id == tenant_id,
                Target.scan_status.in_(["queued", "running"]),
                Target.is_archived == False
            )
        ).one()
        count += db_count
    except Exception:
        pass

    return count

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    # Check for YADS Updates (Automatic)
    update_info = None
    try:
        update_info = UpdateService.check_for_updates()
    except Exception as e:
        logger.warning(f"Dashboard update check failed: {e}")

    # Calculate stats (Tenant Scoped)
    total_targets = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False)).one()
    
    # Total scans is bit harder to filter if scanresult doesn't have tenant_id. 
    # We have to join.
    total_scans_count = session.exec(select(func.count(ScanResult.id)).join(Target).where(Target.tenant_id == user.tenant_id)).one()
    
    # Pagination defaults for initial load
    page = 1
    limit = 9
    offset = 0
    
    # Fetch Paginated Targets (Tenant Scoped)
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False).order_by(Target.created_at.desc()).offset(offset).limit(limit)).all()
    
    # Fetch Active Scans (Tenant Scoped)
    active_scans = session.exec(select(Target).where(Target.scan_status == "running", Target.tenant_id == user.tenant_id)).all()
    
    # Calculate Dead DNS Count
    dns_dead_count = session.exec(
        select(func.count()).select_from(Target).where(
            Target.tenant_id == user.tenant_id, 
            Target.is_archived == True, 
            Target.archived_reason == "dns_dead"
        )
    ).one()
    
    total_pages = (total_targets + limit - 1) // limit
    
    # Calculate Last Scan for each target per module
    last_scans = {}
    
    # Fetch states only for visible targets (optimization)
    target_ids = [t.id for t in targets]
    if target_ids:
        all_states = session.exec(select(ModuleState).where(ModuleState.target_id.in_(target_ids))).all()
        for state in all_states:
            if state.target_id not in last_scans:
                last_scans[state.target_id] = {}
            last_scans[state.target_id][state.module_name] = state.last_scanned_at

    # Queue Stats
    # Queue Stats (From DB for accuracy & tenant isolation)
    queue_len = _get_redis_queue_len(session, user.tenant_id)
    
    config = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = config.value.lower() == "true" if config else False

    # Compliance Calculation
    # Fetch LATEST results for ALL visible targets (for this tenant)
    # This might be heavy if thousands of targets, but acceptable for MVP optimization.
    # We reuse 'targets' (paginated) for display, but for compliance we need ALL targets' data?
    # Strictly speaking, compliance score should reflect the WHOLE infrastructure.
    # So we need a query for all targets + their latest results.
    
    # Optimization: We only fetch what ComplianceScorer needs.
    # Using raw SQL to get latest row per (target, module) efficiently.
    compliance_stats = {"score": 0, "grade": "F", "passing_controls": 0, "failures": []}
    
    try:
        if total_targets > 0:
            query_compliance = text("""
                SELECT DISTINCT ON (s.target_id, s.module_name) 
                    s.target_id, s.module_name, s.data 
                FROM scanresult s
                JOIN target t ON s.target_id = t.id
                WHERE s.module_name IN ('ssl_scanner', 'web_analyzer', 'cve_scanner', 'infrastructure_scanner', 'port_scanner')
                AND (t.tenant_id = :tenant_id OR :tenant_id IS NULL)
                ORDER BY s.target_id, s.module_name, s.scanned_at DESC
            """)
            # Fetch all targets for the map (not paginated)
            all_targets_query = select(Target).where(Target.tenant_id == user.tenant_id)
            all_targets = session.exec(all_targets_query).all()
            
            comp_results = session.execute(query_compliance, {"tenant_id": user.tenant_id}).all()
            
            # Convert raw rows to pseudo-ScanResult objects or dicts for the scorer
            # Scorer expects List[ScanResult] with .target_id, .module_name, .data
            class MockResult:
                def __init__(self, tid, mod, d):
                    self.target_id = tid
                    self.module_name = mod
                    self.data = d
            
            mock_results = [MockResult(r[0], r[1], r[2]) for r in comp_results]
            
            scorer = ComplianceScorer()
            compliance_stats = scorer.calculate_score(all_targets, mock_results)

            # --- Critical Attention Calculation ---
            # Reuse mock_results to find critical issues
            critical_map = {}
            target_lookup = {t.id: t for t in all_targets}
            
            for res in mock_results:
                reason = None
                risk = "High"
                
                # Check SSL Expiry
                if res.module_name == "ssl_scanner":
                    if res.data.get("expired"):
                        reason = "SSL Certificate Expired"
                        risk = "Critical"
                    elif res.data.get("grade") in ["F", "T", "M"]:
                        reason = "Weak SSL Configuration"
                        risk = "High"
                        
                # Check Critical CVEs
                elif res.module_name in ["cve_scanner", "web_analyzer"]:
                    cves = res.data.get("cves", [])
                    max_cvss = 0
                    for cve in cves:
                        try:
                            score = float(cve.get("cvss", 0))
                            if score > max_cvss: max_cvss = score
                        except (ValueError, TypeError) as e:
                            logger.debug(f"Could not parse CVSS score: {e}")
                    
                    if max_cvss >= 9.0:
                        reason = f"Critical Vulnerability (CVSS {max_cvss})"
                        risk = "Critical"
                    elif max_cvss >= 7.0:
                        reason = f"High Vulnerability (CVSS {max_cvss})"
                        risk = "High"
                
                # Check Public Buckets
                elif res.module_name == "infrastructure_scanner":
                    buckets = res.data.get("buckets", [])
                    if any(b.get("status") == "Public" for b in buckets):
                        reason = "Public Cloud Storage Bucket"
                        risk = "Critical"

                if reason and res.target_id in target_lookup:
                    # Priority: Critical > High
                    # If target already in map, only update if new risk is higher
                    if res.target_id in critical_map:
                        current = critical_map[res.target_id]
                        if current["risk_score"] == "High" and risk == "Critical":
                            critical_map[res.target_id].update({"risk_score": risk, "issue": reason})
                    else:
                        t = target_lookup[res.target_id]
                        critical_map[res.target_id] = {
                            "id": t.id,
                            "domain": t.domain,
                            "risk_score": risk,
                            "issue": reason,
                            "action": "Investigate"
                        }
            
            critical_targets = list(critical_map.values())
            # Sort: Critical first
            critical_targets.sort(key=lambda x: x["risk_score"], reverse=True) # C > H alphabetically? No. Critical < High alphabetically.
            # Custom sort
            critical_targets.sort(key=lambda x: 0 if x["risk_score"] == "Critical" else 1)
            
    except Exception as e:
        logger.error(f"Compliance/Critical Calc Failed: {e}")
        # specific fallback?
        pass

    # Fetch Recent Activity (ScanResults)
    recent_activity = session.exec(
        select(ScanResult).join(Target)
        .where(Target.tenant_id == user.tenant_id)
        .order_by(ScanResult.scanned_at.desc())
        .limit(5)
    ).all()

    # Ensure critical_targets is defined if logic skipped/failed
    if 'critical_targets' not in locals():
        critical_targets = []

    # Calculate Average Security Score for Tenant
    # Fetch ALL targets and their latest results to calculate accurate average?
    # For MVP performance, we might want to cache this or just calculate on the fly for visible targets?
    # Calculating for ALL is better for accuracy.
    # Reuse `comp_results` if available (it has latest results for key modules)
    avg_security_score = 0
    if total_targets > 0 and 'comp_results' in locals():
        # comp_results is list of tuples (tid, mod, data)
        # We need to group by target_id
        target_results_map = {} # {tid: {mod: result_obj}}
        for tid, mod, data in comp_results:
             if tid not in target_results_map:
                 target_results_map[tid] = {}
             # Mock result object for scorer (it expects .data)
             class MockRes:
                 def __init__(self, d): self.data = d
             target_results_map[tid][mod] = MockRes(data)
        
        total_score = 0
        scored_count = 0
        for t in all_targets:
             t_res = target_results_map.get(t.id, {})
             # Use safe version of scorer that accepts dict of objects with .data
             s, g, f = calculate_target_score(t, t_res)
             total_score += s
             scored_count += 1
        
        if scored_count > 0:
            avg_security_score = int(total_score / scored_count)
    
    avg_grade = get_grade(avg_security_score)

    # Snapshot Trend (Once per day per tenant)
    try:
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        existing_trend = session.exec(select(SecurityTrend).where(
            SecurityTrend.tenant_id == user.tenant_id, 
            SecurityTrend.recorded_at >= today_start
        )).first()
        
        if not existing_trend and total_targets > 0:
            new_trend = SecurityTrend(
                tenant_id=user.tenant_id,
                score=avg_security_score,
                grade=avg_grade
            )
            session.add(new_trend)
            session.commit()
    except Exception as e:
        # Don't fail dashboard load on trend error
        print(f"Error snapshotting trend: {e}")

    return templates.TemplateResponse("index.html", {
        "request": request,
        "critical_targets": critical_targets, # Added
        "targets": targets,
        "active_scans": active_scans,
        "last_scans": last_scans,
        "recent_activity": recent_activity, # Added
        "stats": {
            "active_targets": total_targets,
            "services_monitored": "-",  # Placeholder
            "total_scans": total_scans_count,
            "queue_length": queue_len,
            "queue_active": queue_active,
            "compliance": compliance_stats,
            "security_score": avg_security_score,
            "security_grade": avg_grade,
            "dns_dead_count": dns_dead_count
        },
        "pagination": {
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "total_count": total_targets,
            "start_item": 1,
            "end_item": min(limit, total_targets)
        },
        "user": user, # Pass user to context
        "update_info": update_info
    })


@router.get("/dashboard/stats", response_class=HTMLResponse)
async def dashboard_stats(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    """HTMX endpoint for auto-updating stats"""
    total_targets = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False)).one()
    total_scans_count = session.exec(select(func.count(ScanResult.id)).join(Target).where(Target.tenant_id == user.tenant_id)).one()
    
    # Queue Stats
    # Queue Stats (From DB for accuracy & tenant isolation)
    queue_len = _get_redis_queue_len(session, user.tenant_id)
    
    config = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = config.value.lower() == "true" if config else False

    # Calculate Average Security Score for Tenant
    avg_security_score = 0
    avg_grade = "F"
    
    try:
        if total_targets > 0:
            # Fetch latest results for security-relevant modules
            query_security = """
                SELECT DISTINCT ON (s.target_id, s.module_name) 
                    s.target_id, s.module_name, s.data 
                FROM scanresult s
                JOIN target t ON s.target_id = t.id
                WHERE s.module_name IN ('ssl_scanner', 'web_analyzer', 'cve_scanner', 'infrastructure_scanner', 'port_scanner')
                AND (t.tenant_id = :tenant_id OR :tenant_id IS NULL)
                ORDER BY s.target_id, s.module_name, s.scanned_at DESC
            """
            
            # Fetch all targets for scoring
            all_targets_query = select(Target).where(Target.tenant_id == user.tenant_id)
            all_targets = session.exec(all_targets_query).all()
            
            security_results = session.execute(text(query_security), {"tenant_id": user.tenant_id}).all()
            
            # Build target results map
            target_results_map = {}
            for tid, mod, data in security_results:
                if tid not in target_results_map:
                    target_results_map[tid] = {}
                # Mock result object for scorer
                class MockRes:
                    def __init__(self, d): self.data = d
                target_results_map[tid][mod] = MockRes(data)
            
            # Calculate average score
            total_score = 0
            scored_count = 0
            for t in all_targets:
                t_res = target_results_map.get(t.id, {})
                s, g, f = calculate_target_score(t, t_res)
                total_score += s
                scored_count += 1
            
            if scored_count > 0:
                avg_security_score = int(total_score / scored_count)
        
        avg_grade = get_grade(avg_security_score)
    except Exception as e:
        logger.error(f"Security score calculation failed in dashboard_stats: {e}")
        # Use defaults on error

    return templates.TemplateResponse("_dashboard_stats.html", {
        "request": request,
        "stats": {
            "active_targets": total_targets,
            "services_monitored": "-",
            "total_scans": total_scans_count,
            "queue_length": queue_len,
            "queue_active": queue_active,
            "security_score": avg_security_score,
            "security_grade": avg_grade
        },
        "user": user
    })

@router.get("/dashboard/active_scans", response_class=HTMLResponse)
async def dashboard_active_scans(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    """HTMX endpoint to refresh the active scans list"""
    try:
        active_scans = session.exec(select(Target).where(Target.scan_status == "running", Target.tenant_id == user.tenant_id)).all()
        return templates.TemplateResponse("_active_scans.html", {
            "request": request,
            "active_scans": active_scans,
            "user": user
        })
    except Exception as e:
        with open("/tmp/yads_debug.log", "a") as f:
            f.write(f"Error in dashboard_active_scans: {e}\n")
        raise e

@router.get("/dashboard/targets", response_class=HTMLResponse)
async def dashboard_targets(request: Request, page: int = 1, limit: int = 9, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    """
    HTMX endpoint to poll for target list updates (status/progress).
    Returns just the table rows/grid.
    """
    offset = (page - 1) * limit
    total_count = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False)).one()
    
    # Fetch Paginated (Tenant Scoped)
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False).order_by(Target.created_at.desc()).offset(offset).limit(limit)).all()
    
    total_pages = (total_count + limit - 1) // limit
    
    # We need to calculate last_scans for the fragment too, or just mock it?
    # Ideally replicate logic or extract it.
    last_scans = {}
    
    # Fetch states only for visible targets (optimization)
    target_ids = [t.id for t in targets]
    if target_ids:
        all_states = session.exec(select(ModuleState).where(ModuleState.target_id.in_(target_ids))).all()
        for state in all_states:
            if state.target_id not in last_scans:
                last_scans[state.target_id] = {}
            last_scans[state.target_id][state.module_name] = state.last_scanned_at

    return templates.TemplateResponse("_target_list.html", {
            "request": request, 
            "targets": targets, 
            "last_scans": last_scans,
            "pagination": {
                "page": page,
                "limit": limit,
                "total_pages": total_pages,
                "total_count": total_count,
                 "start_item": offset + 1,
                "end_item": min(offset + limit, total_count)
            },
            "user": user
        })
