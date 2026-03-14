import logging
import json
import os
import shutil
import tldextract
from typing import Optional, List
from fastapi import APIRouter, Depends, Request, Form, UploadFile, File, BackgroundTasks, HTTPException, Body, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import Session, select, func, text, or_, desc
from datetime import datetime, timedelta

from yads.database import get_session, redis_client
from yads.auth.deps import get_current_user_html, RoleChecker, get_current_active_user
from yads.models import User, Target, ScanResult, ModuleState, SystemConfig, ChangelogEntry, TenantModuleConfig, ChangeEvent
from yads.api.templating import templates

from yads.core.scoring import calculate_target_score, get_grade_color
from yads.core.compliance import calculate_security_grade, generate_compliance_report
from yads.api.routers.tags import get_unique_tags
from yads.core.module_registry import get_scan_categories, REGISTRY
from yads.core.scheduler import get_active_scan_count, get_max_concurrent_scans
from yads.models import SecurityAuditLog


def _audit_scan_trigger(session, user, domains: list, scan_types: list, trigger: str, request=None):
    """Write a SecurityAuditLog entry for every scan trigger."""
    try:
        entry = SecurityAuditLog(
            event_type="scan_triggered",
            username=user.username if user else "system",
            user_id=user.id if user else None,
            source_ip=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            tenant_id=user.tenant_id if user else None,
            success=True,
            details={
                "trigger": trigger,
                "domains": domains[:50],  # cap to avoid huge payloads
                "domain_count": len(domains),
                "scan_types": scan_types,
            },
        )
        session.add(entry)
        session.commit()
    except Exception as e:
        logger.warning(f"[Audit] Failed to write scan_triggered log: {e}")


def _get_scan_categories_for_user(session: Session, user: User, prefix: str):
    """Return scan categories filtered by modules enabled for the user's tenant."""
    if user.tenant_id is None:
        return get_scan_categories(prefix)
    configs = session.exec(
        select(TenantModuleConfig).where(
            TenantModuleConfig.tenant_id == user.tenant_id,
            TenantModuleConfig.enabled == False,
        )
    ).all()
    disabled = {c.module_name for c in configs}
    if not disabled:
        return get_scan_categories(prefix)
    enabled = {name for name in REGISTRY if name not in disabled}
    return get_scan_categories(prefix, enabled_modules=enabled)

from celery import Celery
from yads.config import settings
celery_app = Celery('yads_worker', broker=settings.REDIS_URL, backend=settings.REDIS_URL)

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/targets/bulk/scan", response_class=HTMLResponse)
async def bulk_scan_targets(
    request: Request,
    scan_types: List[str] = Form(default=[]), 
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    form = await request.form()
    target_ids = form.getlist("target_ids") 
    
    if not target_ids:
         return RedirectResponse(url="/targets/table?msg=No+targets+selected", status_code=303)
         
    scan_types_selected = form.getlist("scan_types")

    from yads.core.module_registry import REGISTRY
    # All registered module names + special pseudo-types
    valid_types = set(REGISTRY.keys()) | {"dns_cleanup", "full_scan"}
    final_types = [t for t in scan_types_selected if t in valid_types]

    if "full_scan" in final_types:
        # Expand to all modules EXCEPT subdomain_scanner — it triggers
        # mass auto-queuing of subdomains and must always be an explicit choice.
        final_types = [n for n in REGISTRY.keys() if n != "subdomain_scanner"]
    
    if not final_types:
         return RedirectResponse(url="/targets/table?msg=Error:+No+valid+scan+types+selected", status_code=303)

    import logging
    logger = logging.getLogger("yads-api")
    logger.info(f"DEBUG: Bulk Scan Request. Target Count: {len(target_ids)}. Selected Types: {scan_types_selected}. Final: {final_types}")

    count = 0
    skipped = 0

    # Check Queue Status
    from yads.models import SystemConfig
    queue_config = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = False
    if queue_config and queue_config.value.lower() == "true":
        queue_active = True

    # Global concurrent scan limit
    max_concurrent = get_max_concurrent_scans(session)
    active_count = get_active_scan_count(session)

    for tid_str in target_ids:
        try:
            tid = int(tid_str)
            target = session.exec(select(Target).where(Target.id == tid, Target.tenant_id == user.tenant_id)).first()
            if target:
                # --- License / CE Check ---
                from yads.models import SystemConfig
                from yads.core.license import license_manager
                from yads.core.community_edition import get_ce_state, check_can_scan as ce_check_scan
                _ce = get_ce_state(session)
                if _ce["edition"] == "community":
                    _ok, _reason = ce_check_scan(session)
                    if not _ok:
                        return RedirectResponse(url=f"/targets/table?msg=Error:+{_reason}", status_code=303)
                else:
                    lc = session.get(SystemConfig, "license_key")
                    if not lc or not lc.value or not license_manager.verify(lc.value):
                        return RedirectResponse(url="/targets/table?msg=Error:+License+Required+for+Scanning", status_code=303)

                # Respect global concurrent scan limit
                if active_count >= max_concurrent:
                    skipped += 1
                    continue

                # Dispatch Task FIRST
                celery_app.send_task(
                    "yads.worker.run_all_scans",
                    args=[target.id, target.domain, final_types, user.tenant_id],
                    priority=getattr(target, "scan_priority", 5),
                )
                
                # Update DB only on success
                target.scan_status = "queued"
                session.add(target)
                count += 1
                active_count += 1

        except Exception as e:
            logger.error(f"Failed to queue target {tid_str}: {e}")
            continue

    session.commit()
    _audit_scan_trigger(session, user, list(target_ids)[:50], final_types, "bulk_scan", request)

    msg = f"Queued+{count}+scans"
    if skipped:
        msg += f"+({skipped}+skipped:+concurrent+limit+{max_concurrent}+reached)"
    return RedirectResponse(url=f"/targets/table?msg={msg}", status_code=303)

@router.post("/targets/import", response_class=HTMLResponse)
async def bulk_import_targets(
    request: Request,
    file_upload: UploadFile = File(None),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    form = await request.form()
    raw_text = form.get("targets_raw", "")
    discovery_reason = form.get("discovery_reason")
    next_url = form.get("next", "/targets/table")
    verify_dns = form.get("verify_dns") == "true"
    
    # Process File Upload if present
    if file_upload and file_upload.filename:
        try:
            content = await file_upload.read()
            # Try decoding as utf-8, fallback to latin-1
            try:
                decoded = content.decode("utf-8")
            except UnicodeDecodeError:
                decoded = content.decode("latin-1")
            except Exception as e:
                logger.debug(f"Failed to decode uploaded file: {e}")
                decoded = content.decode("latin-1", errors="ignore")
            
            raw_text += "\n" + decoded
        except Exception as e:
            logger.error(f"Failed to read uploaded file: {e}")
    
    if not raw_text.strip():
        return RedirectResponse(url=f"{next_url}?msg=No+data+provided", status_code=303)
        
    # Split lines and process
    # Use set to remove duplicates within the import batch immediately
    lines = list(set([l.strip().lower() for l in raw_text.splitlines() if l.strip()]))
    
    imported_count = 0
    duplicate_count = 0
    skipped_dns_count = 0
    
    import dns.resolver  # Import here execution context
    
    for domain in lines:
        # Basic cleanup - remove http/https if present and trailing slashes
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
        domain = domain.strip().lower()

        if not domain: continue
        
        # DNS Verification if enabled
        if verify_dns:
            try:
                # Try resolving A record
                dns.resolver.resolve(domain, 'A')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
                try:
                    # Fallback to AAAA
                     dns.resolver.resolve(domain, 'AAAA')
                except Exception as e:
                     logger.debug(f"DNS AAAA resolution failed for {domain}: {e}")
                     skipped_dns_count += 1
                     continue
            except Exception as e:
                # Other DNS errors -> skip
                logger.debug(f"DNS resolution error for {domain}: {e}")
                skipped_dns_count += 1
                continue
        
        # Check duplicate (Tenant Scoped)
        existing = session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == user.tenant_id)).first()
        if existing:
            duplicate_count += 1
            continue
            
        # --- License / CE Check ---
        total_active_targets = session.exec(select(func.count()).select_from(Target)).one()

        from yads.core.community_edition import get_ce_state, check_can_add_target
        from yads.models import SystemConfig
        from yads.core.license import license_manager

        ce_state = get_ce_state(session)
        if ce_state["edition"] == "community":
            allowed, reason = check_can_add_target(session, total_active_targets)
            if not allowed:
                return RedirectResponse(url=f"{next_url}?error={reason}", status_code=303)
        else:
            # Legacy commercial license enforcement
            license_conf = session.get(SystemConfig, "license_key")
            limit = 5  # default free tier
            if license_conf and license_conf.value:
                data = license_manager.verify(license_conf.value)
                if data:
                    limit = data.get("max_targets", 0)
            if total_active_targets >= limit:
                msg = f"License Limit Reached ({limit}). Upgrade license to add more targets."
                return RedirectResponse(url=f"{next_url}?error={msg}", status_code=303)

        # Create
        # Create
        new_target = Target(domain=domain, tenant_id=user.tenant_id, discovery_reason=discovery_reason)
        session.add(new_target)
        imported_count += 1
        
    session.commit()
    
    msg = f"Imported+{imported_count}+targets"
    if duplicate_count > 0:
        msg += f"+({duplicate_count}+skipped+duplicates)"
    if skipped_dns_count > 0:
        msg += f"+({skipped_dns_count}+skipped+offline)"
        
    return RedirectResponse(url=f"{next_url}?msg={msg}", status_code=303)

@router.post("/targets/bulk/delete", response_class=HTMLResponse)
async def bulk_delete_targets(
    target_ids: List[int] = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """
    Deletes multiple targets and their associated data.
    """
    if not target_ids:
        # Should probably return an error or just redirect
        return RedirectResponse(url="/targets/table?msg=No+targets+selected", status_code=303)

    # Convert to set for safety
    ids_to_delete = set(target_ids)
    
    # 1. Delete Dependencies (ScanResults, ModuleStates)
    # Using raw SQL for efficiency with list of IDs
    ids_str = ",".join(map(str, ids_to_delete))
    
    # Check if empty (shouldn't be due to check above)
    if ids_str:
        # 1a. Revoke Active/Queued Tasks for these Targets
        # This is tricky without task IDs stored in DB.
        # We have to inspect active/reserved tasks and check args.
        i = celery_app.control.inspect()
        active = i.active() if i else None
        reserved = i.reserved() if i else None
        
        tasks_to_revoke = []
        
        def check_tasks(task_list):
            for worker_name, tasks in task_list.items():
                for task in tasks:
                    # task args is usually [target_id, domain, ...]
                    args = task.get("args", [])
                    if args and isinstance(args, list) and len(args) > 0:
                        try:
                            tid = int(args[0])
                            if tid in ids_to_delete:
                                tasks_to_revoke.append(task.get("id"))
                        except Exception as e:
                            logger.debug(f"Task revocation check failed: {e}")
                            pass
                            
        if active: check_tasks(active)
        if reserved: check_tasks(reserved)
        
        for tid_revoke in tasks_to_revoke:
            celery_app.control.revoke(tid_revoke, terminate=True)
            
        # 1b. Delete Dependencies
        session.exec(text("DELETE FROM scanresult WHERE target_id IN :ids"), {"ids": tuple(ids_to_delete)})
        session.exec(text("DELETE FROM modulestate WHERE target_id IN :ids"), {"ids": tuple(ids_to_delete)})
        
        # 2. Delete Targets (Verify ownership implicitly by filtering ID list first? Better to rely on prior checks or simple query)
        # But here we used raw delete for speed. 
        # Safety check: Ensure all IDs belong to user.tenant_id
        # For bulk delete, it's safer to fetch IDs that match tenant first.
        
        owned_targets = session.exec(select(Target.id).where(Target.id.in_(ids_to_delete), Target.tenant_id == user.tenant_id)).all()
        # Only delete what we own
        safe_ids = set(owned_targets)
        
        if len(safe_ids) != len(ids_to_delete):
            # Some IDs were not owned. Log warning?
            pass
            
        if safe_ids:
            # Prune dependencies using safe list
            session.exec(text("DELETE FROM scanresult WHERE target_id IN :safe_ids"), {"safe_ids": tuple(safe_ids)})
            session.exec(text("DELETE FROM modulestate WHERE target_id IN :safe_ids"), {"safe_ids": tuple(safe_ids)})
            session.exec(text("DELETE FROM target WHERE id IN :safe_ids"), {"safe_ids": tuple(safe_ids)})
        
        session.commit()
    
    count = len(ids_to_delete)
    revoke_count = len(tasks_to_revoke) if 'tasks_to_revoke' in locals() else 0
    msg = f"Deleted+{count}+targets"
    if revoke_count > 0:
        msg += f"+(Stopped+{revoke_count}+scans)"
        
    return RedirectResponse(url=f"/targets/table?msg={msg}", status_code=303)

@router.post("/targets/bulk/archive-dead", response_class=HTMLResponse)
async def bulk_archive_dead_targets(
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """
    Archives all targets in the current tenant that have been DNS-scanned
    but returned empty records (unresolvable / dead domains).
    """
    from datetime import datetime
    from sqlmodel import text as sql_text

    subquery = sql_text("""
        SELECT t.id FROM target t
        JOIN LATERAL (
            SELECT data FROM scanresult
            WHERE target_id = t.id AND module_name = 'dns_scanner'
            ORDER BY scanned_at DESC LIMIT 1
        ) sr ON true
        WHERE (sr.data->'records')::text = '{}'
        AND t.is_archived = false
        AND t.tenant_id = :tenant_id
    """)

    dead_ids = [row[0] for row in session.exec(subquery.bindparams(tenant_id=user.tenant_id)).all()]

    count = 0
    if dead_ids:
        targets = session.exec(select(Target).where(Target.id.in_(dead_ids))).all()
        for target in targets:
            target.is_archived = True
            target.archived_at = datetime.utcnow()
            target.archived_reason = "DNS cleanup: empty records"
            session.add(target)
            count += 1
        session.commit()

    return RedirectResponse(url=f"/targets/table?msg=Archived+{count}+dead+domains", status_code=303)


@router.post("/targets/bulk/archive", response_class=HTMLResponse)
async def bulk_archive_targets(
    target_ids: List[int] = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """
    Archives multiple targets.
    """
    if not target_ids:
        return RedirectResponse(url="/targets/table?msg=No+targets+selected", status_code=303)

    ids_to_archive = set(target_ids)
    
    # Verify ownership
    owned_targets = session.exec(
        select(Target).where(
            Target.id.in_(ids_to_archive), 
            Target.tenant_id == user.tenant_id,
            Target.is_archived == False
        )
    ).all()
    
    count = 0
    from datetime import datetime
    for target in owned_targets:
        target.is_archived = True
        target.archived_at = datetime.utcnow()
        target.archived_reason = "manual"
        session.add(target)
        count += 1
        
    session.commit()
    
    msg = f"Archived+{count}+targets"
    return RedirectResponse(url=f"/targets/table?msg={msg}", status_code=303)

@router.post("/targets/{target_id}/scan")
async def trigger_scan(target_id: int, request: Request, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))):
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Parse form data for scan types
    form = await request.form()
    scan_types = form.getlist("scan_types") # Returns list of values for keys named "scan_types"

    # Update scan priority if provided
    try:
        priority_val = int(form.get("scan_priority", 5))
        target.scan_priority = max(1, min(9, priority_val))
    except (ValueError, TypeError):
        pass
    
    # Validation/Default
    from yads.core.module_registry import REGISTRY
    valid_types = set(REGISTRY.keys()) | {"dns_cleanup", "full_scan"}
    selected_types = [t for t in scan_types if t in valid_types]

    if "full_scan" in selected_types:
        # Expand to all modules EXCEPT subdomain_scanner — it triggers
        # mass auto-queuing of subdomains and must always be an explicit choice.
        selected_types = [n for n in REGISTRY.keys() if n != "subdomain_scanner"]
    
    # --- License / CE Check ---
    from yads.models import SystemConfig
    from yads.core.license import license_manager
    from yads.core.community_edition import get_ce_state, check_can_scan as ce_check_scan
    ce_state = get_ce_state(session)
    if ce_state["edition"] == "community":
        allowed, reason = ce_check_scan(session)
        if not allowed:
            return RedirectResponse(url=f"/targets/{target_id}?error={reason}", status_code=303)
    else:
        lc = session.get(SystemConfig, "license_key")
        if not lc or not lc.value or not license_manager.verify(lc.value):
            msg = "Error: Scanning requires a valid license."
            return RedirectResponse(url=f"/targets/{target_id}?error={msg}", status_code=303)

    if not selected_types:
        msg = "Error: No valid scan types selected."
        return RedirectResponse(url=f"/targets/{target_id}?error={msg}", status_code=303)

    # Global concurrent scan limit
    max_concurrent = get_max_concurrent_scans(session)
    if get_active_scan_count(session) >= max_concurrent:
        msg = f"Error: Concurrent scan limit ({max_concurrent}) reached. Try again later."
        return RedirectResponse(url=f"/targets/{target_id}?error={msg}", status_code=303)

    # 1. Dispatch Task to Redis
    try:
        celery_app.send_task(
            "yads.worker.run_all_scans",
            args=[target.id, target.domain, selected_types, user.tenant_id],
            priority=getattr(target, "scan_priority", 5),
        )
    except Exception as e:
        logger.error(f"Failed to dispatch scan for {target_id}: {e}")
        return RedirectResponse(url=f"/targets/{target_id}?error=Dispatch+Error", status_code=303)

    # 2. Update status in DB on SUCCESS
    target.scan_status = "queued"
    session.add(target)
    session.commit()
    
    _audit_scan_trigger(session, user, [target.domain], selected_types, "single_scan", request)

    return RedirectResponse(url=f"/targets/{target_id}", status_code=303)
@router.post("/targets/add", response_class=HTMLResponse)
async def ui_add_target(request: Request, domain: str = Form(...), session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    """HTMX endpoint to add a target"""
    domain = domain.lower().strip()
    # Tenant Scope
    existing = session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == user.tenant_id)).first()
    
    if existing:
        target = existing
    else:
        target = Target(domain=domain, tenant_id=user.tenant_id)
        session.add(target)
        session.commit()
        session.refresh(target)
        
    # Always Trigger Scan (New or Existing) - DISABLED by user request (Import Only)
    # celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain])
    
    # Return standard target list row fragment or redirect
    return await dashboard(request, session, user) 
    # In a real HTMX app, we'd return just the new row or the updated list fragment.
    # For simplicity, refreshing the page or returning full page is easiest for now.

@router.delete("/targets/{target_id}")
async def delete_target(target_id: int, request: Request, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Manually delete related records if no cascade is set up in DB
    # SQLModel/SQLAlchemy usually handles this if relationships are defined with cascade.
    # Let's purge explicitly to be safe as we didn't inspect FK constraints deeply in DB init.
    
    session.exec(text("DELETE FROM scanresult WHERE target_id = :tid"), {"tid": target_id})
    # Also delete module states (which control the 'scanned_at' badges)
    session.exec(text("DELETE FROM modulestate WHERE target_id = :tid"), {"tid": target_id})
    
    session.delete(target)
    session.commit()
    
    # Return empty string or redirect? 
    # If HTMX deletes the row, we return empty body (200 OK) so the row disappears.
    return HTMLResponse(content="", status_code=200)

# -- Real-time Scan Status & Logs --

@router.get("/api/scans/{target_id}/status")
async def get_scan_status(target_id: int):
    """
    Returns the latest status message and progress from Redis/DB.
    """
    r = redis_client
    
    # Check Redis for live status first
    status_msg = r.get(f"scan:status:{target_id}")
    if status_msg:
        return {"status": status_msg}
        
    # Fallback to DB if no live status (e.g. idle or finished)
    with Session(engine) as session:
        t = session.get(Target, target_id)
        if t:
            return {"status": t.scan_progress or t.scan_status}
            
    return {"status": "Unknown"}

@router.get("/api/scans/{target_id}/logs")
async def get_scan_logs(target_id: int, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Returns the recent log lines from Redis.
    """
    import json
    r = redis_client
    
    # Security Check
    target = session.get(Target, target_id)
    if not target:
        return {"logs": []}
        
    if user.role != "admin" and target.tenant_id != user.tenant_id:
        # Silently return empty or error? Error 403 is better but this is likely consumed by polling JS.
        # Returning explicit error message in logs list is safer for UI feedback or just 403.
        raise HTTPException(status_code=403, detail="Not authorized to view these logs")

    # Fetch List
    logs = r.lrange(f"scan:logs:{target_id}", 0, -1)
    parsed_logs = []
    
    for l in logs:
        try:
            entry = json.loads(l)
            parsed_logs.append(entry)
        except Exception as e:
            logger.debug(f"Failed to parse log line: {e}")
            parsed_logs.append({"msg": l})
            
    return {"logs": parsed_logs}

@router.get("/api/scans/{target_id}/network-context")
async def get_scan_network_context(target_id: int, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Returns the network context (external IP, resolved IPs) for a scan.
    """
    from yads.core.redis_logger import get_scan_network_context as get_network_ctx

    # Security Check
    target = session.get(Target, target_id)
    if not target:
        return {"network_context": None}

    if user.role != "admin" and target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this data")

    context = get_network_ctx(target_id)
    return {"network_context": context, "target_domain": target.domain}


@router.get("/components/log_viewer/{target_id}", response_class=HTMLResponse)
async def component_log_viewer(request: Request, target_id: int):
    """
    Returns the HTML fragment for the log viewer.
    """
    return templates.TemplateResponse("_log_viewer.html", {
        "request": request,
        "target_id": target_id
    })

@router.get("/components/log_lines/{target_id}", response_class=HTMLResponse)
async def component_log_lines(request: Request, target_id: int):
    """
    Returns just the <li> elements for the log viewer (polled by HTMX).
    """
    import json
    r = redis_client
    
    logs = r.lrange(f"scan:logs:{target_id}", 0, -1)
    parsed_logs = []
    for l in logs:
        try:
            entry = json.loads(l)
            parsed_logs.append(entry)
        except Exception as e:
            logger.debug(f"Failed to parse component log line: {e}")
            parsed_logs.append({"msg": l, "ts": "", "level": "INFO"})
            
    return templates.TemplateResponse("_log_viewer_lines.html", {
        "request": request, 
        "logs": parsed_logs
    })
@router.get("/targets/table", response_class=HTMLResponse)
async def view_target_table(
    request: Request, 
    page: int = 1, 
    limit: int = 20, 
    filter_online: str = "all",

    filter_server: Optional[str] = None,
    filter_asn: Optional[str] = None,
    filter_last_scan: str = "all",
    filter_tag: Optional[str] = None,
    filter_domain: Optional[str] = None,
    filter_web_probe: str = "all",
    
    # New Per-Column Filters
    filter_http_status: Optional[str] = None,
    filter_https_status: Optional[str] = None,
    filter_redirect: Optional[str] = None, # "yes", "no", "all"
    filter_wildcard: Optional[str] = None, # "yes", "no", "all"
    filter_scan_status: Optional[str] = None, # "running", "queued", "idle", "failed"
    
    # New Functional Filters
    filter_login: Optional[str] = None,
    filter_dns: Optional[str] = None,
    filter_secrets: Optional[str] = None,
    filter_takeover: Optional[str] = None,
    filter_ssl: Optional[str] = None,
    
    # New: Persist Scan Options
    scan_types: List[str] = Query(None),
    
    # New: Sorting & Scope
    filter_scope: str = "all", # "all", "external", "internal"
    filter_root_domain: Optional[str] = None, # For the dedicated root filter
    filter_archived: str = "no", # "yes", "no", "only"
    
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Renders a detailed table view of all targets with bulk actions.
    Supports pagination and filtering (Online Status, Last Scan).
    """
    from fastapi import Query # Ensure import availability if not global, but usually at top.
    from datetime import datetime, timedelta
    from sqlmodel import or_, and_, col

    # Scan Types Persistence Logic
    default_scan_types = []  # Default to NOTHING selected to force explicit choice and avoid accidental full scans
    
    # If not provided (initial load or link without params), use defaults
    if scan_types is None:
        selected_scan_types = default_scan_types
    else:
        selected_scan_types = scan_types

    # Base Query (Tenant Scoped)
    query = select(Target).where(Target.tenant_id == user.tenant_id)

    # -- Filter: Archived --
    if filter_archived == "no":
        query = query.where(Target.is_archived == False)
    elif filter_archived == "only":
        query = query.where(Target.is_archived == True)
    # else filter_archived == "yes" -> show all
    
    # -- Filter: Domain (Wildcard) --
    if filter_domain:
        clean_filter = filter_domain.strip()
        if '*' in clean_filter:
            # Shell-style wildcard: * -> SQL %
            sql_pattern = clean_filter.replace('*', '%')
            query = query.where(Target.domain.ilike(sql_pattern))
        else:
            # Strict match if no wildcard provided? 
            # Or standard contains? 
            # Given explicit "using * as wildcard" request, we default to exact match if no * finds, 
            # BUT usually search bars are "contains". 
            # Let's do exact match here to honor the distinction, or maybe simple substring?
            # User request: "filter domains using * as wildcard"
            # It implies "*" is the mechanism.
            # I'll implement: Treat as exact string unless * is present. 
            # Actually, let's treat it as "starts with" or partial?
            # Safe bet: default to partial match (contains) is usually what users want if they don't know wildcards.
            # BUT if they specifically asked for * wildcard, maybe they want to be precise.
            # I will use ILIKE logic: if no * is present, I will treat it as a straight ILIKE match (exact). 
            # Users can add *name* to do contains.
            # Wait, that might be annoying.
            # Compromise: I'll blindly replace * with % and run ILIKE. 
            # If they don't use *, it's an exact match. 
            # If they want contains, they type *foo*.
            # User explicitly requested strict behavior: "Only example-client.de without anything else"
            # So if no wildcard is used, we enforce STRICT equality.
            query = query.where(func.lower(Target.domain) == clean_filter.lower())
    
    # -- Filter: Last Scan Time --
    if filter_last_scan != "all":
        if filter_last_scan == "never":
            # Targets that utilize NO ScanResults
            # We use a subquery to find all target_ids that HAVE results
            sub_scanned = select(ScanResult.target_id).distinct()
            query = query.where(Target.id.notin_(sub_scanned))
        else:
            cutoff = datetime.utcnow()
            if filter_last_scan == "24h":
                cutoff -= timedelta(hours=24)
            elif filter_last_scan == "7d":
                cutoff -= timedelta(days=7)
            
            # Subquery: Targets with at least one scan after cutoff
            sub_recent = select(ScanResult.target_id).where(ScanResult.scanned_at >= cutoff).distinct()
            query = query.where(Target.id.in_(sub_recent))

    # -- Filter: Online Status --
    if filter_online != "all":
        # Define what "Online" means in terms of specific findings
        # 1. Infrastructure Scanner: data->ip is present
        # 2. Web Analyzer: data->status_code is > 0
        
        # Note: We use `text` for raw JSON/Cast operations compatible with PostgreSQL
        online_criteria = or_(
             and_(ScanResult.module_name == 'infrastructure_scanner', text("data->>'ip' IS NOT NULL")),
             and_(ScanResult.module_name == 'web_analyzer', text("(data->>'status_code')::int > 0")),
             and_(ScanResult.module_name == 'port_scanner', text("data->>'is_active' = 'true'"))
        )
        
        sub_online = select(ScanResult.target_id).where(online_criteria).distinct()

        if filter_online == "online":
            query = query.where(Target.id.in_(sub_online))
            
        elif filter_online == "offline":
             # Offline = Has been scanned (at least once) BUT is not in the "Online" list
             # 1. Get all scanned IDs
             sub_scanned = select(ScanResult.target_id).distinct()
             
             query = query.where(Target.id.in_(sub_scanned))
             query = query.where(Target.id.notin_(sub_online))
             
        elif filter_online == "unknown":
             # Unknown = Never Scanned (Same as Last Scan: Never)
             sub_scanned = select(ScanResult.target_id).distinct()
             query = query.where(Target.id.notin_(sub_scanned))

        elif filter_online == "not_checked":
             # Not Checked = No results from any connectivity module (shows "—")
             # Target may have other scan results (e.g. dns_scanner) but none from infra/web/port
             sub_connectivity = select(ScanResult.target_id).where(
                 ScanResult.module_name.in_(["infrastructure_scanner", "web_analyzer", "port_scanner"])
             ).distinct()
             query = query.where(Target.id.notin_(sub_connectivity))

    # -- Filter: Server (Web Analyzer) --
    if filter_server:
        # Subquery: Targets having web_analyzer scan with specific server header
        # Using cast to text for JSON comparison
        sub_server = select(ScanResult.target_id).where(
            ScanResult.module_name == 'web_analyzer',
            text("data->>'server_header' = :server").bindparams(server=filter_server)
        ).distinct()
        query = query.where(Target.id.in_(sub_server))

    # -- Filter: ASN (Infrastructure Scanner) --
    if filter_asn:
        # Subquery: Targets having infrastructure_scanner with specific ASN
        sub_asn = select(ScanResult.target_id).where(
            ScanResult.module_name == 'infrastructure_scanner',
            text("data->'asn'->>'asn' = :asn").bindparams(asn=filter_asn)
        ).distinct()
        query = query.where(Target.id.in_(sub_asn))

    # -- Filter: Tags --
    if filter_tag:
        # JSONB Containment: tags contains [filter_tag]
        query = query.where(Target.tags.contains([filter_tag]))

    # -- Filter: Scan Status --
    if filter_scan_status and filter_scan_status != "all":
        query = query.where(Target.scan_status == filter_scan_status)

    # -- Filter: HTTP Status (Web Analyzer) --
    if filter_http_status:
        # Find targets where Web Analyzer result has this http_status
        # Note: data->'http_status' might be number or string. Cast to text for comparison.
        try:
            status_code = int(filter_http_status)
            sub_http = select(ScanResult.target_id).where(
                ScanResult.module_name == 'web_analyzer',
                text("data->>'http_status' = :code").bindparams(code=str(status_code))
            ).distinct()
            query = query.where(Target.id.in_(sub_http))
        except ValueError:
            pass # Invalid integer input

    # -- Filter: HTTPS Status (Web Analyzer) --
    if filter_https_status:
        try:
            status_code = int(filter_https_status)
            sub_https = select(ScanResult.target_id).where(
                ScanResult.module_name == 'web_analyzer',
                text("data->>'https_status' = :code").bindparams(code=str(status_code))
            ).distinct()
            query = query.where(Target.id.in_(sub_https))
        except ValueError:
            pass

    # -- Filter: Redirect (Web Analyzer) --
    if filter_redirect and filter_redirect != "all":
        # check data->'https_redirect' (boolean)
        is_redir = "true" if filter_redirect == "yes" else "false"
        sub_redir = select(ScanResult.target_id).where(
            ScanResult.module_name == 'web_analyzer',
            text("data->>'https_redirect' = :val").bindparams(val=is_redir)
        ).distinct()
        query = query.where(Target.id.in_(sub_redir))

    # -- Filter: Wildcard (DNS Scanner) --
    if filter_wildcard and filter_wildcard != "all":
        # check data->'wildcard_detected' (boolean)
        is_wild = "true" if filter_wildcard == "yes" else "false"
        # Check both dns_scanner and subdomain_scanner as they both detect wildcards
        sub_wild = select(ScanResult.target_id).where(
            or_(ScanResult.module_name == 'dns_scanner', ScanResult.module_name == 'subdomain_scanner'),
            text("data->>'wildcard_detected' = :val").bindparams(val=is_wild)
        ).distinct()
        query = query.where(Target.id.in_(sub_wild))

    # -- Filter: Login Page --
    if filter_login and filter_login != "all":
        is_login = "true" if filter_login == "yes" else "false"
        sub_login = select(ScanResult.target_id).where(
            ScanResult.module_name == 'web_analyzer',
            text("data->>'is_login_page' = :val").bindparams(val=is_login)
        ).distinct()
        query = query.where(Target.id.in_(sub_login))

    # -- Filter: DNS (Has Data/Subdomains) --
    if filter_dns and filter_dns != "all":
        # "has_data" means either dns_scanner or subdomain_scanner has results
        # We check if 'subdomains' array length > 0 OR 'records' is not empty
        if filter_dns == "active":
             sub_dns = select(ScanResult.target_id).where(
                or_(ScanResult.module_name == 'dns_scanner', ScanResult.module_name == 'subdomain_scanner'),
                text("jsonb_array_length(data->'subdomains') > 0")
             ).distinct()
             query = query.where(Target.id.in_(sub_dns))
        elif filter_dns == "none":
            # Harder to filter "None" with subquery IN, usually requires NOT IN
            pass # TODO: Implement "No DNS" cleanly if needed, or just focus on Active

    # -- Filter: Secrets --
    if filter_secrets and filter_secrets == "found":
        sub_sec = select(ScanResult.target_id).where(
            ScanResult.module_name == 'web_analyzer',
            text("jsonb_array_length(data->'secrets') > 0")
        ).distinct()
        query = query.where(Target.id.in_(sub_sec))

    # -- Filter: Takeover --
    if filter_takeover and filter_takeover == "found":
        sub_take = select(ScanResult.target_id).where(
            ScanResult.module_name == 'dns_scanner',
            text("jsonb_array_length(data->'takeover_risks') > 0")
        ).distinct()
        query = query.where(Target.id.in_(sub_take))

    # -- Filter: SSL Issues --
    if filter_ssl and filter_ssl == "issues":
         # Look for scan result with "error" key present in data
         sub_ssl = select(ScanResult.target_id).where(
            ScanResult.module_name == 'ssl_scanner',
            text("data ? 'error'") # JSONB operator for key existence
         ).distinct()
         query = query.where(Target.id.in_(sub_ssl))
    
    # -- Filter: Server Header --
    if filter_server:
        # data->'server_header' contains string
        search_srv = f"%{filter_server}%"
        sub_srv = select(ScanResult.target_id).where(
            ScanResult.module_name == 'web_analyzer',
            text("data->>'server_header' ILIKE :srv").bindparams(srv=search_srv)
        ).distinct()
        query = query.where(Target.id.in_(sub_srv))

    # -- Filter: ASN --
    if filter_asn:
        # data->'asn'->>'asn' (e.g. "AS1234") or 'asn_description'
        search_asn = f"%{filter_asn}%"
        sub_asn = select(ScanResult.target_id).where(
            ScanResult.module_name == 'infrastructure_scanner',
            text("(data->'asn'->>'asn' ILIKE :asn OR data->'asn'->>'asn_description' ILIKE :asn)").bindparams(asn=search_asn)
        ).distinct()
        query = query.where(Target.id.in_(sub_asn)) 

    # -- Filter: Scope (Internal vs External) --
    INTERNAL_TLDS = ['.vrnet', '.internal', '.local', '.lan', '.test']
    
    if filter_scope == "external":
        # Exclude internal TLDs
        for tld in INTERNAL_TLDS:
            query = query.where(func.lower(Target.domain).not_like(f"%{tld}"))
            
    elif filter_scope == "internal":
        # Include ONLY internal TLDs
        conditions = [func.lower(Target.domain).like(f"%{tld}") for tld in INTERNAL_TLDS]
        query = query.where(or_(*conditions))

    # -- Filter: Root Domain --
    if filter_root_domain:
        # Match EXACT root OR anything ending in .root
        # This covers example-client.de and sub.example-client.de
        query = query.where(
            or_(
                Target.domain == filter_root_domain,
                Target.domain.like(f"%.{filter_root_domain}")
            )
        )

    # Calculate offset

    # Calculate offset
    offset = (page - 1) * limit
    
    # Get Total Count (Applying Filters)
    # We use query.whereclause to count matching records
    if query.whereclause is not None:
        total_count = session.exec(select(func.count()).select_from(Target).where(query.whereclause)).one()
    else:
        total_count = session.exec(select(func.count()).select_from(Target)).one()
    
    # Fetch Paginated Targets
    # Default Sorting: Hierarchical (Reversed Domain)
    # This puts example-client.de (ed.knabzd) before sub.example-client.de (ed.knabzd.bus)
    # Using func.reverse from SQLAlchemy (Postgres supported)
    targets = session.exec(query.order_by(func.reverse(Target.domain)).offset(offset).limit(limit)).all()
    
    # Calculate Total Pages
    total_pages = (total_count + limit - 1) // limit

    # -- Cipher Compliance Setup --
    from yads.models import SystemConfig
    approved_ciphers_set = set()
    ac_conf = session.get(SystemConfig, "APPROVED_CIPHERS")
    raw_ac = ""
    if ac_conf:
        raw_ac = ac_conf.value
    else:
        # Load from file default
        try:
             import os
             if os.path.exists("ciphers.csv"):
                with open("ciphers.csv", "r") as f:
                    raw_ac = f.read()
        except Exception as e:
            logger.debug(f"Failed to load ciphers.csv: {e}")
    
    if raw_ac:
        for line in raw_ac.splitlines():
            # Format: TLS Version,Cipherset
            # We care about the 2nd column "Cipherset" which is the distinct name
            parts = line.split(',')
            if len(parts) >= 2:
                cipher_name = parts[1].strip()
                if cipher_name and cipher_name.lower() != "cipherset": # Skip header
                    approved_ciphers_set.add(cipher_name)
        
    # Prepare table rows with summary data
    table_rows = []
    for t in targets:
        results = session.exec(select(ScanResult).where(ScanResult.target_id == t.id).order_by(ScanResult.scanned_at.desc())).all()
        
        # Summaries
        # Look for either dns_scanner or subdomain_scanner, prioritizing subdomain_scanner (more data)
        sub_scan = next((r for r in results if r.module_name == 'subdomain_scanner'), None)
        dns_scan = next((r for r in results if r.module_name == 'dns_scanner'), None)
        dns = sub_scan if sub_scan else dns_scan
        
        ssl = next((r for r in results if r.module_name == 'ssl_scanner'), None)
        web = next((r for r in results if r.module_name == 'web_analyzer'), None)
        infra = next((r for r in results if r.module_name == 'infrastructure_scanner'), None)
        tld_scan = next((r for r in results if r.module_name == 'tld_scanner'), None)
        tld_scan = next((r for r in results if r.module_name == 'tld_scanner'), None)
        port_scan = next((r for r in results if r.module_name == 'port_scanner'), None)
        nuclei_scan = next((r for r in results if r.module_name == 'nuclei_scanner'), None)
        
        # Security Score Calculation
        # Convert results list to dict {module_name: result} for scorer
        latest_results_map = {r.module_name: r for r in results}
        score, grade, factors = calculate_target_score(t, latest_results_map)
        grade_color = get_grade_color(grade)

        
        # Online Status Logic (Mirroring the Filter Logic)
        is_online = None 
        if infra or web or port_scan:
            has_ip = False
            if infra and infra.data and infra.data.get("ip"):
                has_ip = True
            
            has_http = False
            if web and web.data and web.data.get("status_code"):
                code = web.data.get("status_code")
                if isinstance(code, int) and code > 0:
                    has_http = True
            
            has_probe = False
            if port_scan and port_scan.data and port_scan.data.get("is_active"):
                has_probe = True

            if has_ip or has_http or has_probe:
                is_online = True
            else:
                is_online = False

        # Extract DNS A Record (IP)
        # Data structure: data["records"]["A"] = ["1.2.3.4", ...]
        dns_ip = None
        if dns and dns.data and "records" in dns.data and "A" in dns.data["records"]:
             a_records = dns.data["records"]["A"]
             if a_records:
                 dns_ip = a_records[0]

        row_data = {
            "target": t,
            "is_online": is_online,
            "dns_ip": dns_ip,
            "dns_count": len(dns.data.get("subdomains", [])) if (dns and dns.data) else 0,
            "ssl_issuer": ssl.data.get("issuer", {}).get("commonName") if (ssl and ssl.data and not ssl.data.get("error")) else None,
            "ssl_expiry": ssl.data.get("notAfter") if (ssl and ssl.data and not ssl.data.get("error")) else None,
            "web_server": web.data.get("server_header") if (web and web.data) else None,
            "asn": infra.data.get("asn", {}).get("asn") if (infra and infra.data) else None,
            "http_status": web.data.get("http_status") if (web and web.data) else None,
            "https_status": web.data.get("https_status") if (web and web.data) else None,
            "https_redirect": web.data.get("https_redirect") if (web and web.data) else None,
            "wildcard_detected": dns.data.get("wildcard_detected") if (dns and dns.data) else None,
            "takeover_risks": dns.data.get("takeover_risks", []) if (dns and dns.data) else [],
            "tld_stats": tld_scan.data if (tld_scan and tld_scan.data) else None,
            "port_scan": port_scan.data if (port_scan and port_scan.data) else None,
            "nuclei_stats": nuclei_scan.data.get("stats") if (nuclei_scan and nuclei_scan.data) else None,
            "last_scan": results[0].scanned_at if results else None,
            "last_scan": results[0].scanned_at if results else None,
            "modules": list(set([r.module_name for r in results])),
            "last_scan": results[0].scanned_at if results else None,
            "modules": list(set([r.module_name for r in results])),
            "is_login_page": web.data.get("is_login_page", False) if (web and web.data) else False,
            "security_score": score,
            "security_grade": grade,
            "security_grade_color": grade_color,
            "score_factors": factors
        }
        
        # Calculate Compliance
        compliant = 0
        non_compliant = 0
        if ssl and ssl.data and not ssl.data.get("error"):
            detected_ciphers = ssl.data.get("ciphers", [])
            # detected_ciphers is list of dicts: {name, version, bits}
            for dc in detected_ciphers:
                name = dc.get("name")
                if name:
                    if name in approved_ciphers_set:
                        compliant += 1
                    else:
                        non_compliant += 1
                        
        row_data["cipher_compliant"] = compliant
        row_data["cipher_compliant"] = compliant
        row_data["cipher_non_compliant"] = non_compliant
        
        # CVE Statistics
        cve_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        secrets_count = 0
        
        if web and web.data:
            if "cves" in web.data:
                for cve in web.data["cves"]:
                    try:
                        cvss = float(cve.get("cvss", 0))
                        if cvss >= 9.0:
                            cve_stats["critical"] += 1
                        elif cvss >= 7.0:
                            cve_stats["high"] += 1
                        elif cvss >= 4.0:
                            cve_stats["medium"] += 1
                        else:
                            cve_stats["low"] += 1
                    except (ValueError, TypeError) as e:
                        logger.debug(f"Failed to parse CVSS: {e}")
            
            # Secret Stats
            if "secrets" in web.data:
                secrets_count = len(web.data["secrets"])

        row_data["cve_stats"] = cve_stats
        row_data["secrets_count"] = secrets_count
        
        # Root Domain Logic
        ext = tldextract.extract(t.domain)
        # Reconstruct root (e.g. example-client.de)
        root = f"{ext.domain}.{ext.suffix}"
        row_data["root_domain"] = root
        # Check if this target IS the root (ignoring subdomain part if empty or 'www'?)
        # Strict check: is the subdomain empty?
        row_data["is_root"] = (not ext.subdomain)
        
        # Calculate visual depth
        # If no subdomain, depth 0. Else dot count + 1
        if not ext.subdomain:
            row_data["depth"] = 0
        else:
             row_data["depth"] = ext.subdomain.count('.') + 1
        
        table_rows.append(row_data)

    # -- Extract Unique Root Domains for Filter --
    # Optimization: If list is huge, this might be slow. 
    # Query all domains ONLY if we need to populate the filter?
    # Let's do a lightweight query for all domains to build the dropdown. (Tenant Scoped)
    all_domains = session.exec(select(Target.domain).where(Target.tenant_id == user.tenant_id)).all()
    unique_roots = set()
    for d in all_domains:
        ext = tldextract.extract(d)
        if ext.domain and ext.suffix:
            unique_roots.add(f"{ext.domain}.{ext.suffix}")
    
    unique_roots_list = sorted(list(unique_roots))

    return templates.TemplateResponse("target_table.html", {
        "user": user,
        "request": request, 
        "rows": table_rows,
        "filter_online": filter_online,
        "filter_last_scan": filter_last_scan,
        "filter_tag": filter_tag,
        "filter_server": filter_server,
        "filter_asn": filter_asn,
        "filter_domain": filter_domain,
        "filter_web_probe": filter_web_probe,
        
        "filter_http_status": filter_http_status,
        "filter_https_status": filter_https_status,
        "filter_redirect": filter_redirect,
        "filter_wildcard": filter_wildcard,
        "filter_scan_status": filter_scan_status,
        
        "filter_scope": filter_scope,
        "filter_root_domain": filter_root_domain,
        "unique_root_domains": unique_roots_list,
        
        "limit": limit,
        "total_targets": total_count,
        "total_pages": total_pages,
        "selected_scan_types": selected_scan_types,
        "unique_tags": get_unique_tags(session),
        "pagination": {
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "total_count": total_count,
            "start_item": offset + 1,
            "end_item": min(offset + limit, total_count)
        },
        "scan_categories": _get_scan_categories_for_user(session, user, "t"),
    })




@router.post("/scans/stop-all")
async def stop_all_scans(session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    """
    Panic Button: Immediately stops all scans.
    1. Pauses the Queue (prevent new tasks).
    2. Purges Redis Queue (remove pending).
    3. FORCE KILLS (SIGKILL) all active and reserved tasks.
    4. Updates DB status.
    """
    # 1. Pause Queue
    # We need to ensure QUEUE_ACTIVE is set to false
    # Check if we have set_system_config helper, if not, do it manually
    conf = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
    if not conf:
        conf = SystemConfig(key="QUEUE_ACTIVE", value="false")
        session.add(conf)
    else:
        conf.value = "false"
        session.add(conf)
    session.commit() # Commit pause immediately

    # 2. Purge Pending Queue
    purged_count = celery_app.control.purge()
    
    # 3. Force Kill Active & Reserved Tasks
    i = celery_app.control.inspect()
    active = i.active() if i else None
    reserved = i.reserved() if i else None
    revoked_count = 0
    
    # Helper to kill tasks
    def kill_tasks(task_dict):
        count = 0
        if task_dict:
            for worker, tasks in task_dict.items():
                for task in tasks:
                    task_id = task.get("id")
                    if task_id:
                        # SIGKILL is required for a true "Stop All"
                        celery_app.control.revoke(task_id, terminate=True, signal='SIGKILL')
                        count += 1
        return count

    revoked_count += kill_tasks(active)
    revoked_count += kill_tasks(reserved)
    
    # 4. Update DB Status
    statement = select(Target).where(Target.scan_status.in_(["running", "queued", "scanning"]))
    targets = session.exec(statement).all()
    
    db_updated_count = 0
    for t in targets:
        t.scan_status = "stopped"
        t.scan_progress = "Manually stopped (Panic)"
        session.add(t)
        db_updated_count += 1
        
    session.commit()
    
    msg = f"PANIC STOP: Queue Paused. Purged: {purged_count}, Killed: {revoked_count}, Updated: {db_updated_count}"
    return RedirectResponse(url=f"/?msg={msg}", status_code=303)
@router.get("/targets/{target_id}", response_class=HTMLResponse)
async def view_target_detail(request: Request, target_id: int, history_id: Optional[int] = None, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Fetch all results for history list (limit 50 mostly for brevity)
    history_entries = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc()).limit(50)).all()
    
    # Determine which results to show
    current_results = []
    
    if history_id:
        # User requested specific historic entry
        # For simplicity in this tailored logic: if history_id is for a DNS result, we'll try to find a Web result close to it (same "run")
        # But this basic app stores them as separate rows.
        # IMPROVED LOGIC: 
        # If history_id is provided, we fetch THAT specific result.
        # But we also need the "complementary" result (e.g. if viewing DNS, we might want to see the Web result from same time).
        # For this iteration: We just highlight the requested one, and show latest for others OR try to find closest in time.
        # Let's keep it simple: Show the specifically requested result as the "Main" one for its type.
        
        target_result = session.get(ScanResult, history_id)
        if target_result and target_result.target_id == target_id:
            current_results = [target_result]
            # Try to populate the OTHER type with the result closest in time to `target_result`
            other_type = 'web_analyzer' if target_result.module_name == 'dns_scanner' else 'dns_scanner'
            
            # Find closest
            # This is a bit complex in pure SQLModel without complex filtering, so we'll do a loose search or just fetch latest of other type.
            # Loose search:
            closest_other = session.exec(select(ScanResult).where(
                ScanResult.target_id == target_id,
                ScanResult.module_name == other_type,
                ScanResult.scanned_at <= target_result.scanned_at # Closest previous or same time
            ).order_by(ScanResult.scanned_at.desc()).limit(1)).first()
            
            if closest_other:
                current_results.append(closest_other)
        else:
            # Fallback
             current_results = history_entries 
    else:
    # Default: Latest results (derived from the history list we already fetched)
        # We need latest of EACH type.
        latest_subdomain = next((r for r in history_entries if r.module_name == 'subdomain_scanner'), None)
        latest_dns = next((r for r in history_entries if r.module_name == 'dns_scanner'), None)
        latest_web = next((r for r in history_entries if r.module_name == 'web_analyzer'), None)
        latest_typosquat = next((r for r in history_entries if r.module_name == 'typosquat_scanner'), None)
        latest_infra = next((r for r in history_entries if r.module_name == 'infrastructure_scanner'), None)
        latest_visual = next((r for r in history_entries if r.module_name == 'visual_osint'), None)
        latest_ssl = next((r for r in history_entries if r.module_name == 'ssl_scanner'), None)
        latest_wayback = next((r for r in history_entries if r.module_name == 'wayback_scanner'), None)
        latest_crawler = next((r for r in history_entries if r.module_name == 'crawler'), None)
        latest_cd = next((r for r in history_entries if r.module_name == 'content_discovery'), None)
        latest_tld = next((r for r in history_entries if r.module_name == 'tld_scanner'), None)
        latest_port = next((r for r in history_entries if r.module_name == 'port_scanner'), None)
        latest_nmap = next((r for r in history_entries if r.module_name == 'nmap_scanner'), None)
        latest_nuclei = next((r for r in history_entries if r.module_name == 'nuclei_scanner'), None)
        latest_seed_files = next((r for r in history_entries if r.module_name == 'seed_files_scanner'), None)
        latest_csp = next((r for r in history_entries if r.module_name == 'csp_scanner'), None)

        current_results = [r for r in [latest_subdomain, latest_dns, latest_web, latest_typosquat, latest_infra, latest_visual, latest_ssl, latest_wayback, latest_crawler, latest_cd, latest_tld, latest_port, latest_nmap, latest_nuclei, latest_seed_files, latest_csp] if r]

    
    # Extract specific results for template
    # Extract specific results for template
    # Prioritize subdomain_scanner for DNS view as it contains everything + subdomains
    subdomain_result = next((r for r in current_results if r.module_name == 'subdomain_scanner'), None)
    dns_only_result = next((r for r in current_results if r.module_name == 'dns_scanner'), None)
    dns_result = subdomain_result if subdomain_result else dns_only_result

    web_result = next((r for r in current_results if r.module_name == 'web_analyzer'), None)
    typosquat_result = next((r for r in current_results if r.module_name == 'typosquat_scanner'), None)
    infra_result = next((r for r in current_results if r.module_name == 'infrastructure_scanner'), None)
    visual_result = next((r for r in current_results if r.module_name == 'visual_osint'), None)
    ssl_result = next((r for r in current_results if r.module_name == 'ssl_scanner'), None)
    wayback_result = next((r for r in current_results if r.module_name == 'wayback_scanner'), None)
    crawler_result = next((r for r in current_results if r.module_name == 'crawler'), None)
    content_discovery_result = next((r for r in current_results if r.module_name == 'content_discovery'), None)
    tld_result = next((r for r in current_results if r.module_name == 'tld_scanner'), None)
    port_result = next((r for r in current_results if r.module_name == 'port_scanner'), None)
    nmap_result = next((r for r in current_results if r.module_name == 'nmap_scanner'), None)
    nuclei_result = next((r for r in current_results if r.module_name == 'nuclei_scanner'), None)
    seed_files_result = next((r for r in current_results if r.module_name == 'seed_files_scanner'), None)
    csp_result = next((r for r in current_results if r.module_name == 'csp_scanner'), None)
    email_security_result = next((r for r in current_results if r.module_name == 'email_security'), None)
    axfr_result = next((r for r in current_results if r.module_name == 'axfr_scanner'), None)
    security_txt_result = next((r for r in current_results if r.module_name == 'security_txt'), None)
    http_headers_result = next((r for r in current_results if r.module_name == 'http_headers'), None)
    cookie_result = next((r for r in current_results if r.module_name == 'cookie_scanner'), None)
    cors_result = next((r for r in current_results if r.module_name == 'cors_scanner'), None)
    cert_mismatch_result = next((r for r in current_results if r.module_name == 'cert_mismatch'), None)
    shodan_censys_result = next((r for r in current_results if r.module_name == 'shodan_censys'), None)
    threat_intel_result = next((r for r in current_results if r.module_name == 'threat_intel'), None)
    subdomain_takeover_result = next((r for r in current_results if r.module_name == 'subdomain_takeover'), None)
    git_exposure_result = next((r for r in current_results if r.module_name == 'git_exposure'), None)
    js_secrets_result = next((r for r in current_results if r.module_name == 'js_secrets'), None)
    external_resources_result = next((r for r in current_results if r.module_name == 'external_resources'), None)
    metadata_scanner_result = next((r for r in current_results if r.module_name == 'metadata_scanner'), None)
    rpki_scanner_result = next((r for r in current_results if r.module_name == 'rpki_scanner'), None)
    dsgvo_scanner_result = next((r for r in current_results if r.module_name == 'dsgvo_scanner'), None)
    waf_result = next((r for r in current_results if r.module_name == 'waf_detector'), None)
    open_redirect_result = next((r for r in current_results if r.module_name == 'open_redirect_scanner'), None)
    tls_deep_result = next((r for r in current_results if r.module_name == 'tls_deep_scanner'), None)
    banner_grabber_result = next((r for r in current_results if r.module_name == 'banner_grabber'), None)
    asn_result = next((r for r in current_results if r.module_name == 'asn_scanner'), None)
    login_scanner_result = next((r for r in current_results if r.module_name == 'login_scanner'), None)
    ipv6_result = next((r for r in current_results if r.module_name == 'ipv6_scanner'), None)
    dns_history_result = next((r for r in current_results if r.module_name == 'dns_history_scanner'), None)
    phishing_result = next((r for r in current_results if r.module_name == 'phishing_scanner'), None)
    ct_monitor_result = next((r for r in current_results if r.module_name == 'ct_monitor'), None)
    email_harvester_result = next((r for r in current_results if r.module_name == 'email_harvester'), None)
    dependency_confusion_result = next((r for r in current_results if r.module_name == 'dependency_confusion'), None)
    graphql_result = next((r for r in current_results if r.module_name == 'graphql_scanner'), None)
    websocket_result = next((r for r in current_results if r.module_name == 'websocket_scanner'), None)
    password_spray_result = next((r for r in current_results if r.module_name == 'password_spray_mapper'), None)
    leaked_credentials_result = next((r for r in current_results if r.module_name == 'leaked_credentials'), None)
    api_security_result = next((r for r in current_results if r.module_name == 'api_security_scanner'), None)
    mobile_app_result = next((r for r in current_results if r.module_name == 'mobile_app_discovery'), None)

    # -- Compliance & Grading --
    comp_input = {
        "web_result": web_result,
        "ssl_result": ssl_result,
        "nmap_result": nmap_result,
        "nuclei_result": nuclei_result,
        "port_result": port_result
    }
    security_grade = calculate_security_grade(comp_input)
    compliance_report = generate_compliance_report(comp_input)

    # -- Cipher Compliance Setup --
    from yads.models import SystemConfig
    approved_ciphers_set = set()
    ac_conf = session.get(SystemConfig, "APPROVED_CIPHERS")
    raw_ac = ""
    if ac_conf:
        raw_ac = ac_conf.value
    else:
        try:
             import os
             if os.path.exists("ciphers.csv"):
                with open("ciphers.csv", "r") as f:
                    raw_ac = f.read()
        except Exception as e:
            logger.debug(f"Failed to load ciphers.csv: {e}")
    
    if raw_ac:
        for line in raw_ac.splitlines():
             parts = line.split(',')
             if len(parts) >= 2:
                cipher_name = parts[1].strip()
                if cipher_name and cipher_name.lower() != "cipherset":
                    approved_ciphers_set.add(cipher_name)

    # Fetch Schedule
    from yads.models import ScanSchedule
    schedule = session.exec(select(ScanSchedule).where(ScanSchedule.target_id == target_id)).first()

    # Fetch recent ChangeEvents (last 24h) for the "What changed" banner
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    recent_scan_result_ids = [r.id for r in history_entries]
    recent_changes: list = []
    if recent_scan_result_ids:
        recent_changes = session.exec(
            select(ChangeEvent, ScanResult.module_name)
            .join(ScanResult, ChangeEvent.scan_result_id == ScanResult.id)
            .where(
                ChangeEvent.scan_result_id.in_(recent_scan_result_ids),
                ChangeEvent.created_at >= cutoff_24h,
            )
            .order_by(ChangeEvent.created_at.desc())
            .limit(30)
        ).all()
        # Attach module_name onto each ChangeEvent for template convenience
        enriched = []
        for ce, mod_name in recent_changes:
            ce.module_name = mod_name  # dynamic attribute, not in model
            enriched.append(ce)
        recent_changes = enriched

    # Build a set of module names that have changes (for per-card badges)
    changed_modules = {ce.module_name for ce in recent_changes}

    return templates.TemplateResponse("target_detail.html", {
        "user": user,
        "request": request,
        "target": target,
        "dns_result": dns_result,
        "web_result": web_result,
        "typosquat_result": typosquat_result,
        "infra_result": infra_result,
        "visual_result": visual_result,
        "ssl_result": ssl_result,
        "wayback_result": wayback_result,
        "crawler_result": crawler_result,
        "content_discovery_result": content_discovery_result,
        "tld_result": tld_result,
        "port_result": port_result,
        "nmap_result": nmap_result,
        "nuclei_result": nuclei_result,
        "seed_files_result": seed_files_result,
        "csp_result": csp_result,
        "email_security_result": email_security_result,
        "axfr_result": axfr_result,
        "security_txt_result": security_txt_result,
        "http_headers_result": http_headers_result,
        "cookie_result": cookie_result,
        "cors_result": cors_result,
        "cert_mismatch_result": cert_mismatch_result,
        "shodan_censys_result": shodan_censys_result,
        "threat_intel_result": threat_intel_result,
        "subdomain_takeover_result": subdomain_takeover_result,
        "git_exposure_result": git_exposure_result,
        "js_secrets_result": js_secrets_result,
        "external_resources_result": external_resources_result,
        "metadata_scanner_result": metadata_scanner_result,
        "rpki_scanner_result": rpki_scanner_result,
        "dsgvo_scanner_result": dsgvo_scanner_result,
        "waf_result": waf_result,
        "open_redirect_result": open_redirect_result,
        "tls_deep_result": tls_deep_result,
        "banner_grabber_result": banner_grabber_result,
        "asn_result": asn_result,
        "login_scanner_result": login_scanner_result,
        "ipv6_result": ipv6_result,
        "dns_history_result": dns_history_result,
        "phishing_result": phishing_result,
        "ct_monitor_result": ct_monitor_result,
        "email_harvester_result": email_harvester_result,
        "dependency_confusion_result": dependency_confusion_result,
        "graphql_result": graphql_result,
        "websocket_result": websocket_result,
        "password_spray_result": password_spray_result,
        "leaked_credentials_result": leaked_credentials_result,
        "api_security_result": api_security_result,
        "mobile_app_result": mobile_app_result,
        "security_grade": security_grade,
        "compliance_report": compliance_report,
        "history_entries": history_entries, # Pass full history
        "current_history_id": history_id,
        "raw_results": jsonable_encoder([r.model_dump() for r in current_results]),
        "approved_ciphers": approved_ciphers_set,
        "schedule": schedule,
        "scan_categories": _get_scan_categories_for_user(session, user, "sc"),
        "recent_changes": recent_changes,
        "changed_modules": changed_modules,
    })




# -- Change Events API --

@router.get("/targets/{target_id}/changes")
async def get_target_changes(
    target_id: int,
    limit: int = Query(default=30, le=100),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    """Return recent ChangeEvent records for a target as JSON."""
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    rows = session.exec(
        select(ChangeEvent, ScanResult.module_name)
        .join(ScanResult, ChangeEvent.scan_result_id == ScanResult.id)
        .where(ScanResult.target_id == target_id)
        .order_by(ChangeEvent.created_at.desc())
        .limit(limit)
    ).all()

    result = []
    for ce, mod_name in rows:
        result.append({
            "id": ce.id,
            "module_name": mod_name,
            "event_type": ce.event_type,
            "description": ce.description,
            "detected_at": ce.created_at.isoformat(),
        })
    return JSONResponse(content=result)


# -- API Endpoints (Legacy/JSON) --

@router.post("/api/targets/", response_model=Target)
def add_target(domain: str, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    domain = domain.lower().strip()
    existing = session.exec(select(Target).where(Target.domain == domain)).first()
    if existing:
        target = existing
    else:
        target = Target(domain=domain, tenant_id=user.tenant_id)
        session.add(target)
        session.commit()
        session.refresh(target)
    
    celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain, None, target.tenant_id])
    return target

@router.get("/api/targets/", response_model=List[Target])
def list_targets(session: Session = Depends(get_session)):
    return session.exec(select(Target)).all()

@router.get("/api/targets/{target_id}/traffic")
def get_target_traffic(
    target_id: int, 
    session: Session = Depends(get_session), 
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
    limit: int = Query(100, le=1000),
    offset: int = Query(0)
):
    """
    Returns historical HTTP traffic for a specific target.
    """
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    traffic = session.exec(
        select(HTTPTraffic)
        .where(HTTPTraffic.target_id == target_id)
        .order_by(HTTPTraffic.timestamp.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    
    return traffic

@router.post("/api/targets/{target_id}/traffic/{traffic_id}/replay")
def replay_traffic(
    target_id: int, 
    traffic_id: int,
    session: Session = Depends(get_session), 
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """
    Re-executes a captured HTTP request and returns the result.
    """
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    traffic = session.get(HTTPTraffic, traffic_id)
    if not traffic or traffic.target_id != target_id:
        raise HTTPException(status_code=404, detail="Traffic log not found")
        
    import requests
    import time
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    start_time = time.time()
    try:
        # Filter headers that might cause issues during replay (like host-specific or length)
        headers = {k: v for k, v in (traffic.request_headers or {}).items() if k.lower() not in ['content-length', 'host']}
        
        response = requests.request(
            method=traffic.method,
            url=traffic.url,
            headers=headers,
            timeout=10,
            verify=False
        )
        duration = round(time.time() - start_time, 2)
        
        return {
            "status_code": response.status_code,
            "duration": duration,
            "response_headers": dict(response.headers),
            "response_body_snippet": response.text[:5000]
        }
    except Exception as e:
        return {
            "status_code": 0,
            "duration": round(time.time() - start_time, 2),
            "error": str(e)
        }

@router.get("/api/targets/{target_id}", response_model=Target)
def get_target(target_id: int, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@router.get("/api/targets/{target_id}/results")
def get_target_results(target_id: int, session: Session = Depends(get_session)):
    results = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc())).all()
    return results

@router.post("/api/targets/{target_id}/brand-hunt")
def brand_hunt(target_id: int, logo_url: str = Body(..., embed=True), session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    """
    Triggers a visual comparison between a reference logo and identified typosquat domains.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    # Get latest typosquat results
    ts_result = session.exec(select(ScanResult).where(
        ScanResult.target_id == target_id,
        ScanResult.module_name == "typosquat_scanner"
    ).order_by(ScanResult.scanned_at.desc())).first()
    
    if not ts_result or not ts_result.data or not ts_result.data.get("found"):
        return {"message": "No typosquat candidates found to hunt against.", "matches": []}
        
    candidates = ts_result.data.get("found", [])

    from yads.modules.brand_monitor import BrandMonitor
    monitor = BrandMonitor()
    # This might take a few seconds, but since its a "Hunt" action, blocking slightly is okay-ish for MVP.
    # ideally async or task, but for <50 squats usually fine.
    # If many, we should background task it. But user wants "feature to select... and search".
    # Let's run it synchronously for immediate feedback as requested, unless it times out.
    matches = monitor.hunt_lookalikes(logo_url, candidates)
    
    return {"matches": matches, "count": len(matches)}

# -- Brand Logo Management --

@router.post("/targets/{target_id}/logo")
async def set_target_logo(
    target_id: int, 
    logo_url: str = Form(...), 
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "scanner"]))
):
    """
    Sets the primary brand logo for a target.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    target.brand_logo_url = logo_url.strip()
    session.add(target)
    session.commit()
    
    return RedirectResponse(url=f"/targets/{target_id}?msg=Logo+updated", status_code=303)

@router.post("/targets/{target_id}/logo/upload")
async def upload_target_logo(
    target_id: int, 
    file: UploadFile = File(...), 
    session: Session = Depends(get_session)
):
    """
    Uploads a custom logo file and sets it as primary.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    # Validate
    if not file.content_type.startswith("image/"):
        return RedirectResponse(url=f"/targets/{target_id}?error=Invalid+file+type", status_code=303)
        
    # Save
    import shutil
    import uuid
    
    ext = file.filename.split('.')[-1].lower() if '.' in file.filename else "png"
    if ext not in ["png", "jpg", "jpeg", "svg", "webp", "ico"]:
        return RedirectResponse(url=f"/targets/{target_id}?error=Invalid+extension", status_code=303)
        
    filename = f"logo_{target_id}_{uuid.uuid4().hex[:8]}.{ext}"
    upload_dir = "yads/api/static/logos"
    os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, filename)
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Update Target
        # URL path is relative to static root
        logo_url = f"/static/logos/{filename}"
        target.brand_logo_url = logo_url
        session.add(target)
        session.commit()
        
        return RedirectResponse(url=f"/targets/{target_id}?msg=Logo+uploaded", status_code=303)
    except Exception as e:
         logger.error(f"Logo upload failed: {e}")
         return RedirectResponse(url=f"/targets/{target_id}?error=Upload+failed", status_code=303)
