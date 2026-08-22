"""
Integrations Router (#31 Jira/GitHub Issues + #32 SIEM Connector)

Manages external tool integrations:
  - Jira: Create issues from findings with configurable project/issuetype
  - GitHub Issues: Create issues in a repo from findings
  - SIEM Syslog: Push findings in CEF format to syslog endpoint
  - SIEM HTTP: Push findings in ECS format to HTTP endpoint (Elastic/Splunk HEC)
  - Slack: Already implemented via webhooks — referenced here for completeness
"""

import json
import logging
import socket
import struct
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional

import requests
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import Session, select

JSON_CONTENT_TYPE = "application/json"

from yads.api.templating import templates
from yads.auth.deps import RoleChecker
from yads.database import get_session
from yads.models import IntegrationConfig, ScanResult, Target, User, SecurityFinding

logger = logging.getLogger(__name__)

router = APIRouter()

TIMEOUT = 15


def _validate_integration_url(url: str, field: str = "URL") -> None:
    """Reject non-http(s) schemes and known cloud metadata hosts in integration URLs."""
    from yads.utils.ssrf import validate_integration_url
    try:
        validate_integration_url(url, field)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


def _probe_url_no_redirect_ssrf(url: str, max_hops: int = 5):
    """
    SSRF-safe HEAD probe for the integration health-check (#57).

    requests(..., allow_redirects=True) validates only the ORIGINAL url —
    a malicious/compromised endpoint can then 30x-redirect the request to
    an internal/metadata host and requests will follow it blindly, bypassing
    _validate_integration_url() entirely. Fix: follow redirects manually,
    one hop at a time, re-validating the Location header against the same
    allowlist check before every request.
    """
    _validate_integration_url(url, "Integration URL")
    current = url
    for _ in range(max_hops):
        resp = requests.head(current, timeout=8, allow_redirects=False)
        if resp.is_redirect and resp.headers.get("Location"):
            current = resp.headers["Location"]
            _validate_integration_url(current, "Integration URL (redirect target)")
            continue
        return resp
    return resp

# ─────────────────────────────────────────
# CEF / ECS formatting helpers
# ─────────────────────────────────────────

SEVERITY_TO_CEF = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
SEVERITY_TO_ECS = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "informational"}


def _finding_to_cef(finding: Dict, target_domain: str, vendor: str = "YADS", status: str = "open") -> str:
    """Format a finding as a CEF (Common Event Format) syslog line."""
    severity = finding.get("severity", "info")
    cef_sev = SEVERITY_TO_CEF.get(severity, 1)
    title = finding.get("title", "Security Finding").replace("|", "/").replace("\\", "/")
    desc = finding.get("description", "").replace("|", "/").replace("\\", "/")[:200]
    now = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    
    # Translate status to CEF outcome
    outcome = status
    if status in ("fixed", "false_positive"):
        outcome = "resolved"
    
    header = f"CEF:0|{vendor}|YADS|1.0|{severity.upper()}|{title}|{cef_sev}|"
    ext = f"dhost={target_domain} msg={desc} outcome={outcome} cs1Label=TriageStatus cs1={status}"
    return f"{now} {target_domain} {header}{ext}"


def _finding_to_ecs(finding: Dict, target_domain: str, status: str = "open") -> Dict:
    """Format a finding as an ECS (Elastic Common Schema) event."""
    outcome = "success" if status in ("fixed", "false_positive") else "unknown"
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "event": {
            "kind": "alert",
            "category": ["vulnerability"],
            "type": ["info"],
            "severity": SEVERITY_TO_CEF.get(finding.get("severity", "info"), 1),
            "outcome": outcome,
        },
        "vulnerability": {
            "severity": SEVERITY_TO_ECS.get(finding.get("severity", "info"), "informational"),
            "description": finding.get("description", ""),
            "category": ["finding"],
        },
        "host": {"name": target_domain},
        "message": finding.get("title", ""),
        "labels": {
            "source": "yads", 
            "severity": finding.get("severity", "info"),
            "status": status
        },
    }


# ─────────────────────────────────────────
# Integration push functions
# ─────────────────────────────────────────

def _push_to_jira(config: Dict, finding: Dict, target_domain: str, status: str = "open", ticket_ref: str = None) -> Optional[str]:
    """Create or update a Jira issue. Returns issue key."""
    base_url = config.get("base_url", "").rstrip("/")
    email = config.get("email", "")
    api_token = config.get("api_token", "")
    project_key = config.get("project_key", "")
    issue_type = config.get("issue_type", "Bug")

    if not all([base_url, email, api_token, project_key]):
        return None

    auth = (email, api_token)
    headers = {"Accept": JSON_CONTENT_TYPE, "Content-Type": JSON_CONTENT_TYPE}

    # 1. Update existing ticket if ref provided
    if ticket_ref:
        try:
            # Add a comment about the status update
            comment_payload = {
                "body": f"YADS Status Update: Finding is now '{status}'. Target: {target_domain}"
            }
            requests.post(
                f"{base_url}/rest/api/3/issue/{ticket_ref}/comment",
                json=comment_payload, auth=auth, headers=headers, timeout=TIMEOUT
            )

            # If closed, transition to "Done" (ID 4 is standard, but we'll try by name first)
            if status in ("fixed", "false_positive"):
                # Fetch available transitions
                trans_resp = requests.get(f"{base_url}/rest/api/3/issue/{ticket_ref}/transitions", auth=auth, headers=headers, timeout=TIMEOUT)
                if trans_resp.status_code == 200:
                    transitions = trans_resp.json().get("transitions", [])
                    done_id = next((t["id"] for t in transitions if t["name"].lower() in ("done", "closed", "resolved")), None)
                    if done_id:
                        requests.post(
                            f"{base_url}/rest/api/3/issue/{ticket_ref}/transitions",
                            json={"transition": {"id": done_id}}, auth=auth, headers=headers, timeout=TIMEOUT
                        )
            return ticket_ref
        except Exception as e:
            logger.error(f"Jira update error for {ticket_ref}: {e}")
            return None

    # 2. Create new ticket
    severity = finding.get("severity", "info")
    priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[YADS/{target_domain}] {finding.get('title', 'Security Finding')}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": finding.get("description", "")}]
                }, {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": f"\nSeverity: {severity}\nTarget: {target_domain}\nSource: YADS Security Scanner"}]
                }]
            },
            "issuetype": {"name": issue_type},
            "priority": {"name": priority_map.get(severity, "Medium")},
        }
    }

    try:
        r = requests.post(f"{base_url}/rest/api/3/issue", json=payload, auth=auth, headers=headers, timeout=TIMEOUT)
        if r.status_code in (200, 201):
            return r.json().get("key")
    except Exception as e:
        logger.error(f"Jira push error: {e}")
    return None


def _push_to_github(config: Dict, finding: Dict, target_domain: str, status: str = "open", ticket_ref: str = None) -> Optional[str]:
    """Create or close a GitHub issue."""
    token = config.get("token", "")
    repo = config.get("repo", "")
    labels = config.get("labels", ["security", "yads"])

    if not all([token, repo]):
        return None

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "YADS-Security-Scanner/1.0",
    }

    # 1. Update/Close existing issue
    if ticket_ref:
        try:
            issue_id = ticket_ref.rstrip("/").split("/")[-1]
            comment_url = f"https://api.github.com/repos/{repo}/issues/{issue_id}/comments"
            requests.post(comment_url, json={"body": f"YADS Status Update: Finding is now '{status}'."}, headers=headers, timeout=TIMEOUT)

            if status in ("fixed", "false_positive"):
                requests.patch(f"https://api.github.com/repos/{repo}/issues/{issue_id}", json={"state": "closed"}, headers=headers, timeout=TIMEOUT)
            return ticket_ref
        except Exception as e:
            logger.error(f"GitHub update error: {e}")
            return None

    # 2. Create new issue
    severity = finding.get("severity", "info")
    body = f"**Severity:** {severity}\n**Target:** {target_domain}\n\n{finding.get('description', '')}"
    payload = {
        "title": f"[YADS/{target_domain}] {finding.get('title', 'Security Finding')}",
        "body": body,
        "labels": labels,
    }

    try:
        r = requests.post(f"https://api.github.com/repos/{repo}/issues", json=payload, headers=headers, timeout=TIMEOUT)
        if r.status_code == 201:
            return r.json().get("html_url")
    except Exception as e:
        logger.error(f"GitHub push error: {e}")
    return None


def _push_to_servicenow(config: Dict, finding: Dict, target_domain: str, status: str = "open", ticket_ref: str = None) -> Optional[str]:
    """Skeleton for ServiceNow integration (Table API)."""
    instance_url = config.get("instance_url", "").rstrip("/")
    user = config.get("user", "")
    pwd = config.get("password", "")
    _ = config.get("table", "incident")

    if not all([instance_url, user, pwd]):
        return None
    
    # Placeholder: Implementation logic for ServiceNow status sync goes here
    logger.info(f"ServiceNow Push (Skeleton): {target_domain} {finding.get('title')} -> {status}")
    return ticket_ref or "SN-PLACEHOLDER"


def _push_to_siem_syslog(config: Dict, cef_line: str) -> bool:
    """Send CEF line to syslog host:port via UDP or TCP."""
    host = config.get("host", "")
    port = int(config.get("port", 514))
    protocol = config.get("protocol", "udp").lower()

    if not host:
        return False
    try:
        msg = (cef_line + "\n").encode("utf-8")
        if protocol == "tcp":
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(msg)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(msg, (host, port))
        return True
    except Exception as e:
        logger.error(f"Syslog push error: {e}")
        return False


def _push_to_siem_http(config: Dict, ecs_event: Dict) -> bool:
    """Send ECS event to HTTP endpoint (Elastic/Splunk HEC)."""
    endpoint = config.get("endpoint", "")
    token = config.get("token", "")
    format_type = config.get("format", "ecs")  # "ecs" or "splunk_hec"

    if not endpoint:
        return False

    headers = {"Content-Type": "application/json"}
    if token:
        if "splunk" in endpoint.lower() or format_type == "splunk_hec":
            headers["Authorization"] = f"Splunk {token}"
        else:
            headers["Authorization"] = f"Bearer {token}"

    if format_type == "splunk_hec":
        payload = {"event": ecs_event, "sourcetype": "yads:finding"}
    else:
        payload = ecs_event

    try:
        verify_ssl = config.get("verify_ssl", True)
        r = requests.post(endpoint, json=payload, headers=headers, timeout=TIMEOUT, verify=verify_ssl)
        return r.status_code in (200, 201, 204)
    except Exception as e:
        logger.error(f"SIEM HTTP push error: {e}")
        return False


# ─────────────────────────────────────────
# Routes
# ─────────────────────────────────────────

@router.get("/integrations", response_class=HTMLResponse)
async def integrations_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
):
    configs = session.exec(
        select(IntegrationConfig).where(IntegrationConfig.tenant_id == user.tenant_id)
    ).all()
    config_map = {c.integration_type: c for c in configs}

    return templates.TemplateResponse("integrations.html", {
        "request": request,
        "user": user,
        "config_map": config_map,
        "page_title": "Integrations",
    })


@router.post("/integrations/{integration_type}/test")
async def test_integration(
    integration_type: str,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
):
    """
    Integrations health check (#57) — mirrors #19's BYOK key health-check
    pattern (Baustein 2, Welle 0) but for notification integrations. A
    non-invasive reachability check (no test message sent) against the
    configured webhook/API URL.
    """
    from yads.core.integration_health import record_health_check

    ic = session.exec(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == user.tenant_id,
            IntegrationConfig.integration_type == integration_type,
        )
    ).first()
    if not ic:
        raise HTTPException(status_code=404, detail="Integration not configured")

    url = ic.config.get("url") or ic.config.get("webhook_url") or ic.config.get("api_url")
    ok, message = False, "No URL configured to test"
    if url:
        try:
            resp = _probe_url_no_redirect_ssrf(url)
            # Many webhook endpoints reject bare HEAD/GET with 4xx but are
            # still reachable — anything that isn't a connection failure or
            # 5xx counts as "reachable".
            ok = resp.status_code < 500
            message = f"Reachable (HTTP {resp.status_code})" if ok else f"Server error (HTTP {resp.status_code})"
        except Exception as e:
            ok, message = False, f"Unreachable: {e}"
    else:
        ok = True
        message = "No URL field for this integration type — presence check only"

    record_health_check(session, ic, ok, message)
    return {"integration_type": integration_type, "status": "ok" if ok else "failed", "message": message}


@router.post("/integrations/{integration_type}/save", response_class=HTMLResponse)
async def save_integration(
    integration_type: str,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
):
    valid_types = {"jira", "github", "siem_syslog", "siem_http", "searxng"}
    if integration_type not in valid_types:
        raise HTTPException(status_code=400, detail="Invalid integration type")

    form = await request.form()
    config = {k: v for k, v in form.items() if k not in ("integration_type",)}

    # SSRF: validate any URL/endpoint fields supplied by the user
    if integration_type == "jira":
        _validate_integration_url(config.get("base_url", ""), "base_url")
    elif integration_type == "siem_http":
        _validate_integration_url(config.get("endpoint", ""), "endpoint")
    elif integration_type == "searxng":
        _validate_integration_url(config.get("url", ""), "url")

    existing = session.exec(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == user.tenant_id,
            IntegrationConfig.integration_type == integration_type,
        )
    ).first()

    if existing:
        existing.config = config
        existing.updated_at = datetime.now(timezone.utc)
        existing.is_active = True
        session.add(existing)
    else:
        ic = IntegrationConfig(
            tenant_id=user.tenant_id,
            integration_type=integration_type,
            config=config,
            created_by=user.id,
        )
        session.add(ic)

    session.commit()
    return RedirectResponse(url="/integrations?msg=Saved", status_code=303)


@router.post("/integrations/{integration_type}/disable", response_class=HTMLResponse)
async def disable_integration(
    integration_type: str,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
):
    ic = session.exec(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == user.tenant_id,
            IntegrationConfig.integration_type == integration_type,
        )
    ).first()
    if ic:
        ic.is_active = False
        session.add(ic)
        session.commit()
    return RedirectResponse(url="/integrations?msg=Disabled", status_code=303)


@router.post("/api/integrations/push-finding")
async def push_finding_to_integration(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    """
    Push a single finding to a configured integration.
    Body: { integration_type, finding, target_domain }
    """
    body = await request.json()
    integration_type = body.get("integration_type")
    finding = body.get("finding", {})
    target_domain = body.get("target_domain", "unknown")

    # Fetch SecurityFinding if hash available
    fhash = finding.get("finding_hash")
    sf = None
    if fhash:
        sf = session.exec(select(SecurityFinding).where(SecurityFinding.finding_hash == fhash)).first()

    status = sf.status if sf else "open"
    ticket_ref = sf.ticket_ref if sf else None

    ic = session.exec(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == user.tenant_id,
            IntegrationConfig.integration_type == integration_type,
            IntegrationConfig.is_active == True,
        )
    ).first()

    if not ic:
        raise HTTPException(status_code=404, detail=f"Integration '{integration_type}' not configured or disabled")

    config = ic.config or {}
    result = None

    if integration_type == "jira":
        result = _push_to_jira(config, finding, target_domain, status=status, ticket_ref=ticket_ref)
        if result and sf:
            sf.ticket_ref = result
            session.add(sf)
            session.commit()
        return {"success": bool(result), "issue_key": result}

    elif integration_type == "github":
        result = _push_to_github(config, finding, target_domain, status=status, ticket_ref=ticket_ref)
        if result and sf:
            sf.ticket_ref = result
            session.add(sf)
            session.commit()
        return {"success": bool(result), "issue_url": result}

    elif integration_type == "siem_syslog":
        cef = _finding_to_cef(finding, target_domain, status=status)
        ok = _push_to_siem_syslog(config, cef)
        return {"success": ok, "cef_line": cef}

    elif integration_type == "siem_http":
        ecs = _finding_to_ecs(finding, target_domain, status=status)
        ok = _push_to_siem_http(config, ecs)
        return {"success": ok}

    elif integration_type == "servicenow":
        result = _push_to_servicenow(config, finding, target_domain, status=status, ticket_ref=ticket_ref)
        return {"success": bool(result), "ticket_ref": result}

    raise HTTPException(status_code=400, detail="Unknown integration type")


@router.get("/api/integrations/export/cef/{target_id}")
async def export_cef(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    """Export all findings for a target as CEF lines (text/plain)."""
    from fastapi.responses import PlainTextResponse

    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan_results = session.exec(
        select(ScanResult).where(ScanResult.target_id == target_id)
        .order_by(ScanResult.created_at.desc())
    ).all()

    # Get triage status mapping
    sf_statement = select(SecurityFinding).where(SecurityFinding.target_id == target_id)
    sf_rows = session.exec(sf_statement).all()
    sf_status_map = {row.finding_hash: row.status for row in sf_rows}

    lines = []
    for sr in scan_results:
        data = sr.data or {}
        for finding in data.get("findings", []):
            if finding.get("severity") not in ("info",):
                fhash = finding.get("finding_hash")
                status = sf_status_map.get(fhash, "open")
                lines.append(_finding_to_cef(finding, target.domain, status=status))

    return PlainTextResponse(
        content="\n".join(lines),
        headers={"Content-Disposition": f"attachment; filename={target.domain}_findings.cef"},
    )


@router.get("/api/integrations/export/ecs/{target_id}")
async def export_ecs(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    """Export all findings for a target as ECS JSON array."""
    from fastapi.responses import JSONResponse as JR

    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan_results = session.exec(
        select(ScanResult).where(ScanResult.target_id == target_id)
        .order_by(ScanResult.created_at.desc())
    ).all()

    # Get triage status mapping
    sf_statement = select(SecurityFinding).where(SecurityFinding.target_id == target_id)
    sf_rows = session.exec(sf_statement).all()
    sf_status_map = {row.finding_hash: row.status for row in sf_rows}

    events = []
    for sr in scan_results:
        data = sr.data or {}
        for finding in data.get("findings", []):
            if finding.get("severity") not in ("info",):
                fhash = finding.get("finding_hash")
                status = sf_status_map.get(fhash, "open")
                events.append(_finding_to_ecs(finding, target.domain, status=status))

    return JR(
        content=events,
        headers={"Content-Disposition": f"attachment; filename={target.domain}_findings_ecs.json"},
    )


@router.post("/api/integrations/splunk/alert")
async def splunk_alert_webhook(
    request: Request,
    session: Session = Depends(get_session),
) -> JSONResponse:
    """
    Splunk Alert Webhook Receiver.
    Triggered by Splunk Notable Events to initiate automated re-scans or target prioritization in YADS.
    """
    try:
        body = await request.json()
        search_name = body.get("search_name", "Splunk Alert")
        result = body.get("result", {})
        domain = result.get("domain") or result.get("event.domain")

        logger.info(f"[Splunk Webhook] Alert received: '{search_name}' for domain '{domain}'")

        if domain:
            target = session.exec(select(Target).where(Target.domain == domain)).first()
            if target:
                target.scan_priority = 9  # High Priority
                target.scan_status = "queued"
                session.add(target)
                session.commit()
                
                from yads.worker_core import celery_app
                celery_app.send_task(
                    "yads.worker.run_all_scans",
                    args=[target.id, target.domain, None, target.tenant_id],
                )
                return JSONResponse(content={
                    "status": "ok",
                    "action": "prioritized_and_rescanned",
                    "target": domain
                })

        return JSONResponse(content={"status": "ok", "action": "logged", "alert": search_name})
    except Exception as exc:
        logger.error(f"[Splunk Webhook] Processing error: {exc}")
        return JSONResponse(status_code=400, content={"status": "error", "detail": str(exc)})
