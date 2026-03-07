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
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import RoleChecker
from yads.database import get_session
from yads.models import IntegrationConfig, ScanResult, Target, User

logger = logging.getLogger(__name__)

router = APIRouter()

TIMEOUT = 15

# ─────────────────────────────────────────
# CEF / ECS formatting helpers
# ─────────────────────────────────────────

SEVERITY_TO_CEF = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
SEVERITY_TO_ECS = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "informational"}


def _finding_to_cef(finding: Dict, target_domain: str, vendor: str = "YADS") -> str:
    """Format a finding as a CEF (Common Event Format) syslog line."""
    severity = finding.get("severity", "info")
    cef_sev = SEVERITY_TO_CEF.get(severity, 1)
    title = finding.get("title", "Security Finding").replace("|", "/").replace("\\", "/")
    desc = finding.get("description", "").replace("|", "/").replace("\\", "/")[:200]
    now = datetime.utcnow().strftime("%b %d %H:%M:%S")
    header = f"CEF:0|{vendor}|YADS|1.0|{severity.upper()}|{title}|{cef_sev}|"
    ext = f"dhost={target_domain} msg={desc} outcome={severity}"
    return f"{now} {target_domain} {header}{ext}"


def _finding_to_ecs(finding: Dict, target_domain: str) -> Dict:
    """Format a finding as an ECS (Elastic Common Schema) event."""
    return {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "event": {
            "kind": "alert",
            "category": ["vulnerability"],
            "type": ["info"],
            "severity": SEVERITY_TO_CEF.get(finding.get("severity", "info"), 1),
            "outcome": "unknown",
        },
        "vulnerability": {
            "severity": SEVERITY_TO_ECS.get(finding.get("severity", "info"), "informational"),
            "description": finding.get("description", ""),
            "category": ["finding"],
        },
        "host": {"name": target_domain},
        "message": finding.get("title", ""),
        "labels": {"source": "yads", "severity": finding.get("severity", "info")},
    }


# ─────────────────────────────────────────
# Integration push functions
# ─────────────────────────────────────────

def _push_to_jira(config: Dict, finding: Dict, target_domain: str) -> Optional[str]:
    """Create a Jira issue from a finding. Returns issue key or None."""
    base_url = config.get("base_url", "").rstrip("/")
    email = config.get("email", "")
    api_token = config.get("api_token", "")
    project_key = config.get("project_key", "")
    issue_type = config.get("issue_type", "Bug")

    if not all([base_url, email, api_token, project_key]):
        return None

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
        r = requests.post(
            f"{base_url}/rest/api/3/issue",
            json=payload,
            auth=(email, api_token),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code in (200, 201):
            return r.json().get("key")
        logger.warning(f"Jira create failed: {r.status_code} {r.text[:200]}")
    except Exception as e:
        logger.error(f"Jira push error: {e}")
    return None


def _push_to_github(config: Dict, finding: Dict, target_domain: str) -> Optional[str]:
    """Create a GitHub issue from a finding. Returns issue URL or None."""
    token = config.get("token", "")
    repo = config.get("repo", "")  # "owner/repo"
    labels = config.get("labels", ["security", "yads"])

    if not all([token, repo]):
        return None

    severity = finding.get("severity", "info")
    body = (
        f"**Severity:** {severity}\n"
        f"**Target:** {target_domain}\n"
        f"**Source:** YADS Security Scanner\n\n"
        f"---\n\n"
        f"{finding.get('description', '')}"
    )

    payload = {
        "title": f"[YADS/{target_domain}] {finding.get('title', 'Security Finding')}",
        "body": body,
        "labels": labels,
    }

    try:
        r = requests.post(
            f"https://api.github.com/repos/{repo}/issues",
            json=payload,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "YADS-Security-Scanner/1.0",
            },
            timeout=TIMEOUT,
        )
        if r.status_code == 201:
            return r.json().get("html_url")
        logger.warning(f"GitHub issue create failed: {r.status_code} {r.text[:200]}")
    except Exception as e:
        logger.error(f"GitHub push error: {e}")
    return None


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
        r = requests.post(endpoint, json=payload, headers=headers, timeout=TIMEOUT, verify=False)
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


@router.post("/integrations/{integration_type}/save", response_class=HTMLResponse)
async def save_integration(
    integration_type: str,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
):
    valid_types = {"jira", "github", "siem_syslog", "siem_http"}
    if integration_type not in valid_types:
        raise HTTPException(status_code=400, detail="Invalid integration type")

    form = await request.form()
    config = {k: v for k, v in form.items() if k not in ("integration_type",)}

    existing = session.exec(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == user.tenant_id,
            IntegrationConfig.integration_type == integration_type,
        )
    ).first()

    if existing:
        existing.config = config
        existing.updated_at = datetime.utcnow()
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
        result = _push_to_jira(config, finding, target_domain)
        return {"success": bool(result), "issue_key": result}

    elif integration_type == "github":
        result = _push_to_github(config, finding, target_domain)
        return {"success": bool(result), "issue_url": result}

    elif integration_type == "siem_syslog":
        cef = _finding_to_cef(finding, target_domain)
        ok = _push_to_siem_syslog(config, cef)
        return {"success": ok, "cef_line": cef}

    elif integration_type == "siem_http":
        ecs = _finding_to_ecs(finding, target_domain)
        ok = _push_to_siem_http(config, ecs)
        return {"success": ok}

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

    lines = []
    for sr in scan_results:
        data = sr.data or {}
        for finding in data.get("findings", []):
            if finding.get("severity") not in ("info",):
                lines.append(_finding_to_cef(finding, target.domain))

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

    events = []
    for sr in scan_results:
        data = sr.data or {}
        for finding in data.get("findings", []):
            if finding.get("severity") not in ("info",):
                events.append(_finding_to_ecs(finding, target.domain))

    return JR(
        content=events,
        headers={"Content-Disposition": f"attachment; filename={target.domain}_findings_ecs.json"},
    )
