"""
Security Findings Overview (ASM Aggregation)
=============================================
Aggregates findings from all Phase 1 scanners across all tenant targets.
Provides a unified view of SPF/DKIM/DMARC, AXFR, CORS, headers, cookies, etc.
"""
import csv
import hashlib
import io
import json
from datetime import datetime, timezone, date
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.database import get_session
from yads.models import ScanResult, SystemConfig, Target, User

router = APIRouter(prefix="/security-findings", tags=["analytics"])

# Derived from module registry — no manual list needed
from yads.core.module_registry import get_finding_modules, get_module
FINDING_MODULES = get_finding_modules()

# Key prefix used in SystemConfig for finding status storage
_STATUS_KEY = "finding_statuses"


# ─── Finding status helpers ──────────────────────────────────────────────────

def _load_statuses(session: Session, tenant_id: Optional[int]) -> Dict[str, Dict]:
    """Load the status map for a tenant from SystemConfig."""
    key = f"{_STATUS_KEY}:{tenant_id or 'global'}"
    cfg = session.get(SystemConfig, key)
    if not cfg or not cfg.value:
        return {}
    try:
        return json.loads(cfg.value)
    except Exception:
        return {}


def _save_statuses(session: Session, tenant_id: Optional[int], statuses: Dict[str, Dict]) -> None:
    key = f"{_STATUS_KEY}:{tenant_id or 'global'}"
    cfg = session.get(SystemConfig, key)
    if cfg:
        cfg.value = json.dumps(statuses)
        session.add(cfg)
    else:
        session.add(SystemConfig(key=key, value=json.dumps(statuses)))
    session.commit()


def _finding_hash(domain: str, module: str, issue: str) -> str:
    """Deterministic hash for a finding used as status map key."""
    raw = f"{domain}|{module}|{issue}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ─── Data helpers ─────────────────────────────────────────────────────────────

def _get_tenant_targets(session: Session, user: User) -> Dict[int, Target]:
    q = select(Target).where(Target.is_archived == False)
    if user.tenant_id:
        q = q.where(Target.tenant_id == user.tenant_id)
    targets = session.exec(q).all()
    return {t.id: t for t in targets}


def _fetch_latest_results(session: Session, target_ids: Tuple[int, ...]) -> Dict[Tuple[int, str], ScanResult]:
    if not target_ids:
        return {}
    stmt = select(ScanResult).where(
        ScanResult.module_name.in_(FINDING_MODULES),
        ScanResult.target_id.in_(target_ids),
    ).order_by(ScanResult.scanned_at.desc())
    latest: Dict[Tuple[int, str], ScanResult] = {}
    for r in session.exec(stmt).all():
        key = (r.target_id, r.module_name)
        if key not in latest:
            latest[key] = r
    return latest


def _extract_findings(module: str, data: Dict) -> List[Dict]:
    """Normalize findings from any module into a standard list."""
    findings = []
    if not data:
        return findings

    if module == "email_security":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "info"),
                "issue": f"[{f.get('section','')}] {f.get('issue','')}",
                "score": data.get("score"),
            })

    elif module == "axfr_scanner":
        if data.get("vulnerable"):
            f = data.get("finding") or {}
            findings.append({
                "severity": "critical",
                "issue": f.get("issue", "Zone transfer succeeded"),
                "score": 0,
            })

    elif module == "security_txt":
        for issue in data.get("issues", []):
            findings.append({
                "severity": "low" if data.get("found") else "medium",
                "issue": issue,
                "score": data.get("score"),
            })

    elif module == "http_headers":
        for f in data.get("findings", []):
            if f.get("severity") != "info":
                findings.append({
                    "severity": f.get("severity", "low"),
                    "issue": f"{f.get('header','')}: {f.get('issue','')}",
                    "score": data.get("score"),
                })

    elif module == "cookie_scanner":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "low"),
                "issue": f"[{f.get('cookie','')}] {f.get('issue','')}",
                "score": data.get("score"),
            })

    elif module == "cors_scanner":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("issue", ""),
                "score": data.get("score"),
            })

    elif module == "cert_mismatch":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("issue", ""),
                "score": None,
            })

    elif module == "shodan_censys":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("title", ""),
                "score": data.get("summary", {}).get("score"),
            })

    elif module == "threat_intel":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("title", ""),
                "score": data.get("summary", {}).get("score"),
            })

    else:
        # Generic extractor: all new modules (extractor="generic") store
        # findings as data["findings"] with title/severity/score fields.
        mod_def = get_module(module)
        if mod_def and mod_def.extractor == "generic":
            score = (data.get("summary") or {}).get("score") or data.get("score")
            for f in data.get("findings", []):
                findings.append({
                    "severity": f.get("severity", "info"),
                    "issue": f.get("title") or f.get("issue") or f.get("id") or "",
                    "score": score,
                })

    return findings


def _build_summary(target_findings: List[Dict]) -> Dict:
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for entry in target_findings:
        for f in entry["findings"]:
            sev = f.get("severity", "info")
            stats[sev] = stats.get(sev, 0) + 1
    stats["total"] = sum(stats.values())
    stats["targets_with_findings"] = sum(1 for e in target_findings if e["findings"])
    return stats


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def security_findings_overview(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    module_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
):
    target_map = _get_tenant_targets(session, user)
    statuses = _load_statuses(session, user.tenant_id)

    if not target_map:
        return templates.TemplateResponse("security_findings.html", {
            "request": request,
            "user": user,
            "target_findings": [],
            "summary": {"total": 0, "targets_with_findings": 0},
            "module_filter": module_filter,
            "severity_filter": severity_filter,
            "status_filter": status_filter,
            "finding_modules": FINDING_MODULES,
            "statuses": statuses,
        })

    target_ids = tuple(target_map.keys())
    latest = _fetch_latest_results(session, target_ids)

    target_findings = []
    for tid, target in sorted(target_map.items(), key=lambda x: x[1].domain):
        all_findings = []
        modules_scanned = []

        for module in FINDING_MODULES:
            if module_filter and module != module_filter:
                continue
            result = latest.get((tid, module))
            if result and result.data:
                findings = _extract_findings(module, result.data)
                if severity_filter:
                    findings = [f for f in findings if f["severity"] == severity_filter]

                # Annotate each finding with its hash and status
                enriched = []
                for f in findings:
                    fhash = _finding_hash(target.domain, module, f["issue"])
                    st = statuses.get(fhash, {})
                    fstatus = st.get("status", "open")
                    if status_filter and fstatus != status_filter:
                        continue
                    enriched.append({
                        **f,
                        "module": module,
                        "finding_hash": fhash,
                        "status": fstatus,
                        "status_note": st.get("note", ""),
                        "status_updated_at": st.get("updated_at", ""),
                        "scanned_at": result.scanned_at.isoformat() if result.scanned_at else "",
                    })

                if enriched:
                    all_findings.extend(enriched)
                    modules_scanned.append({
                        "module": module,
                        "scanned_at": result.scanned_at,
                        "finding_count": len(enriched),
                    })

        if all_findings or not (module_filter or severity_filter or status_filter):
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 99))
            target_findings.append({
                "target": target,
                "findings": all_findings,
                "modules_scanned": modules_scanned,
                "highest_severity": all_findings[0]["severity"] if all_findings else None,
            })

    # Sort: targets with critical/high findings first
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 99}
    target_findings.sort(key=lambda x: sev_order.get(x["highest_severity"], 99))

    summary = _build_summary(target_findings)

    return templates.TemplateResponse("security_findings.html", {
        "request": request,
        "user": user,
        "target_findings": target_findings,
        "summary": summary,
        "module_filter": module_filter,
        "severity_filter": severity_filter,
        "status_filter": status_filter,
        "finding_modules": FINDING_MODULES,
        "statuses": statuses,
    })


@router.post("/api/findings/{finding_hash}/status")
async def update_finding_status(
    finding_hash: str,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    """Update the triage status of a finding.

    Body JSON: {status: "open"|"acknowledged"|"false_positive"|"fixed", note: str}
    """
    body = await request.json()
    status = body.get("status", "open")
    note = body.get("note", "")

    valid_statuses = {"open", "acknowledged", "false_positive", "fixed"}
    if status not in valid_statuses:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(valid_statuses)}")

    statuses = _load_statuses(session, user.tenant_id)
    statuses[finding_hash] = {
        "status": status,
        "note": note,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "updated_by": user.username,
    }
    _save_statuses(session, user.tenant_id, statuses)

    return {"finding_hash": finding_hash, "status": status}


@router.get("/api/findings/export")
async def export_findings_csv(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    module: Optional[str] = None,
    domain: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    """Export findings as CSV. Supports filters: severity, status, module, domain, date_from, date_to."""
    target_map = _get_tenant_targets(session, user)
    statuses = _load_statuses(session, user.tenant_id)

    if not target_map:
        content = "domain,title,severity,module,status,found_at,notes\n"
        return StreamingResponse(
            io.StringIO(content),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=findings.csv"},
        )

    # Optional date parsing
    dt_from: Optional[datetime] = None
    dt_to: Optional[datetime] = None
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
        except ValueError:
            pass

    # Filter targets by domain
    if domain:
        target_map = {tid: t for tid, t in target_map.items() if domain.lower() in t.domain.lower()}

    target_ids = tuple(target_map.keys())
    latest = _fetch_latest_results(session, target_ids)

    rows = []
    for tid, target in sorted(target_map.items(), key=lambda x: x[1].domain):
        for mod in FINDING_MODULES:
            if module and mod != module:
                continue
            result = latest.get((tid, mod))
            if not result or not result.data:
                continue
            # Date filter
            if dt_from and result.scanned_at and result.scanned_at < dt_from:
                continue
            if dt_to and result.scanned_at and result.scanned_at > dt_to:
                continue

            findings = _extract_findings(mod, result.data)
            for f in findings:
                if severity and f.get("severity") != severity:
                    continue
                fhash = _finding_hash(target.domain, mod, f["issue"])
                st = statuses.get(fhash, {})
                fstatus = st.get("status", "open")
                if status and fstatus != status:
                    continue
                rows.append({
                    "domain": target.domain,
                    "title": f["issue"],
                    "severity": f.get("severity", ""),
                    "module": mod,
                    "status": fstatus,
                    "found_at": result.scanned_at.isoformat() if result.scanned_at else "",
                    "notes": st.get("note", ""),
                })

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["domain", "title", "severity", "module", "status", "found_at", "notes"])
    writer.writeheader()
    writer.writerows(rows)
    output.seek(0)

    filename = f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
