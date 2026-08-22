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
from datetime import datetime, timezone, date, timedelta
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.database import get_session
from yads.models import ScanResult, SystemConfig, Target, Tenant, User, SecurityFinding
from yads.utils.findings import get_finding_hash
from yads.core.mitre_mapping import get_mitre_mapping

router = APIRouter(prefix="/security-findings", tags=["analytics"])

# Derived from module registry — no manual list needed
from yads.core.module_registry import get_finding_modules, get_module
FINDING_MODULES = sorted(get_finding_modules())

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
    return get_finding_hash(domain, module, issue)


# ─── YF-ID / SecurityFinding helpers ─────────────────────────────────────────

_YF_COUNTER_KEY = "finding_yf_counter"

_BSI_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": None}


def _get_sla_days(tenant: Optional["Tenant"], severity: str) -> Optional[int]:
    """Return SLA days for a severity, using tenant overrides or BSI defaults."""
    if tenant:
        return getattr(tenant, f"sla_{severity}", _BSI_SLA_DAYS.get(severity))
    return _BSI_SLA_DAYS.get(severity)


def _upsert_findings(
    session: Session,
    findings_data: List[Dict],
    tenant_id: Optional[int],
    tenant: Optional["Tenant"],
) -> Dict[str, "SecurityFinding"]:
    """
    Upsert SecurityFinding rows for all findings in findings_data.
    Creates new rows (with YF-ID + due_date) or updates last_seen.
    Returns dict mapping finding_hash → SecurityFinding.
    """
    if not findings_data:
        return {}

    hashes = [f["finding_hash"] for f in findings_data]
    existing_rows = session.exec(
        select(SecurityFinding).where(SecurityFinding.finding_hash.in_(hashes))
    ).all()
    existing_map: Dict[str, SecurityFinding] = {r.finding_hash: r for r in existing_rows}

    # Load counter for new IDs
    counter_cfg = session.get(SystemConfig, _YF_COUNTER_KEY)
    counter = int(counter_cfg.value) if counter_cfg and counter_cfg.value else 0

    now = datetime.now(timezone.utc)
    changed = False

    for f in findings_data:
        fhash = f["finding_hash"]
        if fhash in existing_map:
            row = existing_map[fhash]
            row.last_seen = now
            session.add(row)
        else:
            counter += 1
            sla_days = _get_sla_days(tenant, f.get("severity", "info"))
            due = date.fromisoformat(now.date().isoformat())
            from datetime import timedelta
            due_date = (now + timedelta(days=sla_days)).date() if sla_days else None
            module_name = f.get("module", "")
            mitre = get_mitre_mapping(module_name, f.get("issue", ""))
            row = SecurityFinding(
                yf_id=f"YF-{counter:06d}",
                finding_hash=fhash,
                tenant_id=tenant_id,
                target_id=f.get("target_id"),
                domain=f.get("domain", ""),
                module=module_name,
                issue=f.get("issue", ""),
                severity=f.get("severity", "info"),
                first_found=now,
                last_seen=now,
                due_date=due_date,
                status="open",
                mitre_tactic_id=mitre["tactic_id"] if mitre else None,
                mitre_technique_id=mitre["technique_id"] if mitre else None,
                mitre_technique_name=mitre["technique_name"] if mitre else None,
            )
            session.add(row)
            existing_map[fhash] = row
            changed = True

    if changed:
        if counter_cfg:
            counter_cfg.value = str(counter)
            session.add(counter_cfg)
        else:
            session.add(SystemConfig(key=_YF_COUNTER_KEY, value=str(counter)))

    session.commit()
    # Refresh to get DB-assigned IDs
    for row in existing_map.values():
        session.refresh(row)
    return existing_map


# ─── Data helpers ─────────────────────────────────────────────────────────────

def _get_finding_for_user(session: Session, finding_hash: str, user: User) -> SecurityFinding:
    """
    Tenant-scoped lookup for finding-mutation endpoints (status/NIS2 mark).
    finding_hash is a stable but non-secret SHA256[:16] of domain|module|issue
    — without this check, any authenticated user of ANY tenant could retriage
    or NIS2-mark another tenant's finding just by knowing/guessing its hash
    (IDOR). Platform admins (tenant_id=None) are unrestricted, matching the
    same convention as _get_tenant_targets() below.
    """
    from fastapi import HTTPException
    stmt = select(SecurityFinding).where(SecurityFinding.finding_hash == finding_hash)
    if user.tenant_id:
        stmt = stmt.where(SecurityFinding.tenant_id == user.tenant_id)
    sf = session.exec(stmt).first()
    if not sf:
        raise HTTPException(status_code=404, detail="Finding not found")
    return sf


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

    elif module == "web_analyzer":
        # Narrowly scoped (#28): only redirect-chain health issues, not the
        # rest of web_analyzer's data — that module isn't a finding_module.
        for f in data.get("redirect_chain_issues", []):
            findings.append({
                "severity": f.get("severity", "info"),
                "issue": f.get("title", ""),
                "score": None,
            })

    elif module == "api_discovery":
        # Narrowly scoped (#63): only the endpoint-delta findings, not the
        # rest of api_discovery's data — mirrors the web_analyzer pattern (#28).
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "info"),
                "issue": f.get("title", ""),
                "score": None,
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


def _compute_mttr(session: Session, tenant_id: Optional[int]) -> Dict:
    """
    SLA/MTTR tracking (#89): mean time-to-remediate per severity, computed
    from SecurityFinding.first_found -> closing_date for status="fixed" rows.
    Both timestamps already exist on the model — no schema change needed.
    """
    rows = session.exec(
        select(SecurityFinding).where(
            SecurityFinding.tenant_id == tenant_id,
            SecurityFinding.status == "fixed",
            SecurityFinding.closing_date.is_not(None),
        )
    ).all()
    buckets: Dict[str, List[float]] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in rows:
        days = (r.closing_date - r.first_found).total_seconds() / 86400.0
        if days >= 0:
            buckets.setdefault(r.severity, []).append(days)
    mttr = {}
    for sev, vals in buckets.items():
        mttr[sev] = round(sum(vals) / len(vals), 1) if vals else None
    mttr["sample_size"] = sum(len(v) for v in buckets.values())
    return mttr


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
    tenant = session.get(Tenant, user.tenant_id) if user.tenant_id else None

    if not target_map:
        return templates.TemplateResponse("security_findings.html", {
            "request": request, "user": user,
            "target_findings": [], "summary": {"total": 0, "targets_with_findings": 0},
            "module_filter": module_filter, "severity_filter": severity_filter,
            "status_filter": status_filter, "finding_modules": FINDING_MODULES,
        })

    target_ids = tuple(target_map.keys())
    latest = _fetch_latest_results(session, target_ids)

    # Collect all raw findings first (for bulk upsert)
    raw_findings: List[Dict] = []
    for tid, target in target_map.items():
        for module in FINDING_MODULES:
            result = latest.get((tid, module))
            if result and result.data:
                for f in _extract_findings(module, result.data):
                    fhash = _finding_hash(target.domain, module, f["issue"])
                    raw_findings.append({
                        **f, "module": module, "finding_hash": fhash,
                        "domain": target.domain, "target_id": tid,
                        "scanned_at": result.scanned_at.isoformat() if result.scanned_at else "",
                    })

    # Upsert all findings → creates YF-IDs + due_dates, updates last_seen
    sf_map = _upsert_findings(session, raw_findings, user.tenant_id, tenant)

    # Build display structure with filters applied
    target_findings = []
    for tid, target in sorted(target_map.items(), key=lambda x: x[1].domain):
        all_findings = []
        modules_scanned: Dict[str, Dict] = {}

        for rf in raw_findings:
            if rf["target_id"] != tid:
                continue
            if module_filter and rf["module"] != module_filter:
                continue
            if severity_filter and rf.get("severity") != severity_filter:
                continue

            sf = sf_map.get(rf["finding_hash"])
            if not sf:
                continue

            now_utc = datetime.now(timezone.utc)
            sf_snoozed_until = sf.snoozed_until.replace(tzinfo=timezone.utc) if sf.snoozed_until and sf.snoozed_until.tzinfo is None else sf.snoozed_until
            is_snoozed = bool(sf_snoozed_until and sf_snoozed_until > now_utc)

            # "snoozed" is a pseudo-status (orthogonal to sf.status): the
            # triage snooze/undo window (#29/#79), not one of the real
            # open/acknowledged/false_positive/fixed states.
            if status_filter == "snoozed":
                if not is_snoozed:
                    continue
            else:
                if status_filter and sf.status != status_filter:
                    continue
                if is_snoozed:
                    continue

            all_findings.append({
                **rf,
                "yf_id": sf.yf_id,
                "status": sf.status,
                "status_note": sf.status_note or "",
                "status_updated_at": sf.status_updated_at.isoformat() if sf.status_updated_at else "",
                "assigned_to": sf.assigned_to or "",
                "ticket_ref": sf.ticket_ref or "",
                "first_found": sf.first_found.strftime("%Y-%m-%d") if sf.first_found else "",
                "last_seen": sf.last_seen.strftime("%Y-%m-%d") if sf.last_seen else "",
                "due_date": sf.due_date.strftime("%Y-%m-%d") if sf.due_date else "",
                "due_overdue": sf.due_date and sf.due_date < date.today() and sf.status == "open",
                "reopened_count": sf.reopened_count,
                "snoozed_until": sf.snoozed_until.strftime("%Y-%m-%d") if is_snoozed else "",
                "nis2_marked_at": sf.nis2_marked_at.isoformat() if sf.nis2_marked_at else "",
                "nis2_deadline_24h": sf.nis2_deadline_24h.isoformat() if sf.nis2_deadline_24h else "",
                "nis2_deadline_72h": sf.nis2_deadline_72h.isoformat() if sf.nis2_deadline_72h else "",
            })
            mod = rf["module"]
            if mod not in modules_scanned:
                modules_scanned[mod] = {"module": mod, "scanned_at": rf["scanned_at"], "finding_count": 0}
            modules_scanned[mod]["finding_count"] += 1

        if all_findings or not (module_filter or severity_filter or status_filter):
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 99))
            target_findings.append({
                "target": target,
                "findings": all_findings,
                "modules_scanned": list(modules_scanned.values()),
                "highest_severity": all_findings[0]["severity"] if all_findings else None,
            })

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 99}
    target_findings.sort(key=lambda x: sev_order.get(x["highest_severity"], 99))

    summary = _build_summary(target_findings)
    summary["mttr"] = _compute_mttr(session, user.tenant_id)

    return templates.TemplateResponse("security_findings.html", {
        "request": request, "user": user,
        "target_findings": target_findings, "summary": summary,
        "module_filter": module_filter, "severity_filter": severity_filter,
        "status_filter": status_filter, "finding_modules": FINDING_MODULES,
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

    valid_statuses = {"open", "acknowledged", "false_positive", "fixed", "risk_acceptance"}
    from fastapi import HTTPException
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(valid_statuses)}")

    sf = _get_finding_for_user(session, finding_hash, user)

    now = datetime.now(timezone.utc)
    prev_status = sf.status

    # Track reopens: was closed, now re-opened
    if prev_status in ("fixed", "false_positive") and status == "open":
        sf.reopened_count += 1
        sf.closing_date = None

    # Set closing date when resolving
    if status in ("fixed", "false_positive") and prev_status not in ("fixed", "false_positive"):
        sf.closing_date = now

    sf.status = status
    sf.status_note = note
    sf.status_updated_at = now
    sf.status_updated_by = user.username

    # Optional fields from body
    if "assigned_to" in body:
        sf.assigned_to = body["assigned_to"] or None
    if "ticket_ref" in body:
        sf.ticket_ref = body["ticket_ref"] or None
    if "due_date" in body and body["due_date"]:
        try:
            sf.due_date = date.fromisoformat(body["due_date"])
        except ValueError:
            pass

    # Snooze/undo window (#29, #79): temporarily hide a finding from the
    # default view without changing its real triage status — e.g. "already
    # ticketed, remind me in a week" or "just re-opened by mistake, give me
    # a moment before it disappears again".
    if "snooze_days" in body:
        try:
            days = int(body["snooze_days"])
            sf.snoozed_until = now + timedelta(days=days) if days > 0 else None
        except (TypeError, ValueError):
            pass
    if body.get("unsnooze"):
        sf.snoozed_until = None

    session.add(sf)
    session.commit()

    return {"finding_hash": finding_hash, "yf_id": sf.yf_id, "status": status, "snoozed_until": sf.snoozed_until.isoformat() if sf.snoozed_until else None}


@router.post("/api/findings/{finding_hash}/nis2-report")
async def mark_nis2_reportable(
    finding_hash: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    """
    NIS2 incident-reporting timer (#58). Marking a finding as NIS2-reportable
    is a legal judgment call the user makes explicitly — this only starts the
    24h early-warning / 72h detailed-notification clock and prepares a
    draft with the mandatory fields, it does not decide reportability itself.
    """
    sf = _get_finding_for_user(session, finding_hash, user)

    now = datetime.now(timezone.utc)
    sf.nis2_marked_at = now
    sf.nis2_deadline_24h = now + timedelta(hours=24)
    sf.nis2_deadline_72h = now + timedelta(hours=72)
    sf.nis2_marked_by = user.username
    session.add(sf)
    session.commit()

    draft = {
        "yf_id": sf.yf_id,
        "domain": sf.domain,
        "module": sf.module,
        "issue": sf.issue,
        "severity": sf.severity,
        "first_found": sf.first_found.isoformat() if sf.first_found else None,
        "impact_assessment": "TODO: describe scope, affected systems, and business impact.",
        "cross_border_effect": "TODO: assess whether this incident affects users/systems in other EU member states.",
        "iocs": [],
        "mitre_tactic_id": sf.mitre_tactic_id,
        "mitre_technique_id": sf.mitre_technique_id,
        "deadline_24h": sf.nis2_deadline_24h.isoformat(),
        "deadline_72h": sf.nis2_deadline_72h.isoformat(),
    }
    return {"finding_hash": finding_hash, "nis2_marked_at": sf.nis2_marked_at.isoformat(), "draft": draft}


@router.post("/api/findings/{finding_hash}/nis2-unmark")
async def unmark_nis2_reportable(
    finding_hash: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    sf = _get_finding_for_user(session, finding_hash, user)
    sf.nis2_marked_at = None
    sf.nis2_deadline_24h = None
    sf.nis2_deadline_72h = None
    sf.nis2_marked_by = None
    session.add(sf)
    session.commit()
    return {"finding_hash": finding_hash, "unmarked": True}


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


def _get_findings_for_export(session: Session, user: User, severity: Optional[str], status: Optional[str], module: Optional[str]) -> List[Dict]:
    """Shared query for the SARIF/JSON exports (#46) — reads SecurityFinding
    directly rather than re-deriving from raw scan data, since it already
    has yf_id/domain/module/severity/status in one row."""
    query = select(SecurityFinding)
    if user.tenant_id:
        query = query.where(SecurityFinding.tenant_id == user.tenant_id)
    elif user.role != "admin":
        query = query.where(SecurityFinding.tenant_id == None)  # noqa: E711
    if severity:
        query = query.where(SecurityFinding.severity == severity)
    if status:
        query = query.where(SecurityFinding.status == status)
    if module:
        query = query.where(SecurityFinding.module == module)

    return [
        {
            "yf_id": sf.yf_id, "domain": sf.domain, "module": sf.module,
            "issue": sf.issue, "severity": sf.severity, "status": sf.status,
            "first_found": sf.first_found.isoformat() if sf.first_found else None,
            "last_seen": sf.last_seen.isoformat() if sf.last_seen else None,
            "mitre_tactic_id": sf.mitre_tactic_id, "mitre_technique_id": sf.mitre_technique_id,
        }
        for sf in session.exec(query).all()
    ]


@router.get("/api/findings/export-sarif")
async def export_findings_sarif(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    module: Optional[str] = None,
):
    """SARIF 2.1.0 export (#46) — feeds YADS findings into GitHub Code Scanning
    and other SARIF consumers."""
    from yads.utils.export import generate_sarif
    rows = _get_findings_for_export(session, user, severity, status, module)
    return generate_sarif(rows, "yads_findings")


@router.get("/api/findings/export-json")
async def export_findings_json(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    module: Optional[str] = None,
):
    """JSON export (#46)."""
    from yads.utils.export import generate_json
    rows = _get_findings_for_export(session, user, severity, status, module)
    return generate_json(rows, "yads_findings")
