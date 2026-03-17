"""
Web UI routes for the YADS Support Portal.

Protected by SessionAuthMiddleware in main.py (session cookie = ADMIN_TOKEN).
"""

import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, col, select

from app.auth import COOKIE_NAME, make_session_token, verify_session_token
from app.database import get_session
from app.models import ActivationRequest, BugReport, BugReportMessage, ContactRequest, CustomerKey, InstallationReport, ReportCategory
import app.routers.installations as _inst_mod

router = APIRouter()

_templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(_templates_dir))

VALID_STATUSES = ["new", "open", "resolved"]
VALID_CONTACT_STATUSES = ["offen", "in_arbeit", "potenzial", "kunde", "spam"]


# ---------------------------------------------------------------------------
# LLM prompt builder
# ---------------------------------------------------------------------------

def _format_scan_errors(errors: list) -> str:
    if not errors:
        return "(keine)"
    lines = []
    for e in errors:
        if isinstance(e, dict):
            domain = e.get("domain", "?")
            msgs = [m for m in e.get("errors", []) if m and m.strip()]
            count = e.get("count", len(msgs))
            if msgs:
                lines.append(f"  [{domain}] {msgs[0]}" + (f" (+{count-1} weitere)" if count > 1 else ""))
            else:
                lines.append(f"  [{domain}] {count} Fehler")
        else:
            lines.append(f"  {e}")
    return "\n".join(lines) or "(keine)"


def _format_system_alerts(alerts: list) -> str:
    if not alerts:
        return "(keine)"
    lines = []
    for a in alerts:
        if isinstance(a, dict):
            severity = a.get("severity", "?").upper()
            check = a.get("check_name", "?")
            msg = a.get("message", "?")
            lines.append(f"  [{severity}] {check}: {msg}")
        else:
            lines.append(f"  {a}")
    return "\n".join(lines) or "(keine)"


def build_llm_prompt(report: BugReport, report_data: dict) -> str:
    topic_line = f"\nThema    : {report.topic}" if report.topic else ""
    return f"""Du bist YADS-Entwickler. Analysiere diesen Bug Report und schlage eine konkrete Lösung vor.

=== BUG REPORT {report.report_id} ==={topic_line}
Kunde    : {report.customer_name}
Tenant   : {report.tenant_name}
Version  : {report.yads_version}
Datum    : {report.submitted_at.strftime('%Y-%m-%d %H:%M UTC')}
Browser  : {report_data.get('browser', 'unbekannt')}
URL      : {report_data.get('affected_url', 'nicht angegeben')}

--- Fehlerbeschreibung ---
{report_data.get('description', '(leer)')}

--- Letzte Scan-Fehler (automatisch) ---
{_format_scan_errors(report_data.get('scan_errors', []))}

--- Aktive System-Alerts (automatisch) ---
{_format_system_alerts(report_data.get('system_alerts', []))}
=== ENDE REPORT ===

Frage: Was ist die wahrscheinliche Ursache und wie behebe ich den Fehler?"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: Session = Depends(get_session)):
    """Dashboard with KPI cards and last 10 reports."""
    all_reports = session.exec(
        select(BugReport).order_by(col(BugReport.submitted_at).desc())
    ).all()

    new_count   = sum(1 for r in all_reports if r.status == "new")
    open_count  = sum(1 for r in all_reports if r.status == "open")
    total_count = len(all_reports)
    last_10     = all_reports[:10]

    new_contacts = session.exec(
        select(ContactRequest).where(ContactRequest.status == "offen")
        .order_by(col(ContactRequest.submitted_at).desc())
    ).all()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request":       request,
            "new_count":     new_count,
            "open_count":    open_count,
            "total_count":   total_count,
            "last_10":       last_10,
            "new_contacts":  new_contacts,
        },
    )


def _eos_customer_ids(session) -> set:
    """Return the set of customer_ids that are marked EOS."""
    return {
        ck.customer_id
        for ck in session.exec(select(CustomerKey).where(CustomerKey.is_eos == True)).all()
    }


@router.get("/reports", response_class=HTMLResponse)
async def report_list(
    request: Request,
    customer: Optional[str] = None,
    status: Optional[str] = None,
    topic: Optional[str] = None,
    session: Session = Depends(get_session),
):
    """List all reports with optional customer / status / topic filters."""
    query = select(BugReport).order_by(col(BugReport.submitted_at).desc())
    reports = session.exec(query).all()

    eos_ids = _eos_customer_ids(session)

    # Collect distinct customer names and topics before filtering
    all_customers = sorted({r.customer_name for r in reports})
    all_topics = sorted({r.topic for r in reports if r.topic})
    all_categories = session.exec(select(ReportCategory).order_by(ReportCategory.name)).all()
    categories_by_id = {c.id: c for c in all_categories}

    selected_category = request.query_params.get("category", "")

    # Apply filters in-memory (small dataset expected)
    if customer:
        reports = [r for r in reports if r.customer_name == customer]
    if status and status in VALID_STATUSES:
        reports = [r for r in reports if r.status == status]
    if topic:
        reports = [r for r in reports if r.topic == topic]
    if selected_category:
        try:
            cat_id = int(selected_category)
            reports = [r for r in reports if r.category_id == cat_id]
        except ValueError:
            pass

    # Build grouped view (only when no active filter)
    show_grouped = not any([customer, status, topic, selected_category])
    grouped_reports: list = []
    if show_grouped:
        from collections import defaultdict
        cat_map: dict = defaultdict(list)
        for r in reports:
            cat_map[r.category_id].append(r)
        for cat in all_categories:
            if cat.id in cat_map:
                grouped_reports.append((cat, cat_map[cat.id]))
        if cat_map.get(None):
            grouped_reports.append((None, cat_map[None]))

    # Unread customer messages (not yet read by support)
    unread_msgs = session.exec(
        select(BugReportMessage).where(
            BugReportMessage.sender == "customer",
            BugReportMessage.is_read_by_support == False,
        )
    ).all()
    unread_counts: dict[str, int] = {}
    for m in unread_msgs:
        unread_counts[m.report_id] = unread_counts.get(m.report_id, 0) + 1

    return templates.TemplateResponse(
        "report_list.html",
        {
            "request": request,
            "reports": reports,
            "eos_ids": eos_ids,
            "unread_counts": unread_counts,
            "all_customers": all_customers,
            "all_topics": all_topics,
            "selected_customer": customer or "",
            "selected_status": status or "",
            "selected_topic": topic or "",
            "selected_category": selected_category,
            "all_categories": all_categories,
            "categories_by_id": categories_by_id,
            "valid_statuses": VALID_STATUSES,
            "show_grouped": show_grouped,
            "grouped_reports": grouped_reports,
        },
    )


@router.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_detail(
    request: Request,
    report_id: str,
    session: Session = Depends(get_session),
):
    """Detail view for a single bug report."""
    report = session.exec(
        select(BugReport).where(BugReport.report_id == report_id)
    ).first()
    if not report:
        return HTMLResponse(content="<h1>Report not found</h1>", status_code=404)

    try:
        report_data = json.loads(report.full_report)
    except Exception:
        report_data = {}

    eos_customer = session.exec(
        select(CustomerKey).where(
            CustomerKey.customer_id == report.customer_id,
            CustomerKey.is_eos == True,
        )
    ).first()

    messages = session.exec(
        select(BugReportMessage)
        .where(BugReportMessage.report_id == report_id)
        .order_by(col(BugReportMessage.created_at).asc())
    ).all()

    # Mark customer messages as read when admin opens the detail view
    for m in messages:
        if m.sender == "customer" and not m.is_read_by_support:
            m.is_read_by_support = True
            session.add(m)
    session.commit()

    llm_prompt = build_llm_prompt(report, report_data)
    all_categories = session.exec(select(ReportCategory).order_by(ReportCategory.name)).all()
    current_category = session.get(ReportCategory, report.category_id) if report.category_id else None

    return templates.TemplateResponse(
        "report_detail.html",
        {
            "request": request,
            "report": report,
            "report_data": report_data,
            "llm_prompt": llm_prompt,
            "valid_statuses": VALID_STATUSES,
            "scan_errors": report_data.get("scan_errors", []),
            "system_alerts": report_data.get("system_alerts", []),
            "eos_customer": eos_customer,
            "messages": messages,
            "all_categories": all_categories,
            "current_category": current_category,
        },
    )


@router.post("/reports/{report_id}/status")
async def update_status(
    report_id: str,
    status: str = Form(...),
    session: Session = Depends(get_session),
):
    """Update report status and redirect back to detail view."""
    report = session.exec(
        select(BugReport).where(BugReport.report_id == report_id)
    ).first()
    if not report:
        return HTMLResponse(content="<h1>Report not found</h1>", status_code=404)

    if status in VALID_STATUSES:
        report.status = status
        session.add(report)
        session.commit()

    return RedirectResponse(url=f"/reports/{report_id}", status_code=303)


@router.post("/reports/{report_id}/reply")
async def send_reply(
    report_id: str,
    text: str = Form(""),
    author_name: str = Form("Support"),
    session: Session = Depends(get_session),
):
    """Dashboard form: support team sends a reply to a customer report."""
    from app.models import BugReportMessage

    text = text.strip()[:4000]
    if text:
        report = session.exec(
            select(BugReport).where(BugReport.report_id == report_id)
        ).first()
        if report:
            msg = BugReportMessage(
                report_id=report_id,
                sender="support",
                author_name=author_name.strip()[:80] or "Support",
                text=text,
                is_read_by_support=True,
                is_read_by_customer=False,
            )
            session.add(msg)
            if report.status == "new":
                report.status = "open"
                session.add(report)
            session.commit()

    return RedirectResponse(url=f"/reports/{report_id}", status_code=303)


@router.get("/contacts", response_class=HTMLResponse)
async def contact_list(
    request: Request,
    status: Optional[str] = None,
    topic: Optional[str] = None,
    session: Session = Depends(get_session),
):
    """List all contact form submissions."""
    contacts = session.exec(
        select(ContactRequest).order_by(col(ContactRequest.submitted_at).desc())
    ).all()

    all_topics = sorted({c.topic for c in contacts if c.topic})

    if status and status in VALID_CONTACT_STATUSES:
        contacts = [c for c in contacts if c.status == status]
    if topic:
        contacts = [c for c in contacts if c.topic == topic]

    return templates.TemplateResponse("contact_list.html", {
        "request":          request,
        "contacts":         contacts,
        "all_topics":       all_topics,
        "selected_status":  status or "",
        "selected_topic":   topic or "",
        "valid_statuses":   VALID_CONTACT_STATUSES,
    })


@router.post("/contacts/{contact_id}/status")
async def update_contact_status(
    contact_id: str,
    status: str = Form(...),
    session: Session = Depends(get_session),
):
    contact = session.exec(
        select(ContactRequest).where(ContactRequest.contact_id == contact_id)
    ).first()
    if contact and status in VALID_CONTACT_STATUSES:
        contact.status = status
        session.add(contact)
        session.commit()
    return RedirectResponse(url="/contacts", status_code=303)


@router.post("/contacts/{contact_id}/notes")
async def update_contact_notes(
    contact_id: str,
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    contact = session.exec(
        select(ContactRequest).where(ContactRequest.contact_id == contact_id)
    ).first()
    if contact:
        contact.notes = notes[:4000].strip()
        session.add(contact)
        session.commit()
    return RedirectResponse(url="/contacts", status_code=303)


@router.post("/contacts/{contact_id}/convert")
async def convert_contact_to_report(
    contact_id: str,
    session: Session = Depends(get_session),
):
    """Convert a contact request into a bug report so it appears in the Reports view."""
    import json as _json
    from datetime import datetime, timezone

    contact = session.exec(
        select(ContactRequest).where(ContactRequest.contact_id == contact_id)
    ).first()
    if not contact:
        return HTMLResponse(content="<h1>Contact not found</h1>", status_code=404)

    # Build a synthetic report_id: YAD-CON-XXXXX derived from contact_id
    derived_id = "YAD-" + contact.contact_id  # e.g. YAD-CON-2026-00001

    # Check if already converted
    existing = session.exec(
        select(BugReport).where(BugReport.report_id == derived_id)
    ).first()
    if existing:
        return RedirectResponse(url=f"/reports/{derived_id}", status_code=303)

    full_report_data = {
        "source":        "contact_form",
        "contact_id":    contact.contact_id,
        "topic":         contact.topic,
        "description":   contact.message,
        "browser":       "N/A",
        "affected_url":  "N/A",
        "scan_errors":   [],
        "system_alerts": [],
    }

    report = BugReport(
        report_id=derived_id,
        customer_id=contact.email,
        customer_name=contact.name + (f" ({contact.company})" if contact.company else ""),
        tenant_name=contact.company or "Homepage Contact",
        yads_version="N/A",
        topic=contact.topic,
        description=contact.message[:300],
        full_report=_json.dumps(full_report_data),
        submitted_at=contact.submitted_at,
        status="new",
    )
    session.add(report)
    # Mark contact as in_arbeit
    contact.status = "in_arbeit"
    session.add(contact)
    session.commit()

    return RedirectResponse(url=f"/reports/{derived_id}", status_code=303)


@router.get("/installations", response_class=HTMLResponse)
async def installations_page(
    request: Request,
    session: Session = Depends(get_session),
):
    """Admin installations overview page."""
    rows = session.exec(
        select(InstallationReport).order_by(col(InstallationReport.last_seen).desc())
    ).all()

    version_dist: dict = {}
    for r in rows:
        version_dist[r.version] = version_dist.get(r.version, 0) + 1

    type_dist: dict = {}
    for r in rows:
        type_dist[r.install_type] = type_dist.get(r.install_type, 0) + 1

    # customer_id → customer_name lookup
    from app.models import CustomerKey
    cust_ids = {r.customer_id for r in rows if r.customer_id}
    cust_map: dict = {}
    for cid in cust_ids:
        ck = session.get(CustomerKey, cid)
        if ck:
            cust_map[cid] = ck.customer_name

    # Group by customer_id for the per-customer summary table
    cust_groups: dict = {}
    for r in rows:
        if not r.customer_id:
            continue
        entry = cust_groups.setdefault(r.customer_id, {
            "customer_id": r.customer_id,
            "name": cust_map.get(r.customer_id) or r.customer_id,
            "count": 0,
            "versions": [],
        })
        entry["count"] += 1
        if r.version not in entry["versions"]:
            entry["versions"].append(r.version)
    by_customer = sorted(cust_groups.values(), key=lambda x: -x["count"])

    return templates.TemplateResponse("installations.html", {
        "request": request,
        "total": len(rows),
        "version_distribution": [
            {"version": k, "count": v}
            for k, v in sorted(version_dist.items(), key=lambda x: -x[1])
        ],
        "type_distribution": type_dist,
        "by_customer": by_customer,
        "installations": [
            {
                "instance_uuid": r.instance_uuid,
                "version": r.version,
                "install_type": r.install_type,
                "customer_id": r.customer_id,
                "customer_name": cust_map.get(r.customer_id) if r.customer_id else None,
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
                "report_count": r.report_count,
            }
            for r in rows
        ],
    })


@router.get("/activations", response_class=HTMLResponse)
async def activations_page(
    request: Request,
    session: Session = Depends(get_session),
):
    """Admin activation requests overview page."""
    ar_rows = session.exec(
        select(ActivationRequest).order_by(col(ActivationRequest.received_at).desc())
    ).all()

    # customer_id → customer_name lookup
    cust_ids = {r.customer_id for r in ar_rows if r.customer_id}
    cust_map: dict = {}
    for cid in cust_ids:
        ck = session.get(CustomerKey, cid)
        if ck:
            cust_map[cid] = ck.customer_name

    requests_data = [
        {
            "id": r.id,
            "instance_uuid": r.instance_uuid,
            "customer_id": r.customer_id,
            "customer_name": cust_map.get(r.customer_id) if r.customer_id else None,
            "status": r.status,
            "request_code": r.request_code or "",
            "response_code": r.response_code or "",
            "received_at": r.received_at.isoformat(),
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
        }
        for r in ar_rows
    ]

    return templates.TemplateResponse("activations.html", {
        "request": request,
        "requests": requests_data,
    })


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = "", next: str = "/"):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "next": next,
    })


@router.post("/login")
async def do_login(
    request: Request,
    password: str = Form(...),
    next: str = Form("/"),
):
    import app.auth as _auth
    if password and password == _inst_mod.ADMIN_TOKEN:
        token = make_session_token()
        response = RedirectResponse(next or "/", status_code=303)
        response.set_cookie(
            COOKIE_NAME, token,
            httponly=True, secure=True, samesite="lax",
            max_age=8 * 3600,
        )
        return response
    return RedirectResponse(f"/login?error=1&next={next}", status_code=303)


@router.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME)
    return response


# ---------------------------------------------------------------------------
# Server-side proxy for activation admin actions
# (replaces client-side JS calls that required the ADMIN_TOKEN in the HTML)
# ---------------------------------------------------------------------------

from datetime import datetime, timezone as _tz


@router.post("/ui/activate-offline")
async def ui_activate_offline(
    request: Request,
    session: Session = Depends(get_session),
):
    import base64 as _b64, json as _json
    body = await request.json()
    code = (body.get("code") or "").strip()
    if not code:
        return JSONResponse({"detail": "code required"}, status_code=400)

    try:
        padded = code + "=" * ((4 - len(code) % 4) % 4)
        payload = _json.loads(_b64.urlsafe_b64decode(padded))
    except Exception as exc:
        return JSONResponse({"detail": f"Invalid activation code: {exc}"}, status_code=400)

    required = {"instance_uuid", "version"}
    if not required.issubset(payload.keys()):
        return JSONResponse({"detail": "Missing required fields."}, status_code=400)

    install_type = (payload.get("install_type") or "installer").strip()
    customer_id = (payload.get("customer_id") or "").strip() or None
    now = datetime.now(_tz.utc)

    from app.models import InstallationReport
    existing = session.exec(
        select(InstallationReport).where(
            InstallationReport.instance_uuid == payload["instance_uuid"]
        )
    ).first()
    if existing:
        existing.version = payload["version"]
        existing.last_seen = now
        existing.report_count += 1
        if existing.install_type == "unknown" and install_type != "unknown":
            existing.install_type = install_type
        if not existing.customer_id and customer_id:
            existing.customer_id = customer_id
        session.add(existing)
    else:
        session.add(InstallationReport(
            instance_uuid=payload["instance_uuid"],
            version=payload["version"],
            install_type=install_type,
            customer_id=customer_id,
        ))
    session.commit()

    existing_ar = session.exec(
        select(ActivationRequest).where(
            ActivationRequest.instance_uuid == payload["instance_uuid"]
        )
    ).first()
    if not existing_ar:
        session.add(ActivationRequest(
            instance_uuid=payload["instance_uuid"],
            customer_id=customer_id,
            request_code=code,
            status="approved",
            resolved_at=now,
        ))
        session.commit()

    return JSONResponse({"ok": True, "instance_uuid": payload["instance_uuid"]})


@router.post("/ui/activations/{instance_uuid}/respond")
async def ui_respond_activation(
    instance_uuid: str,
    request: Request,
    session: Session = Depends(get_session),
):
    body = await request.json()
    response_code = (body.get("response_code") or "").strip()
    if not response_code:
        return JSONResponse({"detail": "response_code required"}, status_code=400)

    ar = session.exec(
        select(ActivationRequest).where(ActivationRequest.instance_uuid == instance_uuid)
    ).first()
    if not ar:
        return JSONResponse({"detail": "Not found."}, status_code=404)

    ar.response_code = response_code
    ar.status = "approved"
    ar.resolved_at = datetime.now(_tz.utc)
    session.add(ar)
    session.commit()
    return JSONResponse({"ok": True})


@router.post("/ui/activations/{instance_uuid}/revoke")
async def ui_revoke_activation(
    instance_uuid: str,
    session: Session = Depends(get_session),
):
    ar = session.exec(
        select(ActivationRequest).where(ActivationRequest.instance_uuid == instance_uuid)
    ).first()
    if not ar:
        return JSONResponse({"detail": "Not found."}, status_code=404)

    ar.status = "rejected"
    ar.response_code = None
    ar.resolved_at = datetime.now(_tz.utc)
    session.add(ar)
    session.commit()
    return JSONResponse({"ok": True})


@router.delete("/ui/activations/{instance_uuid}")
async def ui_delete_activation(
    instance_uuid: str,
    session: Session = Depends(get_session),
):
    ar = session.exec(
        select(ActivationRequest).where(ActivationRequest.instance_uuid == instance_uuid)
    ).first()
    if not ar:
        return JSONResponse({"detail": "Not found."}, status_code=404)

    session.delete(ar)
    session.commit()
    return JSONResponse({"ok": True})
