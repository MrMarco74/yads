"""
Web UI routes for the YADS Support Portal.

Protected by nginx auth_basic externally; no app-level auth required.
"""

import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, col, select

from app.database import get_session
from app.models import BugReport, BugReportMessage, ContactRequest, CustomerKey, InstallationReport, ReportCategory

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

    return templates.TemplateResponse("installations.html", {
        "request": request,
        "total": len(rows),
        "version_distribution": [
            {"version": k, "count": v}
            for k, v in sorted(version_dist.items(), key=lambda x: -x[1])
        ],
        "type_distribution": type_dist,
        "installations": [
            {
                "instance_uuid": r.instance_uuid,
                "version": r.version,
                "install_type": r.install_type,
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
                "report_count": r.report_count,
            }
            for r in rows
        ],
    })
