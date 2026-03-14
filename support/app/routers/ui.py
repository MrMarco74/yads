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
from app.models import BugReport

router = APIRouter()

_templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(_templates_dir))

VALID_STATUSES = ["new", "open", "resolved"]


# ---------------------------------------------------------------------------
# LLM prompt builder
# ---------------------------------------------------------------------------

def build_llm_prompt(report: BugReport, report_data: dict) -> str:
    return f"""Du bist YADS-Entwickler. Analysiere diesen Bug Report und schlage eine konkrete Lösung vor.

=== BUG REPORT {report.report_id} ===
Kunde    : {report.customer_name}
Tenant   : {report.tenant_name}
Version  : {report.yads_version}
Datum    : {report.submitted_at.strftime('%Y-%m-%d %H:%M UTC')}
Browser  : {report_data.get('browser', 'unbekannt')}
URL      : {report_data.get('affected_url', 'nicht angegeben')}

--- Fehlerbeschreibung ---
{report_data.get('description', '(leer)')}

--- Letzte Scan-Fehler (automatisch) ---
{chr(10).join(str(e) for e in report_data.get('scan_errors', [])) or '(keine)'}

--- Aktive System-Alerts (automatisch) ---
{chr(10).join(str(a) for a in report_data.get('system_alerts', [])) or '(keine)'}
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

    new_count = sum(1 for r in all_reports if r.status == "new")
    open_count = sum(1 for r in all_reports if r.status == "open")
    total_count = len(all_reports)
    last_10 = all_reports[:10]

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "new_count": new_count,
            "open_count": open_count,
            "total_count": total_count,
            "last_10": last_10,
        },
    )


@router.get("/reports", response_class=HTMLResponse)
async def report_list(
    request: Request,
    customer: Optional[str] = None,
    status: Optional[str] = None,
    session: Session = Depends(get_session),
):
    """List all reports with optional customer / status filters."""
    query = select(BugReport).order_by(col(BugReport.submitted_at).desc())
    reports = session.exec(query).all()

    # Collect distinct customer names before filtering
    all_customers = sorted({r.customer_name for r in reports})

    # Apply filters in-memory (small dataset expected)
    if customer:
        reports = [r for r in reports if r.customer_name == customer]
    if status and status in VALID_STATUSES:
        reports = [r for r in reports if r.status == status]

    return templates.TemplateResponse(
        "report_list.html",
        {
            "request": request,
            "reports": reports,
            "all_customers": all_customers,
            "selected_customer": customer or "",
            "selected_status": status or "",
            "valid_statuses": VALID_STATUSES,
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

    llm_prompt = build_llm_prompt(report, report_data)

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
