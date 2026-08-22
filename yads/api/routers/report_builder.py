"""
Report Builder Router

Provides endpoints for managing report templates, generating reports from markdown,
and exporting to PDF with tenant-specific branding.
"""

from fastapi import APIRouter, Depends, Request, Form, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from sqlmodel import Session, select, or_
from datetime import datetime
from typing import Optional, List
import json
import base64
import logging

from yads.database import get_session
from yads.models import (
    User, Tenant, Target, ScanResult, ReportTemplate, GeneratedReport
)
from yads.auth.deps import get_current_user_html, RoleChecker
from yads.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/reports",
    tags=["reports"]
)

from yads.api.templating import templates

# Helper to get all tenants for template context
def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

# Role checker for report access - tenant_admin and above
report_access = RoleChecker(["admin", "tenant_admin", "scanner"])


# ============================================================================
# Template Management
# ============================================================================

@router.get("/templates", response_class=HTMLResponse)
async def list_templates(
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """List all available report templates (tenant + system)."""
    # Get system templates (tenant_id is NULL, is_public=True)
    system_templates = session.exec(
        select(ReportTemplate)
        .where(ReportTemplate.tenant_id == None)
        .where(ReportTemplate.is_public == True)
        .order_by(ReportTemplate.category, ReportTemplate.name)
    ).all()

    # Get tenant templates
    tenant_templates = []
    if user.tenant_id:
        tenant_templates = session.exec(
            select(ReportTemplate)
            .where(ReportTemplate.tenant_id == user.tenant_id)
            .order_by(ReportTemplate.category, ReportTemplate.name)
        ).all()

    return templates.TemplateResponse("report_templates.html", {
        "request": request,
        "user": user,
        "system_templates": system_templates,
        "tenant_templates": tenant_templates,
        "settings": settings
    })


@router.get("/templates/new", response_class=HTMLResponse)
async def new_template_form(
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Show form to create a new report template."""
    return templates.TemplateResponse("report_template_edit.html", {
        "request": request,
        "user": user,
        "template": None,
        "is_new": True,
        "available_sections": get_available_sections(),
        "settings": settings
    })


@router.post("/templates", dependencies=[Depends(report_access)])
async def create_template(
    request: Request,
    name: str = Form(..., max_length=200),
    description: str = Form(None, max_length=500),
    category: str = Form("custom", max_length=50),
    markdown_content: str = Form(..., max_length=200000),
    available_sections: str = Form("[]"),
    custom_css: str = Form(None, max_length=50000),
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Create a new report template."""
    try:
        sections = json.loads(available_sections) if available_sections else []
    except json.JSONDecodeError:
        sections = []

    template = ReportTemplate(
        tenant_id=user.tenant_id,
        name=name,
        description=description,
        category=category,
        markdown_content=markdown_content,
        available_sections=sections,
        custom_css=custom_css if custom_css else None,
        created_by=user.id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

    session.add(template)
    session.commit()
    session.refresh(template)

    logger.info(f"User {user.username} created report template '{name}' (ID: {template.id})")

    if request.headers.get("HX-Request"):
        return HTMLResponse(
            f'<div class="text-emerald-400">Template created successfully!</div>',
            headers={"HX-Redirect": f"/reports/templates/{template.id}"}
        )

    return RedirectResponse(url=f"/reports/templates/{template.id}", status_code=303)


@router.get("/templates/{template_id}", response_class=HTMLResponse)
async def view_template(
    template_id: int,
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """View/edit a report template."""
    template = session.get(ReportTemplate, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Check access: system templates are viewable, tenant templates only by tenant
    if template.tenant_id and template.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    # Check if user can edit (only tenant templates can be edited by tenant users)
    can_edit = (template.tenant_id == user.tenant_id) or (user.role == "admin")

    return templates.TemplateResponse("report_template_edit.html", {
        "request": request,
        "user": user,
        "template": template,
        "is_new": False,
        "can_edit": can_edit,
        "available_sections": get_available_sections(),
        "settings": settings
    })


@router.put("/templates/{template_id}", dependencies=[Depends(report_access)])
@router.post("/templates/{template_id}/update", dependencies=[Depends(report_access)])
async def update_template(
    template_id: int,
    request: Request,
    name: str = Form(..., max_length=200),
    description: str = Form(None, max_length=500),
    category: str = Form("custom", max_length=50),
    markdown_content: str = Form(..., max_length=200000),
    available_sections: str = Form("[]"),
    custom_css: str = Form(None, max_length=50000),
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Update an existing report template."""
    template = session.get(ReportTemplate, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Only tenant owner or admin can edit
    if template.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        sections = json.loads(available_sections) if available_sections else []
    except json.JSONDecodeError:
        sections = []

    template.name = name
    template.description = description
    template.category = category
    template.markdown_content = markdown_content
    template.available_sections = sections
    template.custom_css = custom_css if custom_css else None
    template.updated_at = datetime.utcnow()

    session.add(template)
    session.commit()

    logger.info(f"User {user.username} updated report template '{name}' (ID: {template_id})")

    if request.headers.get("HX-Request"):
        return HTMLResponse('<div class="text-emerald-400">Template saved!</div>')

    return RedirectResponse(url=f"/reports/templates/{template_id}", status_code=303)


@router.delete("/templates/{template_id}", dependencies=[Depends(report_access)])
@router.post("/templates/{template_id}/delete", dependencies=[Depends(report_access)])
async def delete_template(
    template_id: int,
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Delete a report template."""
    template = session.get(ReportTemplate, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Only tenant owner or admin can delete
    if template.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    # Don't allow deleting system default templates
    if template.is_default:
        raise HTTPException(status_code=403, detail="Cannot delete system default templates")

    session.delete(template)
    session.commit()

    logger.info(f"User {user.username} deleted report template (ID: {template_id})")

    if request.headers.get("HX-Request"):
        return HTMLResponse("", headers={"HX-Redirect": "/reports/templates"})

    return RedirectResponse(url="/reports/templates", status_code=303)


# ============================================================================
# Report Builder (Main Interface)
# ============================================================================

@router.get("/builder", response_class=HTMLResponse)
async def report_builder(
    request: Request,
    template_id: Optional[int] = None,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Main report builder interface with WYSIWYG editor."""
    # Get available templates
    available_templates = session.exec(
        select(ReportTemplate)
        .where(
            or_(
                ReportTemplate.tenant_id == user.tenant_id,
                ReportTemplate.is_public == True
            )
        )
        .order_by(ReportTemplate.category, ReportTemplate.name)
    ).all()

    # Get selected template if provided
    selected_template = None
    if template_id:
        selected_template = session.get(ReportTemplate, template_id)

    # Get tenant targets for data selection
    targets = []
    if user.tenant_id:
        targets = session.exec(
            select(Target)
            .where(Target.tenant_id == user.tenant_id)
            .where(Target.is_archived == False)
            .order_by(Target.domain)
        ).all()

    # Get tenant branding
    tenant = session.get(Tenant, user.tenant_id) if user.tenant_id else None

    return templates.TemplateResponse("report_builder.html", {
        "request": request,
        "user": user,
        "templates": available_templates,
        "selected_template": selected_template,
        "targets": targets,
        "tenant": tenant,
        "available_sections": get_available_sections(),
        "settings": settings
    })


@router.post("/builder/preview", dependencies=[Depends(report_access)])
async def preview_report(
    request: Request,
    markdown_content: str = Form(...),
    target_ids: str = Form("[]"),
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Generate HTML preview of the markdown report with data."""
    from yads.core.markdown_report_generator import render_markdown_with_data

    try:
        target_id_list = json.loads(target_ids) if target_ids else []
    except json.JSONDecodeError:
        target_id_list = []

    # Get tenant branding
    tenant = session.get(Tenant, user.tenant_id) if user.tenant_id else None

    # Gather scan data for selected targets
    scan_data = gather_scan_data(session, target_id_list, user.tenant_id)

    # Render markdown with data
    html_content = render_markdown_with_data(
        markdown_content,
        scan_data,
        tenant
    )

    return HTMLResponse(html_content)


@router.post("/builder/check-variables", dependencies=[Depends(report_access)])
async def check_template_variables(
    request: Request,
    markdown_content: str = Form(...),
    user: User = Depends(get_current_user_html)
):
    """
    Check template variables against known valid variables.
    Returns JSON with valid, unknown, and filter lists.
    """
    import re

    # Get known variables from our reference
    known_vars = get_template_variables()

    # Build a set of all valid variable paths
    valid_paths = set()
    for category, vars_list in known_vars.items():
        for var_def in vars_list:
            # Extract the variable path from {{ var.path }} or {{ var.path|filter }}
            var_str = var_def.get("var", "")
            # Remove {{ }} and extract variable path
            match = re.search(r'\{\{\s*([^}|]+)', var_str)
            if match:
                path = match.group(1).strip()
                valid_paths.add(path)
                # Also add base path for nested access (e.g., dns.records allows dns.records.A)
                parts = path.split('.')
                for i in range(1, len(parts)):
                    valid_paths.add('.'.join(parts[:i]))

    # Add common loop variables
    valid_paths.update([
        't', 't.domain', 't.status', 't.security_score', 't.last_scan',
        't.dns', 't.ssl', 't.nuclei', 't.web', 't.nmap', 't.infrastructure',
        't.cloud', 't.crawler', 't.wayback', 't.typosquat', 't.tld', 't.content_discovery',
        't.osint', 't.seed_files', 't.csp',
        'f', 'f.name', 'f.severity', 'f.description', 'f.matched_at', 'f.cve_id',
        'p', 'p.port', 'p.protocol', 'p.state', 'p.service', 'p.version',
        'sub', 'record', 'tech', 'item', 'finding', 'port', 'page', 'link',
        'loop.index', 'loop.index0', 'loop.first', 'loop.last', 'loop.length'
    ])

    # Also add base objects
    valid_paths.update([
        'tenant', 'target', 'targets', 'summary', 'report', 'now',
        'dns', 'ssl', 'nuclei', 'web', 'nmap', 'infrastructure',
        'cloud', 'crawler', 'wayback', 'typosquat', 'tld', 'content_discovery',
        'osint', 'seed_files', 'csp'
    ])

    # Known Jinja2 filters
    known_filters = {
        'date', 'datetime', 'count', 'length', 'join', 'truncate', 'default',
        'upper', 'lower', 'title', 'capitalize', 'trim', 'striptags',
        'first', 'last', 'sort', 'reverse', 'unique', 'sum', 'min', 'max',
        'abs', 'round', 'int', 'float', 'string', 'list', 'dictsort',
        'safe', 'e', 'escape', 'forceescape', 'urlencode', 'tojson',
        'severity_badge', 'nl2br', 'batch', 'slice', 'groupby', 'map', 'select', 'reject',
        'selectattr', 'rejectattr', 'filesizeformat', 'pprint', 'indent', 'wordwrap',
        'center', 'format', 'replace', 'regex_replace', 'wordcount', 'xmlattr'
    }

    # Extract variables from template using regex
    # Match {{ variable }} or {{ variable|filter }}
    var_pattern = r'\{\{\s*([^}]+)\s*\}\}'
    found_vars = re.findall(var_pattern, markdown_content)

    valid_found = set()
    unknown_found = set()
    filters_found = set()

    for expr in found_vars:
        expr = expr.strip()

        # Extract filters
        if '|' in expr:
            parts = expr.split('|')
            var_part = parts[0].strip()
            for filter_part in parts[1:]:
                # Filter might have args like truncate(50)
                filter_name = filter_part.split('(')[0].strip()
                if filter_name in known_filters:
                    filters_found.add(filter_name)
        else:
            var_part = expr

        # Clean up variable part (remove any trailing whitespace or operators)
        var_part = var_part.strip()

        # Skip control structures like 'for x in y' or 'if condition'
        if any(keyword in var_part for keyword in [' for ', ' in ', ' if ', ' else ', ' endif', ' endfor']):
            continue

        # Check if it's a valid variable path
        # Allow nested access like dns.records.A
        base_var = var_part.split('.')[0].strip()
        if base_var in valid_paths or var_part in valid_paths:
            valid_found.add(var_part)
        else:
            # Check if it starts with a known base object
            is_valid = False
            for valid_base in ['tenant', 'target', 'targets', 'summary', 'report', 'dns', 'ssl',
                               'nuclei', 'web', 'nmap', 'infrastructure', 'cloud', 'crawler',
                               'wayback', 'typosquat', 'tld', 'content_discovery', 'osint',
                               'seed_files', 'csp', 't', 'f', 'p', 'now', 'loop']:
                if base_var == valid_base or var_part.startswith(valid_base + '.'):
                    valid_found.add(var_part)
                    is_valid = True
                    break
            if not is_valid:
                unknown_found.add(var_part)

    return {
        "valid": sorted(list(valid_found)),
        "unknown": sorted(list(unknown_found)),
        "filters": sorted(list(filters_found))
    }


@router.post("/generate", dependencies=[Depends(report_access)])
async def generate_report(
    request: Request,
    title: str = Form(...),
    description: str = Form(None),
    template_id: Optional[int] = Form(None),
    markdown_content: str = Form(...),
    target_ids: str = Form("[]"),
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Generate and save a new report."""
    from yads.core.markdown_report_generator import render_markdown_with_data, markdown_to_html

    try:
        target_id_list = json.loads(target_ids) if target_ids else []
    except json.JSONDecodeError:
        target_id_list = []

    # Get tenant
    tenant = session.get(Tenant, user.tenant_id) if user.tenant_id else None

    # Gather scan data
    scan_data = gather_scan_data(session, target_id_list, user.tenant_id)

    # Render markdown with data
    rendered_markdown = render_markdown_with_data(
        markdown_content,
        scan_data,
        tenant,
        return_markdown=True
    )

    # Convert to HTML
    html_content = markdown_to_html(rendered_markdown)

    # Capture branding snapshot
    branding_snapshot = {}
    if tenant:
        branding_snapshot = {
            "logo_url": tenant.report_logo_url,
            "company_name": tenant.report_company_name or tenant.name,
            "primary_color": tenant.report_primary_color,
            "secondary_color": tenant.report_secondary_color,
            "header_text": tenant.report_header_text,
            "footer_text": tenant.report_footer_text
        }

    # Create report record
    report = GeneratedReport(
        tenant_id=user.tenant_id,
        template_id=template_id,
        title=title,
        description=description,
        target_ids=target_id_list,
        markdown_content=rendered_markdown,
        html_content=html_content,
        status="completed",
        branding_snapshot=branding_snapshot,
        created_by=user.id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        generated_at=datetime.utcnow()
    )

    session.add(report)
    session.commit()
    session.refresh(report)

    logger.info(f"User {user.username} generated report '{title}' (ID: {report.id})")

    if request.headers.get("HX-Request"):
        return HTMLResponse(
            f'<div class="text-emerald-400">Report generated!</div>',
            headers={"HX-Redirect": f"/reports/{report.id}"}
        )

    return RedirectResponse(url=f"/reports/{report.id}", status_code=303)


@router.post("/save-draft", dependencies=[Depends(report_access)])
async def save_draft(
    request: Request,
    title: str = Form(...),
    description: str = Form(None),
    template_id: Optional[int] = Form(None),
    markdown_content: str = Form(...),
    target_ids: str = Form("[]"),
    report_id: Optional[int] = Form(None),
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Save report as draft (work in progress)."""
    try:
        target_id_list = json.loads(target_ids) if target_ids else []
    except json.JSONDecodeError:
        target_id_list = []

    # Get tenant
    tenant = session.get(Tenant, user.tenant_id) if user.tenant_id else None

    # Capture branding snapshot
    branding_snapshot = {}
    if tenant:
        branding_snapshot = {
            "logo_url": tenant.report_logo_url,
            "company_name": tenant.report_company_name or tenant.name,
            "primary_color": tenant.report_primary_color,
            "secondary_color": tenant.report_secondary_color,
            "header_text": tenant.report_header_text,
            "footer_text": tenant.report_footer_text
        }

    if report_id:
        # Update existing draft
        report = session.get(GeneratedReport, report_id)
        if not report or report.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Report not found")

        report.title = title
        report.description = description
        report.template_id = template_id if template_id else None
        report.markdown_content = markdown_content
        report.target_ids = target_id_list
        report.branding_snapshot = branding_snapshot
        report.updated_at = datetime.utcnow()
    else:
        # Create new draft
        report = GeneratedReport(
            tenant_id=user.tenant_id,
            template_id=template_id if template_id else None,
            title=title,
            description=description,
            target_ids=target_id_list,
            markdown_content=markdown_content,
            html_content=None,
            status="draft",
            branding_snapshot=branding_snapshot,
            created_by=user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        session.add(report)

    session.commit()
    session.refresh(report)

    logger.info(f"User {user.username} saved draft report '{title}' (ID: {report.id})")

    if request.headers.get("HX-Request"):
        return HTMLResponse(
            f'<div class="text-emerald-400">Draft saved!</div>',
            headers={"HX-Redirect": f"/reports/{report.id}/edit"}
        )

    return RedirectResponse(url=f"/reports/{report.id}/edit", status_code=303)


@router.post("/save-as-template", dependencies=[Depends(report_access)])
async def save_as_template(
    request: Request,
    name: str = Form(...),
    description: str = Form(None),
    category: str = Form("custom"),
    markdown_content: str = Form(...),
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Save current markdown content as a reusable template."""
    if not user.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant required")

    # Create new template
    template = ReportTemplate(
        tenant_id=user.tenant_id,
        name=name,
        description=description,
        category=category,
        markdown_content=markdown_content,
        available_sections=[],
        is_public=False,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

    session.add(template)
    session.commit()
    session.refresh(template)

    logger.info(f"User {user.username} saved report content as template '{name}' (ID: {template.id})")

    if request.headers.get("HX-Request"):
        return HTMLResponse(
            f'<div class="text-emerald-400">Template created!</div>',
            headers={"HX-Redirect": f"/reports/templates/{template.id}"}
        )

    return RedirectResponse(url=f"/reports/templates/{template.id}", status_code=303)


# ============================================================================
# Report Management
# ============================================================================

@router.get("/", response_class=HTMLResponse)
async def list_reports(
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """List all generated reports for the tenant."""
    reports = []
    if user.tenant_id:
        reports = session.exec(
            select(GeneratedReport)
            .where(GeneratedReport.tenant_id == user.tenant_id)
            .order_by(GeneratedReport.created_at.desc())
        ).all()

    # Enrich reports with template type information
    enriched_reports = []
    for report in reports:
        report_dict = {
            "report": report,
            "template_type": "ad-hoc",  # Default: no template
            "template_name": None
        }
        if report.template_id:
            template = session.get(ReportTemplate, report.template_id)
            if template:
                report_dict["template_name"] = template.name
                # System templates have tenant_id = NULL
                if template.tenant_id is None:
                    report_dict["template_type"] = "system"
                else:
                    report_dict["template_type"] = "custom"
        enriched_reports.append(report_dict)

    return templates.TemplateResponse("reports_list.html", {
        "request": request,
        "user": user,
        "reports": enriched_reports,
        "settings": settings
    })


@router.get("/{report_id}", response_class=HTMLResponse)
async def view_report(
    report_id: int,
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """View a generated report."""
    report = session.get(GeneratedReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Check access
    if report.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    return templates.TemplateResponse("report_view.html", {
        "request": request,
        "user": user,
        "report": report,
        "settings": settings
    })


@router.post("/{report_id}/review")
async def save_report_review_notes(
    report_id: int,
    review_notes: str = Form(""),
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session),
):
    """Internal reviewer annotations before send (#49) — never shown to the
    report's external recipient."""
    report = session.get(GeneratedReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    report.review_notes = review_notes or None
    report.reviewed_by = user.username
    report.reviewed_at = datetime.utcnow()
    session.add(report)
    session.commit()
    return RedirectResponse(url=f"/reports/{report_id}?msg=Review+notes+saved", status_code=303)


@router.get("/{report_id}/edit", response_class=HTMLResponse)
async def edit_report(
    report_id: int,
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Edit an existing report."""
    report = session.get(GeneratedReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Check access
    if report.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    # Get targets for the dropdown
    targets = []
    if user.tenant_id:
        targets = session.exec(
            select(Target)
            .where(Target.tenant_id == user.tenant_id)
            .where(Target.is_archived == False)
            .order_by(Target.domain)
        ).all()

    # Get templates
    available_templates = session.exec(
        select(ReportTemplate)
        .where(
            or_(
                ReportTemplate.tenant_id == user.tenant_id,
                ReportTemplate.is_public == True
            )
        )
        .order_by(ReportTemplate.category, ReportTemplate.name)
    ).all()

    tenant = session.get(Tenant, user.tenant_id) if user.tenant_id else None

    return templates.TemplateResponse("report_edit.html", {
        "request": request,
        "user": user,
        "report": report,
        "targets": targets,
        "templates": available_templates,
        "tenant": tenant,
        "available_sections": get_available_sections(),
        "settings": settings
    })


@router.post("/{report_id}/update", dependencies=[Depends(report_access)])
async def update_report(
    report_id: int,
    request: Request,
    title: str = Form(...),
    description: str = Form(None),
    markdown_content: str = Form(...),
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Update an existing report."""
    from yads.core.markdown_report_generator import markdown_to_html

    report = session.get(GeneratedReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Check access
    if report.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    report.title = title
    report.description = description
    report.markdown_content = markdown_content
    report.html_content = markdown_to_html(markdown_content)
    report.updated_at = datetime.utcnow()

    session.add(report)
    session.commit()

    logger.info(f"User {user.username} updated report '{title}' (ID: {report_id})")

    if request.headers.get("HX-Request"):
        return HTMLResponse('<div class="text-emerald-400">Report saved!</div>')

    return RedirectResponse(url=f"/reports/{report_id}", status_code=303)


@router.delete("/{report_id}", dependencies=[Depends(report_access)])
@router.post("/{report_id}/delete", dependencies=[Depends(report_access)])
async def delete_report(
    report_id: int,
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Delete a generated report."""
    report = session.get(GeneratedReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Check access
    if report.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    session.delete(report)
    session.commit()

    logger.info(f"User {user.username} deleted report (ID: {report_id})")

    if request.headers.get("HX-Request"):
        return HTMLResponse("", headers={"HX-Redirect": "/reports"})

    return RedirectResponse(url="/reports", status_code=303)


# ============================================================================
# PDF Export
# ============================================================================

@router.get("/{report_id}/export/pdf")
@router.post("/{report_id}/export/pdf", dependencies=[Depends(report_access)])
async def export_report_pdf(
    report_id: int,
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Export a report to PDF."""
    from yads.core.markdown_report_generator import generate_pdf_from_html

    report = session.get(GeneratedReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Check access
    if report.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    # Use cached PDF if available
    if report.pdf_data:
        pdf_bytes = base64.b64decode(report.pdf_data)
    else:
        # Generate PDF
        pdf_bytes = generate_pdf_from_html(
            report.html_content,
            report.branding_snapshot,
            report.title
        )

        # Cache the PDF
        report.pdf_data = base64.b64encode(pdf_bytes).decode('utf-8')
        session.add(report)
        session.commit()

    # Generate filename
    safe_title = "".join(c for c in report.title if c.isalnum() or c in (' ', '-', '_')).strip()
    filename = f"{safe_title}_{datetime.now().strftime('%Y%m%d')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


# ============================================================================
# Data API Endpoints (for WYSIWYG editor)
# ============================================================================

@router.get("/api/targets/{target_id}/data")
async def get_target_data(
    target_id: int,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """Get scan data for a specific target (for template preview)."""
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Check access
    if target.tenant_id != user.tenant_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    # Get latest scan results
    scan_results = session.exec(
        select(ScanResult)
        .where(ScanResult.target_id == target_id)
        .order_by(ScanResult.scanned_at.desc())
    ).all()

    # Organize by module
    data = {
        "target": {
            "id": target.id,
            "domain": target.domain,
            "created_at": target.created_at.isoformat() if target.created_at else None,
            "tags": target.tags
        },
        "modules": {}
    }

    seen_modules = set()
    for result in scan_results:
        if result.module_name not in seen_modules:
            data["modules"][result.module_name] = {
                "data": result.data,
                "scanned_at": result.scanned_at.isoformat() if result.scanned_at else None
            }
            seen_modules.add(result.module_name)

    return JSONResponse(data)


@router.get("/api/available-variables")
async def get_available_variables(
    user: User = Depends(get_current_user_html)
):
    """Get list of available template variables for the editor."""
    return JSONResponse({
        "sections": get_available_sections(),
        "variables": get_template_variables()
    })


# ============================================================================
# Helper Functions
# ============================================================================


def normalize_scan_data(modules_data: dict) -> dict:
    """
    Normalize raw scan data to match documented template variable structure.

    This ensures that template variables like {{ ssl.not_after }} work correctly
    even though the raw data uses camelCase (notAfter).
    """
    normalized = {}

    for module_name, data in modules_data.items():
        if data is None:
            normalized[module_name] = {}
            continue

        # Make a copy to avoid modifying original
        norm_data = dict(data) if isinstance(data, dict) else data

        # === SSL Scanner Normalization ===
        if module_name == "ssl_scanner" and isinstance(norm_data, dict):
            # Convert camelCase to snake_case for common fields
            if "notAfter" in norm_data:
                norm_data["not_after"] = norm_data["notAfter"]
            if "notBefore" in norm_data:
                norm_data["not_before"] = norm_data["notBefore"]
            if "subjectAltName" in norm_data:
                # Convert [["DNS", "example.com"]] to ["example.com"]
                san_list = norm_data["subjectAltName"]
                if isinstance(san_list, list):
                    norm_data["subject_alt_names"] = [
                        item[1] if isinstance(item, (list, tuple)) and len(item) > 1 else str(item)
                        for item in san_list
                    ]
                else:
                    norm_data["subject_alt_names"] = []
            if "serialNumber" in norm_data:
                norm_data["serial_number"] = norm_data["serialNumber"]

            # Flatten issuer/subject to string for easy template access
            issuer = norm_data.get("issuer", {})
            if isinstance(issuer, dict):
                norm_data["issuer"] = issuer.get("commonName") or issuer.get("organizationName") or str(issuer)

            subject = norm_data.get("subject", {})
            if isinstance(subject, dict):
                norm_data["subject"] = subject.get("commonName") or str(subject)

            # Extract protocols from ciphers
            ciphers = norm_data.get("ciphers", [])
            if ciphers and isinstance(ciphers, list):
                protocols = list(set(c.get("version", "") for c in ciphers if isinstance(c, dict)))
                norm_data["protocols"] = sorted(protocols)

            # Add convenience fields
            norm_data["is_valid"] = norm_data.get("error") is None and norm_data.get("not_after") is not None
            norm_data["is_self_signed"] = False  # Would need chain analysis to determine

            # Calculate days until expiry
            not_after = norm_data.get("not_after") or norm_data.get("notAfter")
            if not_after and isinstance(not_after, str):
                try:
                    from datetime import datetime
                    # Parse format like "Mar 11 19:12:37 2026 GMT"
                    expiry_dt = datetime.strptime(not_after.replace(" GMT", ""), "%b %d %H:%M:%S %Y")
                    norm_data["days_until_expiry"] = (expiry_dt - datetime.utcnow()).days
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).debug(f"Failed to parse SSL expiry date: {e}")

        # === Web Analyzer Normalization ===
        elif module_name == "web_analyzer" and isinstance(norm_data, dict):
            # Map http_headers to security_headers for template compatibility
            http_headers = norm_data.get("http_headers", {})
            if http_headers and isinstance(http_headers, dict):
                security_headers = {}
                security_header_names = [
                    "Strict-Transport-Security", "Content-Security-Policy",
                    "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
                    "Referrer-Policy", "Permissions-Policy", "X-Permitted-Cross-Domain-Policies"
                ]
                for header_name in security_header_names:
                    # Check case-insensitive
                    for key, value in http_headers.items():
                        if key.lower() == header_name.lower():
                            security_headers[header_name] = value
                            break
                norm_data["security_headers"] = security_headers

                # Calculate missing headers
                missing = [h for h in security_header_names[:6] if h not in security_headers]
                norm_data["missing_headers"] = missing

            # Add server from headers if not present
            if "server" not in norm_data and http_headers:
                for key, value in http_headers.items():
                    if key.lower() == "server":
                        norm_data["server"] = value
                        break

            # Ensure tech_stack is a list
            if "tech_stack" not in norm_data:
                norm_data["tech_stack"] = []

        # === DNS Scanner Normalization ===
        elif module_name == "dns_scanner" and isinstance(norm_data, dict):
            # Ensure subdomains exists (may come from subdomain_scanner)
            if "subdomains" not in norm_data:
                norm_data["subdomains"] = []
            # Ensure records exists
            if "records" not in norm_data:
                norm_data["records"] = {}

        # === Merge subdomain_scanner into dns_scanner ===
        elif module_name == "subdomain_scanner" and isinstance(norm_data, dict):
            # This will be handled after the loop
            pass

        # === Port Scanner / Nmap Normalization ===
        elif module_name in ("port_scanner", "nmap_scanner") and isinstance(norm_data, dict):
            # Ensure open_ports list exists
            if "open_ports" not in norm_data:
                ports = norm_data.get("ports", [])
                if isinstance(ports, list):
                    norm_data["open_ports"] = [p for p in ports if isinstance(p, dict) and p.get("state") == "open"]
                else:
                    norm_data["open_ports"] = []

        # === Nuclei Scanner Normalization ===
        elif module_name == "nuclei_scanner" and isinstance(norm_data, dict):
            # Ensure both findings and vulnerabilities exist for template compatibility
            vulns = norm_data.get("vulnerabilities", []) or norm_data.get("findings", [])
            norm_data["findings"] = vulns
            norm_data["vulnerabilities"] = vulns

            # Calculate stats if not present
            if "stats" not in norm_data:
                stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for v in vulns:
                    sev = v.get("severity", "info").lower()
                    if sev in stats:
                        stats[sev] += 1
                norm_data["stats"] = stats

        # === Infrastructure Scanner Normalization ===
        elif module_name == "infrastructure_scanner" and isinstance(norm_data, dict):
            # Add convenience aliases
            if "ip" in norm_data and "ip_address" not in norm_data:
                norm_data["ip_address"] = norm_data["ip"]

        normalized[module_name] = norm_data

    # Merge subdomain_scanner data into dns_scanner
    if "subdomain_scanner" in normalized and "dns_scanner" in normalized:
        subdomain_data = normalized["subdomain_scanner"]
        dns_data = normalized["dns_scanner"]

        # Copy subdomains to dns_scanner
        if "subdomains" in subdomain_data:
            dns_data["subdomains"] = subdomain_data["subdomains"]

        # Merge records if dns_scanner has empty records
        if subdomain_data.get("records") and not dns_data.get("records", {}).get("A"):
            dns_data["records"] = subdomain_data["records"]

    # If only subdomain_scanner exists, also expose as dns_scanner
    if "subdomain_scanner" in normalized and "dns_scanner" not in normalized:
        normalized["dns_scanner"] = normalized["subdomain_scanner"]

    return normalized


def gather_scan_data(session: Session, target_ids: List[int], tenant_id: Optional[int]) -> dict:
    """
    Collect all scan data for the requested targets.
    Returns a dictionary structure compatible with report generator.

    IMPORTANT: This function enforces tenant isolation - only targets belonging
    to the specified tenant_id will be included in the results.
    """
    scan_data = {
        "targets": [],
        "summary": {
            "total_targets": 0,
            "total_vulnerabilities": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
    }

    if not target_ids:
        return scan_data

    # Fetch targets - ALWAYS filter by tenant_id for security
    query = select(Target).where(Target.id.in_(target_ids))
    if tenant_id is not None:
        query = query.where(Target.tenant_id == tenant_id)

    targets = session.exec(query).all()
    scan_data["summary"]["total_targets"] = len(targets)

    for target in targets:
        # Get latest results for each module
        results = session.exec(
            select(ScanResult)
            .where(ScanResult.target_id == target.id)
            .order_by(ScanResult.scanned_at.desc())
        ).all()

        modules_data = {}
        seen_modules = set()

        for res in results:
            if res.module_name not in seen_modules:
                modules_data[res.module_name] = res.data
                seen_modules.add(res.module_name)

        # Normalize module data to match template variable expectations
        modules_data = normalize_scan_data(modules_data)

        # Calculate stats from Nuclei results
        if "nuclei_scanner" in modules_data:
            vulns = modules_data["nuclei_scanner"].get("vulnerabilities", []) or \
                    modules_data["nuclei_scanner"].get("findings", [])
            scan_data["summary"]["total_vulnerabilities"] += len(vulns)
            for v in vulns:
                sev = v.get("severity", "info").lower()
                if sev == "critical":
                    scan_data["summary"]["critical_count"] += 1
                elif sev == "high":
                    scan_data["summary"]["high_count"] += 1
                elif sev == "medium":
                    scan_data["summary"]["medium_count"] += 1
                elif sev == "low":
                    scan_data["summary"]["low_count"] += 1
                else:
                    scan_data["summary"]["info_count"] += 1

        target_info = {
            "id": target.id,
            "domain": target.domain,
            "created_at": target.created_at,
            "tags": target.tags or [],
            "status": target.scan_status,
            "last_scan": None,  # Will be populated from latest scan result below
            "modules": modules_data
        }

        # Get last scan time from the most recent scan result
        if results:
            latest_result = max(results, key=lambda r: r.scanned_at)
            target_info["last_scan"] = latest_result.scanned_at
        scan_data["targets"].append(target_info)

    return scan_data


def get_available_sections():
    """Return list of available report sections with metadata."""
    return [
        {
            "id": "summary",
            "name": "Executive Summary",
            "description": "High-level overview with security score and key findings"
        },
        {
            "id": "dns",
            "name": "DNS Analysis",
            "description": "DNS records, subdomains, and nameserver information"
        },
        {
            "id": "ssl",
            "name": "SSL/TLS Analysis",
            "description": "Certificate details, expiration, and security configuration"
        },
        {
            "id": "web",
            "name": "Web Analysis",
            "description": "Technology stack, headers, and web application findings"
        },
        {
            "id": "vulnerabilities",
            "name": "Vulnerabilities",
            "description": "CVEs, security issues, and risk findings"
        },
        {
            "id": "nuclei",
            "name": "Nuclei Scan Results",
            "description": "Active vulnerability scan findings"
        },
        {
            "id": "infrastructure",
            "name": "Infrastructure",
            "description": "Cloud providers, ASN, geolocation data"
        },
        {
            "id": "ports",
            "name": "Port Exposure",
            "description": "Open ports and service detection"
        },
        {
            "id": "compliance",
            "name": "Compliance Status",
            "description": "SOC2, GDPR, PCI-DSS compliance mapping"
        },
        {
            "id": "screenshots",
            "name": "Screenshots",
            "description": "Visual captures of web interfaces"
        },
        {
            "id": "osint",
            "name": "OSINT Findings",
            "description": "Open-source intelligence results"
        },
        {
            "id": "typosquat",
            "name": "Typosquatting",
            "description": "Brand protection and lookalike domain detection"
        }
    ]


def get_template_variables():
    """Return list of available template variables with comprehensive documentation."""
    return {
        # ===== BRANDING & REPORT METADATA =====
        "tenant": [
            {"var": "{{ tenant.name }}", "desc": "Tenant/Organization name"},
            {"var": "{{ tenant.report_company_name }}", "desc": "Company name displayed in reports"},
            {"var": "{{ tenant.report_logo_url }}", "desc": "Logo URL or data URI for branding"},
            {"var": "{{ tenant.report_primary_color }}", "desc": "Primary brand color (hex)"},
            {"var": "{{ tenant.report_secondary_color }}", "desc": "Secondary brand color (hex)"},
            {"var": "{{ tenant.report_header_text }}", "desc": "Custom header text for reports"},
            {"var": "{{ tenant.report_footer_text }}", "desc": "Custom footer text for reports"},
        ],
        "report": [
            {"var": "{{ report.title }}", "desc": "Report title"},
            {"var": "{{ report.generated_at }}", "desc": "Generation timestamp"},
            {"var": "{{ report.generated_at|date }}", "desc": "Generation date (formatted)"},
            {"var": "{{ report.target_count }}", "desc": "Number of targets included"},
            {"var": "{{ now }}", "desc": "Current timestamp"},
            {"var": "{{ now|datetime }}", "desc": "Current date and time (formatted)"},
        ],
        "summary": [
            {"var": "{{ summary.total_targets }}", "desc": "Total number of targets"},
            {"var": "{{ summary.total_vulnerabilities }}", "desc": "Total vulnerabilities found"},
            {"var": "{{ summary.critical_count }}", "desc": "Critical severity count"},
            {"var": "{{ summary.high_count }}", "desc": "High severity count"},
            {"var": "{{ summary.medium_count }}", "desc": "Medium severity count"},
            {"var": "{{ summary.low_count }}", "desc": "Low severity count"},
            {"var": "{{ summary.info_count }}", "desc": "Informational findings count"},
        ],

        # ===== TARGET DATA =====
        "target": [
            {"var": "{{ target.domain }}", "desc": "Domain name (single-target reports)"},
            {"var": "{{ target.id }}", "desc": "Internal target ID"},
            {"var": "{{ target.created_at }}", "desc": "When target was added"},
            {"var": "{{ target.created_at|date }}", "desc": "Creation date (formatted)"},
            {"var": "{{ target.tags }}", "desc": "List of target tags"},
            {"var": "{{ target.tags|join(', ') }}", "desc": "Tags as comma-separated string"},
            {"var": "{{ target.status }}", "desc": "Current scan status"},
            {"var": "{{ target.last_scan }}", "desc": "Last scan timestamp"},
        ],
        "targets_loop": [
            {"var": "{% for t in targets %}", "desc": "Loop through all targets"},
            {"var": "{{ t.domain }}", "desc": "Domain in loop"},
            {"var": "{{ t.modules.dns_scanner }}", "desc": "DNS data for target"},
            {"var": "{{ t.modules.ssl_scanner }}", "desc": "SSL data for target"},
            {"var": "{{ t.modules.nuclei_scanner }}", "desc": "Vulnerability data for target"},
            {"var": "{{ loop.index }}", "desc": "Current iteration number (1-based)"},
            {"var": "{% endfor %}", "desc": "End of loop"},
        ],

        # ===== DNS SCANNER =====
        "dns": [
            {"var": "{{ dns.subdomains }}", "desc": "List of discovered subdomains"},
            {"var": "{{ dns.subdomains|count }}", "desc": "Number of subdomains found"},
            {"var": "{{ dns.records.A }}", "desc": "A records (IPv4 addresses)"},
            {"var": "{{ dns.records.AAAA }}", "desc": "AAAA records (IPv6 addresses)"},
            {"var": "{{ dns.records.MX }}", "desc": "MX records (mail servers)"},
            {"var": "{{ dns.records.TXT }}", "desc": "TXT records"},
            {"var": "{{ dns.records.NS }}", "desc": "NS records (nameservers)"},
            {"var": "{{ dns.records.CNAME }}", "desc": "CNAME records"},
            {"var": "{{ dns.records.SOA }}", "desc": "SOA record"},
            {"var": "{{ dns.records.SPF }}", "desc": "SPF record for email security"},
            {"var": "{{ dns.records.DMARC }}", "desc": "DMARC record for email auth"},
            {"var": "{{ dns.records.DKIM }}", "desc": "DKIM records"},
            {"var": "{{ dns.nameservers }}", "desc": "List of authoritative nameservers"},
            {"var": "{{ dns.wildcard_detected }}", "desc": "Whether wildcard DNS is enabled"},
            {"var": "{{ dns.dangling_cnames }}", "desc": "CNAME records pointing to non-existent domains"},
            {"var": "{{ dns.zone_transfer_possible }}", "desc": "Whether zone transfer is allowed"},
        ],

        # ===== SSL/TLS SCANNER =====
        "ssl": [
            {"var": "{{ ssl.issuer }}", "desc": "Certificate issuer (CA)"},
            {"var": "{{ ssl.subject }}", "desc": "Certificate subject"},
            {"var": "{{ ssl.not_before }}", "desc": "Certificate valid from date"},
            {"var": "{{ ssl.not_after }}", "desc": "Certificate expiration date"},
            {"var": "{{ ssl.days_until_expiry }}", "desc": "Days until certificate expires"},
            {"var": "{{ ssl.serial_number }}", "desc": "Certificate serial number"},
            {"var": "{{ ssl.version }}", "desc": "Certificate version"},
            {"var": "{{ ssl.subject_alt_names }}", "desc": "Subject Alternative Names (SANs)"},
            {"var": "{{ ssl.subject_alt_names|count }}", "desc": "Number of SANs"},
            {"var": "{{ ssl.signature_algorithm }}", "desc": "Signature algorithm used"},
            {"var": "{{ ssl.public_key_type }}", "desc": "Public key type (RSA, EC, etc.)"},
            {"var": "{{ ssl.public_key_bits }}", "desc": "Public key size in bits"},
            {"var": "{{ ssl.ciphers }}", "desc": "List of supported cipher suites"},
            {"var": "{{ ssl.protocols }}", "desc": "Supported TLS/SSL protocols"},
            {"var": "{{ ssl.is_valid }}", "desc": "Whether certificate is currently valid"},
            {"var": "{{ ssl.is_self_signed }}", "desc": "Whether certificate is self-signed"},
            {"var": "{{ ssl.chain }}", "desc": "Certificate chain details"},
            {"var": "{{ ssl.error }}", "desc": "SSL error message (if any)"},
        ],

        # ===== WEB ANALYZER =====
        "web": [
            {"var": "{{ web.status_code }}", "desc": "HTTP response status code"},
            {"var": "{{ web.server }}", "desc": "Web server software"},
            {"var": "{{ web.title }}", "desc": "Page title"},
            {"var": "{{ web.tech_stack }}", "desc": "Detected technologies list"},
            {"var": "{{ web.tech_stack|join(', ') }}", "desc": "Technologies as string"},
            {"var": "{{ web.frameworks }}", "desc": "Detected web frameworks"},
            {"var": "{{ web.cms }}", "desc": "Content management system"},
            {"var": "{{ web.programming_languages }}", "desc": "Detected programming languages"},
            {"var": "{{ web.security_headers }}", "desc": "Security headers analysis"},
            {"var": "{{ web.security_headers.X-Frame-Options }}", "desc": "X-Frame-Options header"},
            {"var": "{{ web.security_headers.Content-Security-Policy }}", "desc": "CSP header present"},
            {"var": "{{ web.security_headers.Strict-Transport-Security }}", "desc": "HSTS header"},
            {"var": "{{ web.security_headers.X-Content-Type-Options }}", "desc": "X-Content-Type-Options"},
            {"var": "{{ web.missing_headers }}", "desc": "List of missing security headers"},
            {"var": "{{ web.cookies }}", "desc": "Cookies found"},
            {"var": "{{ web.has_login }}", "desc": "Whether login form detected"},
            {"var": "{{ web.forms }}", "desc": "Forms found on page"},
            {"var": "{{ web.external_links }}", "desc": "External links found"},
            {"var": "{{ web.meta_tags }}", "desc": "HTML meta tags"},
            {"var": "{{ web.response_time_ms }}", "desc": "Response time in milliseconds"},
        ],

        # ===== VULNERABILITY SCANNER (NUCLEI) =====
        "nuclei": [
            {"var": "{{ nuclei.findings }}", "desc": "List of all vulnerability findings"},
            {"var": "{{ nuclei.findings|count }}", "desc": "Total number of findings"},
            {"var": "{{ nuclei.stats.critical }}", "desc": "Critical vulnerability count"},
            {"var": "{{ nuclei.stats.high }}", "desc": "High vulnerability count"},
            {"var": "{{ nuclei.stats.medium }}", "desc": "Medium vulnerability count"},
            {"var": "{{ nuclei.stats.low }}", "desc": "Low vulnerability count"},
            {"var": "{{ nuclei.stats.info }}", "desc": "Informational finding count"},
            {"var": "{{ vulnerabilities }}", "desc": "Alias for nuclei.findings"},
        ],
        "vuln_loop": [
            {"var": "{% for v in nuclei.findings %}", "desc": "Loop through vulnerabilities"},
            {"var": "{{ v.name }}", "desc": "Vulnerability name"},
            {"var": "{{ v.severity }}", "desc": "Severity level"},
            {"var": "{{ v.severity|severity_badge }}", "desc": "Severity as colored badge"},
            {"var": "{{ v.template_id }}", "desc": "Nuclei template ID"},
            {"var": "{{ v.description }}", "desc": "Vulnerability description"},
            {"var": "{{ v.matched_at }}", "desc": "URL where vulnerability found"},
            {"var": "{{ v.curl_command }}", "desc": "cURL command to reproduce"},
            {"var": "{{ v.reference }}", "desc": "Reference links"},
            {"var": "{{ v.remediation }}", "desc": "Remediation guidance"},
            {"var": "{{ v.cve_id }}", "desc": "CVE identifier if applicable"},
            {"var": "{% endfor %}", "desc": "End vulnerability loop"},
        ],

        # ===== NMAP / PORT SCANNER =====
        "nmap": [
            {"var": "{{ nmap.open_ports }}", "desc": "List of open ports"},
            {"var": "{{ nmap.open_ports|count }}", "desc": "Number of open ports"},
            {"var": "{{ nmap.services }}", "desc": "Detected services"},
            {"var": "{{ nmap.os_detection }}", "desc": "Operating system detection"},
            {"var": "{{ nmap.host_status }}", "desc": "Host up/down status"},
            {"var": "{{ nmap.scan_time }}", "desc": "Scan duration"},
        ],
        "port_loop": [
            {"var": "{% for p in nmap.open_ports %}", "desc": "Loop through ports"},
            {"var": "{{ p.port }}", "desc": "Port number"},
            {"var": "{{ p.protocol }}", "desc": "Protocol (tcp/udp)"},
            {"var": "{{ p.service }}", "desc": "Service name"},
            {"var": "{{ p.version }}", "desc": "Service version"},
            {"var": "{{ p.state }}", "desc": "Port state"},
            {"var": "{% endfor %}", "desc": "End port loop"},
        ],
        "ports": [
            {"var": "{{ ports.exposed }}", "desc": "List of exposed ports"},
            {"var": "{{ ports.risky_ports }}", "desc": "Potentially dangerous open ports"},
            {"var": "{{ ports.by_service }}", "desc": "Ports grouped by service"},
        ],

        # ===== INFRASTRUCTURE SCANNER =====
        "infrastructure": [
            {"var": "{{ infrastructure.ip_address }}", "desc": "Primary IP address"},
            {"var": "{{ infrastructure.asn }}", "desc": "Autonomous System Number"},
            {"var": "{{ infrastructure.asn_org }}", "desc": "ASN organization name"},
            {"var": "{{ infrastructure.isp }}", "desc": "Internet Service Provider"},
            {"var": "{{ infrastructure.country }}", "desc": "Server country"},
            {"var": "{{ infrastructure.city }}", "desc": "Server city"},
            {"var": "{{ infrastructure.region }}", "desc": "Server region"},
            {"var": "{{ infrastructure.hosting_provider }}", "desc": "Hosting provider name"},
            {"var": "{{ infrastructure.is_cloud }}", "desc": "Whether hosted on cloud provider"},
            {"var": "{{ infrastructure.cloud_provider }}", "desc": "Cloud provider (AWS, GCP, Azure)"},
            {"var": "{{ infrastructure.datacenter }}", "desc": "Datacenter information"},
            {"var": "{{ infrastructure.reverse_dns }}", "desc": "Reverse DNS (PTR) record"},
        ],

        # ===== CLOUD SCANNER =====
        "cloud": [
            {"var": "{{ cloud.buckets }}", "desc": "Discovered cloud storage buckets"},
            {"var": "{{ cloud.buckets|count }}", "desc": "Number of buckets found"},
            {"var": "{{ cloud.public_buckets }}", "desc": "Publicly accessible buckets"},
            {"var": "{{ cloud.azure_blobs }}", "desc": "Azure blob containers"},
            {"var": "{{ cloud.gcp_buckets }}", "desc": "Google Cloud Storage buckets"},
        ],
        "bucket_loop": [
            {"var": "{% for b in cloud.buckets %}", "desc": "Loop through buckets"},
            {"var": "{{ b.name }}", "desc": "Bucket name"},
            {"var": "{{ b.provider }}", "desc": "Cloud provider (S3, Azure, GCP)"},
            {"var": "{{ b.region }}", "desc": "Bucket region"},
            {"var": "{{ b.is_public }}", "desc": "Whether publicly accessible"},
            {"var": "{{ b.url }}", "desc": "Bucket URL"},
            {"var": "{% endfor %}", "desc": "End bucket loop"},
        ],

        # ===== TYPOSQUATTING SCANNER =====
        "typosquat": [
            {"var": "{{ typosquat.lookalikes }}", "desc": "Similar/lookalike domains found"},
            {"var": "{{ typosquat.lookalikes|count }}", "desc": "Number of lookalikes"},
            {"var": "{{ typosquat.registered }}", "desc": "Registered lookalike domains"},
            {"var": "{{ typosquat.available }}", "desc": "Available lookalike domains"},
            {"var": "{{ typosquat.risky }}", "desc": "High-risk lookalikes (active websites)"},
            {"var": "{{ typosquat.brand_impersonation }}", "desc": "Domains with brand impersonation"},
        ],
        "typo_loop": [
            {"var": "{% for d in typosquat.lookalikes %}", "desc": "Loop through lookalikes"},
            {"var": "{{ d.domain }}", "desc": "Lookalike domain name"},
            {"var": "{{ d.technique }}", "desc": "Typosquat technique used"},
            {"var": "{{ d.is_registered }}", "desc": "Whether domain is registered"},
            {"var": "{{ d.is_active }}", "desc": "Whether has active website"},
            {"var": "{{ d.similarity_score }}", "desc": "Visual similarity score"},
            {"var": "{{ d.risk_level }}", "desc": "Risk assessment level"},
            {"var": "{% endfor %}", "desc": "End typosquat loop"},
        ],

        # ===== VISUAL OSINT / SCREENSHOTS =====
        "osint": [
            {"var": "{{ osint.screenshots }}", "desc": "List of captured screenshots"},
            {"var": "{{ osint.screenshots|count }}", "desc": "Number of screenshots"},
            {"var": "{{ osint.google_results }}", "desc": "Google search results"},
            {"var": "{{ osint.social_media }}", "desc": "Social media mentions"},
            {"var": "{{ osint.breach_data }}", "desc": "Data breach information"},
            {"var": "{{ osint.paste_sites }}", "desc": "Paste site mentions"},
            {"var": "{{ osint.metadata }}", "desc": "Extracted metadata"},
        ],
        "screenshot_loop": [
            {"var": "{% for s in osint.screenshots %}", "desc": "Loop through screenshots"},
            {"var": "{{ s.url }}", "desc": "Screenshot URL"},
            {"var": "{{ s.filename }}", "desc": "Screenshot filename"},
            {"var": "{{ s.timestamp }}", "desc": "Capture timestamp"},
            {"var": "{% endfor %}", "desc": "End screenshot loop"},
        ],

        # ===== CRAWLER =====
        "crawler": [
            {"var": "{{ crawler.pages }}", "desc": "List of crawled pages"},
            {"var": "{{ crawler.pages|count }}", "desc": "Number of pages crawled"},
            {"var": "{{ crawler.internal_links }}", "desc": "Internal links found"},
            {"var": "{{ crawler.external_links }}", "desc": "External links found"},
            {"var": "{{ crawler.forms }}", "desc": "Forms discovered"},
            {"var": "{{ crawler.emails }}", "desc": "Email addresses found"},
            {"var": "{{ crawler.files }}", "desc": "Files discovered (PDFs, docs, etc.)"},
            {"var": "{{ crawler.parameters }}", "desc": "URL parameters found"},
            {"var": "{{ crawler.comments }}", "desc": "HTML comments extracted"},
            {"var": "{{ crawler.js_files }}", "desc": "JavaScript files found"},
            {"var": "{{ crawler.api_endpoints }}", "desc": "Potential API endpoints"},
        ],

        # ===== WAYBACK MACHINE =====
        "wayback": [
            {"var": "{{ wayback.snapshots }}", "desc": "List of archived snapshots"},
            {"var": "{{ wayback.snapshots|count }}", "desc": "Number of snapshots"},
            {"var": "{{ wayback.first_seen }}", "desc": "First archive date"},
            {"var": "{{ wayback.last_seen }}", "desc": "Most recent archive"},
            {"var": "{{ wayback.historical_urls }}", "desc": "Historical URLs discovered"},
            {"var": "{{ wayback.removed_pages }}", "desc": "Pages no longer available"},
            {"var": "{{ wayback.old_technologies }}", "desc": "Historical tech stack"},
        ],

        # ===== TLD SCANNER =====
        "tld": [
            {"var": "{{ tld.variations }}", "desc": "Domain TLD variations checked"},
            {"var": "{{ tld.registered }}", "desc": "Registered TLD variations"},
            {"var": "{{ tld.available }}", "desc": "Available TLD variations"},
            {"var": "{{ tld.parked }}", "desc": "Parked domains"},
            {"var": "{{ tld.active_sites }}", "desc": "TLD variations with active sites"},
        ],

        # ===== CONTENT DISCOVERY =====
        "content_discovery": [
            {"var": "{{ content_discovery.directories }}", "desc": "Discovered directories"},
            {"var": "{{ content_discovery.files }}", "desc": "Discovered files"},
            {"var": "{{ content_discovery.backup_files }}", "desc": "Backup files found"},
            {"var": "{{ content_discovery.config_files }}", "desc": "Configuration files found"},
            {"var": "{{ content_discovery.admin_panels }}", "desc": "Admin panel URLs"},
            {"var": "{{ content_discovery.sensitive_paths }}", "desc": "Sensitive paths found"},
        ],

        # ===== SEED FILES SCANNER (NEW) =====
        "seed_files": [
            {"var": "{{ seed_files.robots_txt }}", "desc": "robots.txt analysis"},
            {"var": "{{ seed_files.robots_txt.found }}", "desc": "Whether robots.txt exists"},
            {"var": "{{ seed_files.robots_txt.disallow_rules }}", "desc": "Disallowed paths"},
            {"var": "{{ seed_files.robots_txt.allow_rules }}", "desc": "Allowed paths"},
            {"var": "{{ seed_files.robots_txt.sitemaps }}", "desc": "Sitemaps declared in robots.txt"},
            {"var": "{{ seed_files.robots_txt.crawl_delay }}", "desc": "Crawl delay value"},
            {"var": "{{ seed_files.sitemaps }}", "desc": "List of analyzed sitemaps"},
            {"var": "{{ seed_files.sitemaps|count }}", "desc": "Number of sitemaps"},
            {"var": "{{ seed_files.total_urls }}", "desc": "Total URLs in sitemaps"},
            {"var": "{{ seed_files.sensitive_paths }}", "desc": "Sensitive paths from robots.txt"},
            {"var": "{{ seed_files.statistics.total_paths }}", "desc": "Total paths discovered"},
        ],
        "sitemap_loop": [
            {"var": "{% for sm in seed_files.sitemaps %}", "desc": "Loop through sitemaps"},
            {"var": "{{ sm.url }}", "desc": "Sitemap URL"},
            {"var": "{{ sm.url_count }}", "desc": "Number of URLs in sitemap"},
            {"var": "{{ sm.lastmod }}", "desc": "Last modification date"},
            {"var": "{% endfor %}", "desc": "End sitemap loop"},
        ],

        # ===== CSP SCANNER (NEW) =====
        "csp": [
            {"var": "{{ csp.csp_header }}", "desc": "Full CSP header value"},
            {"var": "{{ csp.has_csp }}", "desc": "Whether CSP header is present"},
            {"var": "{{ csp.csp_report_only }}", "desc": "Report-Only CSP header"},
            {"var": "{{ csp.external_domains }}", "desc": "All external domains in CSP"},
            {"var": "{{ csp.external_domains|count }}", "desc": "Number of external domains"},
            {"var": "{{ csp.potential_assets }}", "desc": "Potential company assets found"},
            {"var": "{{ csp.third_party_services }}", "desc": "Third-party services by category"},
            {"var": "{{ csp.third_party_services.cdn }}", "desc": "CDN domains"},
            {"var": "{{ csp.third_party_services.analytics }}", "desc": "Analytics domains"},
            {"var": "{{ csp.third_party_services.social }}", "desc": "Social media domains"},
            {"var": "{{ csp.third_party_services.advertising }}", "desc": "Advertising domains"},
            {"var": "{{ csp.third_party_services.payment }}", "desc": "Payment provider domains"},
            {"var": "{{ csp.security_findings }}", "desc": "CSP security issues found"},
            {"var": "{{ csp.parsed_directives }}", "desc": "Parsed CSP directives"},
            {"var": "{{ csp.statistics.security_issues }}", "desc": "Number of CSP issues"},
        ],
        "csp_asset_loop": [
            {"var": "{% for a in csp.potential_assets %}", "desc": "Loop through potential assets"},
            {"var": "{{ a.domain }}", "desc": "Asset domain"},
            {"var": "{{ a.reason }}", "desc": "Why it's a potential asset"},
            {"var": "{{ a.priority }}", "desc": "Priority level"},
            {"var": "{% endfor %}", "desc": "End asset loop"},
        ],

        # ===== FILTERS & HELPERS =====
        "filters": [
            {"var": "{{ value|date }}", "desc": "Format as date (YYYY-MM-DD)"},
            {"var": "{{ value|datetime }}", "desc": "Format as datetime"},
            {"var": "{{ value|count }}", "desc": "Count items in a list"},
            {"var": "{{ value|truncate(50) }}", "desc": "Truncate text to length"},
            {"var": "{{ value|severity_badge }}", "desc": "Render severity as colored badge"},
            {"var": "{{ list|join(', ') }}", "desc": "Join list items with separator"},
            {"var": "{{ value|default('N/A') }}", "desc": "Default value if empty"},
            {"var": "{{ value|upper }}", "desc": "Convert to uppercase"},
            {"var": "{{ value|lower }}", "desc": "Convert to lowercase"},
        ],
        "conditionals": [
            {"var": "{% if condition %}...{% endif %}", "desc": "Conditional block"},
            {"var": "{% if value %}...{% else %}...{% endif %}", "desc": "If-else block"},
            {"var": "{% if list|count > 0 %}...{% endif %}", "desc": "Check if list not empty"},
        ],
    }
