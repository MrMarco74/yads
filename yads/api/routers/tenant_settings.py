from fastapi import APIRouter, Depends, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from sqlmodel import Session, select, func
from typing import Optional
import csv
import io
import logging
import math
from datetime import date, datetime, timezone

logger = logging.getLogger(__name__)

from typing import List
from yads.database import get_session
from yads.models import User, Tenant, Webhook, TenantScanConfig, SecurityFinding, Target
from yads.auth.deps import RoleChecker, get_current_user
from yads.core.module_registry import REGISTRY
from yads.config import settings

router = APIRouter(prefix="/tenant-settings", tags=["tenant-settings"])
from yads.api.templating import templates

# Inject Globals (similar to other routers)
from datetime import datetime
templates.env.globals['settings'] = settings
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

def get_all_tenants(): # Helper for context switching if needed
    try:
        from yads.database import engine
        from yads.models import Tenant
        from sqlmodel import select
        with Session(engine) as session:
            return session.exec(select(Tenant).order_by(Tenant.name)).all()
    except Exception as e:
        print(f"Error in get_available_tenants: {e}")
        return []
templates.env.globals['get_available_tenants'] = get_all_tenants


@router.get("/", response_class=HTMLResponse)
async def tenant_settings_page(
    request: Request,
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session)
):
    # Ensure user has a tenant
    if not user.tenant_id:
         # If admin, maybe redirect or show error? 
         # Platform admins might not have a tenant context selected.
         # For now, require tenant context.
         if user.role == 'admin':
             # Check if they have switched context?
             # If tenant_id is None, show warning "Select a tenant first"
             return templates.TemplateResponse("tenant_settings.html", {
                 "request": request,
                 "error": "Please select a Tenant context from the sidebar/topbar to manage its settings.",
                 "no_context": True,
                 "user": user
             })
         else:
             # Should practically never happen for tenant_admin with required tenant
             return RedirectResponse("/", status_code=303)

    # Reload tenant from DB to confirm fresh data
    tenant = session.get(Tenant, user.tenant_id)

    webhooks = session.exec(select(Webhook).where(Webhook.tenant_id == user.tenant_id)).all()
    scan_config = session.exec(
        select(TenantScanConfig).where(TenantScanConfig.tenant_id == user.tenant_id)
    ).first()
    all_scan_types = sorted(REGISTRY.keys())

    # Dynamic API key specs from all registered modules
    from yads.core.tenant_keys import get_all_api_key_specs, load_tenant_api_keys
    all_specs = get_all_api_key_specs()
    current_keys = load_tenant_api_keys(session, user.tenant_id)
    # Build list of (spec, current_value, is_set)
    module_api_keys = [
        {"spec": spec, "value": current_keys.get(spec.name, ""), "is_set": bool(current_keys.get(spec.name))}
        for spec in all_specs
    ]

    return templates.TemplateResponse("tenant_settings.html", {
        "request": request,
        "tenant": tenant,
        "webhooks": webhooks,
        "user": user,
        "scan_config": scan_config,
        "all_scan_types": all_scan_types,
        "module_api_keys": module_api_keys,
    })


@router.post("/", response_class=HTMLResponse)
async def update_tenant_settings(
    request: Request,
    google_api_key: Optional[str] = Form(None),
    google_cse_cx: Optional[str] = Form(None),
    nuclei_api_key: Optional[str] = Form(None),
    hibp_api_key: Optional[str] = Form(None),
    hunter_api_key: Optional[str] = Form(None),
    github_token: Optional[str] = Form(None),
    twitter_bearer_token: Optional[str] = Form(None),
    # Advanced OSINT API Keys (v1.16.0)
    shodan_api_key: Optional[str] = Form(None),
    censys_api_key: Optional[str] = Form(None),
    virustotal_api_key: Optional[str] = Form(None),
    # Optional[str], not Optional[int]: an empty number input submits "",
    # which FastAPI/Pydantic v2 doesn't coerce to None for Optional[int] --
    # it 422s the whole form before this function even runs. Parsed to int
    # manually below instead.
    session_timeout_minutes: Optional[str] = Form(None),
    # Report Branding Fields
    report_logo_url: Optional[str] = Form(None),
    report_company_name: Optional[str] = Form(None),
    report_primary_color: Optional[str] = Form(None),
    report_secondary_color: Optional[str] = Form(None),
    report_header_text: Optional[str] = Form(None),
    report_footer_text: Optional[str] = Form(None),
    hide_yads_branding: Optional[str] = Form(None),
    # LLM Settings
    llm_provider: Optional[str] = Form(None),
    llm_api_url: Optional[str] = Form(None),
    llm_api_key: Optional[str] = Form(None),
    llm_model: Optional[str] = Form(None),
    catchall_llm_fallback_enabled: Optional[str] = Form(None),
    # SLA Settings (same Optional[str]-not-int reasoning as session_timeout_minutes above)
    sla_critical: Optional[str] = Form(None),
    sla_high: Optional[str] = Form(None),
    sla_medium: Optional[str] = Form(None),
    sla_low: Optional[str] = Form(None),
    sla_info: Optional[str] = Form(None),
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session)
):
    if not user.tenant_id:
        return RedirectResponse("/tenant-settings", status_code=303)

    def _to_int(raw: Optional[str]) -> Optional[int]:
        if raw is None or not raw.strip():
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    session_timeout_minutes = _to_int(session_timeout_minutes)
    sla_critical = _to_int(sla_critical)
    sla_high = _to_int(sla_high)
    sla_medium = _to_int(sla_medium)
    sla_low = _to_int(sla_low)
    sla_info = _to_int(sla_info)

    tenant = session.get(Tenant, user.tenant_id)
    if not tenant:
        return RedirectResponse("/", status_code=303)

    # Update fields
    tenant.google_api_key = google_api_key if google_api_key and google_api_key.strip() else None
    tenant.google_cse_cx = google_cse_cx if google_cse_cx and google_cse_cx.strip() else None
    tenant.nuclei_api_key = nuclei_api_key if nuclei_api_key and nuclei_api_key.strip() else None
    tenant.hibp_api_key = hibp_api_key if hibp_api_key and hibp_api_key.strip() else None

    # New OSINT API Keys (v1.15.0)
    tenant.hunter_api_key = hunter_api_key if hunter_api_key and hunter_api_key.strip() else None
    tenant.github_token = github_token if github_token and github_token.strip() else None
    tenant.twitter_bearer_token = twitter_bearer_token if twitter_bearer_token and twitter_bearer_token.strip() else None

    # Advanced OSINT API Keys (v1.16.0) — also sync to TenantApiKey table
    tenant.shodan_api_key = shodan_api_key if shodan_api_key and shodan_api_key.strip() else None
    tenant.censys_api_key = censys_api_key if censys_api_key and censys_api_key.strip() else None
    tenant.virustotal_api_key = virustotal_api_key if virustotal_api_key and virustotal_api_key.strip() else None

    # Dynamic API keys from module specs (form fields named "apikey_<key_name>")
    from yads.core.tenant_keys import get_all_api_key_specs, set_tenant_api_key
    form_data = await request.form()
    for spec in get_all_api_key_specs():
        field_name = f"apikey_{spec.name}"
        raw = form_data.get(field_name)
        if raw is not None:  # field was submitted
            val = str(raw).strip() or None
            set_tenant_api_key(session, user.tenant_id, spec.name, val)
            # Also sync to legacy Tenant attr if it exists
            if spec.legacy_tenant_attr and hasattr(tenant, spec.legacy_tenant_attr):
                setattr(tenant, spec.legacy_tenant_attr, val)

    # Session Timeout Validation
    if session_timeout_minutes is not None:
        if session_timeout_minutes < 5:
            return templates.TemplateResponse("tenant_settings.html", {
                "request": request, "tenant": tenant, "webhooks": [], "user": user,
                "error": "Session timeout must be at least 5 minutes."
            })
        if session_timeout_minutes > 480: # Max 8 hours
            return templates.TemplateResponse("tenant_settings.html", {
                "request": request, "tenant": tenant, "webhooks": [], "user": user,
                "error": "Session timeout cannot exceed 8 hours (480 minutes)."
            })
        tenant.session_timeout_minutes = session_timeout_minutes

    # LLM Settings
    tenant.llm_provider = llm_provider if llm_provider and llm_provider.strip() else None
    tenant.llm_api_url = llm_api_url if llm_api_url and llm_api_url.strip() else None
    tenant.llm_api_key = llm_api_key if llm_api_key and llm_api_key.strip() else None
    tenant.llm_model = llm_model if llm_model and llm_model.strip() else None
    tenant.catchall_llm_fallback_enabled = bool(catchall_llm_fallback_enabled)

    # Finding SLA
    if sla_critical is not None: tenant.sla_critical = sla_critical
    if sla_high is not None: tenant.sla_high = sla_high
    if sla_medium is not None: tenant.sla_medium = sla_medium
    if sla_low is not None: tenant.sla_low = sla_low
    # Allow clearing sla_info
    tenant.sla_info = sla_info if sla_info is not None else None

    # Report Branding Settings
    tenant.report_logo_url = report_logo_url if report_logo_url and report_logo_url.strip() else None
    tenant.report_company_name = report_company_name if report_company_name and report_company_name.strip() else None
    tenant.report_primary_color = report_primary_color if report_primary_color and report_primary_color.strip() else "#3b82f6"
    tenant.report_secondary_color = report_secondary_color if report_secondary_color and report_secondary_color.strip() else "#64748b"
    tenant.report_header_text = report_header_text if report_header_text and report_header_text.strip() else None
    tenant.report_footer_text = report_footer_text if report_footer_text and report_footer_text.strip() else None
    tenant.hide_yads_branding = bool(hide_yads_branding)

    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    
    return templates.TemplateResponse("tenant_settings.html", {
        "request": request,
        "tenant": tenant,
        "user": user,
        "success": "Settings updated successfully."
    })

# --- Webhook Management ---

@router.post("/webhooks", response_class=RedirectResponse)
async def create_webhook(
    request: Request,
    url: str = Form(...),
    events: list[str] = Form(default=[]),
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session)
):
    if not user.tenant_id: return RedirectResponse("/tenant-settings", status_code=303)
    
    # Validation
    if not url.startswith("http"):
        # simple validation
        pass 
        
    hook = Webhook(tenant_id=user.tenant_id, url=url, event_types=events)
    session.add(hook)
    session.commit()
    return RedirectResponse("/tenant-settings", status_code=303)

@router.post("/webhooks/{webhook_id}/delete", response_class=RedirectResponse)
async def delete_webhook(
    webhook_id: int,
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session)
):
    if not user.tenant_id: return RedirectResponse("/tenant-settings", status_code=303)
    
    hook = session.get(Webhook, webhook_id)
    if hook and hook.tenant_id == user.tenant_id:
        session.delete(hook)
        session.commit()
        
    return RedirectResponse("/tenant-settings", status_code=303)

@router.post("/webhooks/{webhook_id}/test", response_class=HTMLResponse)
async def test_webhook(
    webhook_id: int,
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session)
):
    if not user.tenant_id: return RedirectResponse("/tenant-settings", status_code=303)
    
    hook = session.get(Webhook, webhook_id)
    if hook and hook.tenant_id == user.tenant_id:
        from yads.core.webhook_service import webhook_service
        webhook_service.trigger_event(user.tenant_id, "test_event", {
            "message": "This is a test event from YADS.",
            "user": user.username
        })
        return f"""
        <div class="alert alert-success shadow-lg mb-4">
            <div>
                <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current flex-shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                <span>Test payload sent to {hook.url}</span>
            </div>
        </div>
        """
    return ""


@router.post("/automation", response_class=HTMLResponse)
async def update_scan_automation(
    request: Request,
    auto_scan_enabled: bool = Form(False),
    frequency: str = Form("weekly"),
    cron_expression: Optional[str] = Form(None),
    scan_types: List[str] = Form(default=[]),
    max_targets_per_run: int = Form(10),
    max_concurrent_scans: int = Form(3),
    scan_window_start: Optional[str] = Form(None),
    scan_window_end: Optional[str] = Form(None),
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session),
):
    if not user.tenant_id:
        return RedirectResponse("/tenant-settings", status_code=303)

    # Validate + sanitise
    if frequency not in ("daily", "weekly", "monthly"):
        frequency = "weekly"
    max_targets_per_run = max(1, min(max_targets_per_run, 100))
    max_concurrent_scans = max(1, min(max_concurrent_scans, 10))
    cron_expr = cron_expression.strip() if cron_expression and cron_expression.strip() else None
    win_start = scan_window_start.strip() if scan_window_start and scan_window_start.strip() else None
    win_end = scan_window_end.strip() if scan_window_end and scan_window_end.strip() else None
    types = scan_types if scan_types else ["dns_scanner", "ssl_scanner", "web_analyzer"]

    # Upsert
    config = session.exec(
        select(TenantScanConfig).where(TenantScanConfig.tenant_id == user.tenant_id)
    ).first()
    if not config:
        config = TenantScanConfig(tenant_id=user.tenant_id)

    config.auto_scan_enabled = auto_scan_enabled
    config.frequency = frequency
    config.cron_expression = cron_expr
    config.scan_types = types
    config.max_targets_per_run = max_targets_per_run
    config.max_concurrent_scans = max_concurrent_scans
    config.scan_window_start = win_start
    config.scan_window_end = win_end
    config.updated_at = datetime.utcnow()

    # Set next run when enabling for the first time
    if auto_scan_enabled and not config.next_auto_run_at:
        from yads.core.scheduler import compute_next_auto_run
        config.next_auto_run_at = compute_next_auto_run(frequency, cron_expr, datetime.utcnow())

    session.add(config)
    session.commit()
    return RedirectResponse("/tenant-settings#automation", status_code=303)


# =============================================================================
# Tenant Config Export / Import (.ytcfg)
# =============================================================================

@router.get("/export-config", response_class=StreamingResponse)
async def export_tenant_config(
    password: str,
    request: Request,
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session),
):
    """Download tenant config as encrypted .ytcfg file."""
    if not user.tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context selected")
    if not password or len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    from yads.core.tenant_config import export_tenant_config as _export
    from yads.models import Tenant

    tenant = session.get(Tenant, user.tenant_id)
    safe_name = "".join(c if c.isalnum() else "_" for c in (tenant.name if tenant else "tenant"))
    filename = f"tenant_config_{safe_name}_{__import__('datetime').datetime.utcnow().strftime('%Y%m%d')}.ytcfg"

    file_bytes = _export(user.tenant_id, password, session)

    return StreamingResponse(
        io.BytesIO(file_bytes),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/import-config/preview", response_class=HTMLResponse)
async def import_config_preview(
    request: Request,
    config_file: UploadFile = File(...),
    import_password: str = Form(...),
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session),
):
    """Parse the uploaded .ytcfg and return an HTML diff preview (HTMX fragment)."""
    if not user.tenant_id:
        return HTMLResponse('<div class="text-red-400 text-sm">No tenant context selected.</div>')

    from yads.core.tenant_config import parse_ytcfg, build_preview

    file_bytes = await config_file.read()
    try:
        config = parse_ytcfg(file_bytes, import_password)
    except ValueError as e:
        return HTMLResponse(
            f'<div class="p-3 bg-red-900/40 border border-red-700/60 rounded-lg text-red-300 text-sm">'
            f'<strong>Fehler:</strong> {e}</div>'
        )

    preview = build_preview(config, user.tenant_id, session)

    # Store parsed config in session via hidden field approach:
    # We pass the raw file + password back in the apply form via hidden inputs.
    # (Simpler than server-side session storage — file is small.)

    def _change_row(label, from_val, to_val):
        return (
            f'<tr class="border-b border-slate-800">'
            f'<td class="py-1.5 pr-4 text-slate-400 text-xs font-mono">{label}</td>'
            f'<td class="py-1.5 pr-4 text-slate-500 text-xs line-through">{from_val}</td>'
            f'<td class="py-1.5 text-emerald-400 text-xs">{to_val}</td>'
            f'</tr>'
        )

    key_rows = "".join(
        _change_row(c["field"], c["from"], c["to"])
        for c in preview.get("api_key_changes", [])
    )
    setting_rows = "".join(
        _change_row(c["field"], c.get("from", "—"), c.get("to", "—"))
        for c in preview.get("setting_changes", [])
    )

    wh = preview["webhooks"]
    pr = preview["scan_profiles"]

    html = f'''
<div id="import-preview" class="space-y-4 mt-4">
  <div class="flex items-center gap-2 text-sm text-slate-300">
    <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
    </svg>
    Datei entschlüsselt · Exportiert von <strong class="text-white ml-1">{preview["source_tenant"]}</strong>
    <span class="text-slate-600 text-xs ml-1">({preview["exported_at"][:10]})</span>
  </div>

  {"".join([
      f'<div class="overflow-x-auto bg-slate-950 rounded-lg border border-slate-800 p-3">',
      f'<p class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">API Key Änderungen</p>',
      f'<table class="w-full"><tbody>{key_rows}</tbody></table></div>'
  ]) if key_rows else ""}

  {"".join([
      f'<div class="overflow-x-auto bg-slate-950 rounded-lg border border-slate-800 p-3">',
      f'<p class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Einstellungen</p>',
      f'<table class="w-full"><tbody>{setting_rows}</tbody></table></div>'
  ]) if setting_rows else ""}

  <div class="grid grid-cols-3 gap-3 text-xs">
    <div class="bg-slate-800/50 border border-slate-700 rounded-lg p-3 text-center">
      <div class="text-slate-500 mb-1">Webhooks</div>
      <div class="text-white font-semibold">{wh["current_count"]} → {wh["import_count"]}</div>
      <div class="text-amber-400 text-[10px] mt-1">wird ersetzt</div>
    </div>
    <div class="bg-slate-800/50 border border-slate-700 rounded-lg p-3 text-center">
      <div class="text-slate-500 mb-1">Scan Profile</div>
      <div class="text-white font-semibold">{pr["current_count"]} → {pr["import_count"]}</div>
      <div class="text-amber-400 text-[10px] mt-1">wird ersetzt</div>
    </div>
    <div class="bg-slate-800/50 border border-slate-700 rounded-lg p-3 text-center">
      <div class="text-slate-500 mb-1">Scan Config</div>
      <div class="text-white font-semibold">{"Ja" if preview["scan_config"]["importing"] else "Nein"}</div>
      <div class="text-[10px] mt-1 {"text-amber-400" if preview["scan_config"]["importing"] else "text-slate-600"}">{"wird importiert" if preview["scan_config"]["importing"] else "keine Änderung"}</div>
    </div>
  </div>

  <div class="p-3 bg-amber-900/30 border border-amber-700/50 rounded-lg text-amber-300 text-xs">
    <strong>Hinweis:</strong> Webhooks und Scan-Profile werden vollständig ersetzt.
    Targets und Scan-Ergebnisse bleiben unberührt.
  </div>

  <div class="flex justify-end">
    <button type="button" onclick="doApplyConfig()"
            class="px-6 py-2 bg-emerald-700 hover:bg-emerald-600 text-white text-sm font-semibold rounded-lg transition-colors flex items-center gap-2">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
      </svg>
      Jetzt importieren
    </button>
  </div>
</div>
'''
    return HTMLResponse(html)


@router.post("/import-config/apply", response_class=HTMLResponse)
async def import_config_apply(
    request: Request,
    config_file: UploadFile = File(...),
    import_password: str = Form(...),
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session),
):
    """Apply the uploaded .ytcfg to the current tenant."""
    if not user.tenant_id:
        raise HTTPException(status_code=400, detail="No tenant context")

    from yads.core.tenant_config import parse_ytcfg, apply_config

    file_bytes = await config_file.read()
    try:
        config = parse_ytcfg(file_bytes, import_password)
        summary = apply_config(config, user.tenant_id, session)
    except ValueError as e:
        return HTMLResponse(
            f'<div class="p-4 bg-red-900/40 border border-red-700/60 rounded-lg text-red-300 text-sm">'
            f'<strong>Import fehlgeschlagen:</strong> {e}</div>'
        )

    return HTMLResponse(f'''
<div class="p-4 bg-emerald-900/30 border border-emerald-700/50 rounded-xl text-emerald-300 text-sm space-y-1">
  <div class="flex items-center gap-2 font-semibold text-emerald-200">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
    </svg>
    Konfiguration erfolgreich importiert
  </div>
  <ul class="list-disc list-inside text-xs text-emerald-400 ml-1 space-y-0.5">
    <li>{summary["webhooks_imported"]} Webhook(s) importiert</li>
    <li>{summary["profiles_imported"]} Scan-Profil(e) importiert</li>
    <li>{summary["module_overrides_imported"]} Modul-Override(s) importiert</li>
    {"<li>Scan-Automation importiert</li>" if summary["scan_config_imported"] else ""}
    {f'<li>{summary["dynamic_api_keys_imported"]} API-Schlüssel importiert</li>' if summary.get("dynamic_api_keys_imported") else ""}
  </ul>
  {_missing_addon_warning(summary.get("missing_addon_keys", []))}
  <a href="/tenant-settings" class="inline-block mt-2 text-xs text-emerald-400 hover:text-emerald-300 underline">
    Einstellungen neu laden →
  </a>
</div>
''')


def _missing_addon_warning(missing: list) -> str:
    if not missing:
        return ""
    keys = ", ".join(f"<code>{k}</code>" for k in missing)
    return (
        f'<div class="mt-3 p-2 bg-amber-900/30 border border-amber-700/40 rounded text-amber-300 text-xs">'
        f'<strong>Hinweis:</strong> Die folgenden API-Schlüssel wurden importiert, aber die zugehörigen '
        f'Add-ons sind aktuell nicht installiert: {keys}. '
        f'Die Keys werden gespeichert und aktiviert sobald die Add-ons nachinstalliert werden.'
        f'</div>'
    )


# ─── Findings Management ──────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SORT_COLS = {
    "severity": SecurityFinding.severity,
    "yf_id": SecurityFinding.yf_id,
    "domain": SecurityFinding.domain,
    "module": SecurityFinding.module,
    "status": SecurityFinding.status,
    "first_found": SecurityFinding.first_found,
    "last_seen": SecurityFinding.last_seen,
    "due_date": SecurityFinding.due_date,
    "assigned_to": SecurityFinding.assigned_to,
}

PER_PAGE = 50


@router.get("/findings", response_class=HTMLResponse)
async def tenant_findings_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner", "auditor"])),
    page: int = 1,
    sort: str = "severity",
    order: str = "asc",
    severity: Optional[str] = None,
    status: Optional[str] = None,
    module: Optional[str] = None,
    domain: Optional[str] = None,
    assigned_to: Optional[str] = None,
    overdue: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    q = select(SecurityFinding).where(SecurityFinding.tenant_id == user.tenant_id)

    if severity:
        q = q.where(SecurityFinding.severity == severity)
    if status:
        q = q.where(SecurityFinding.status == status)
    if module:
        q = q.where(SecurityFinding.module == module)
    if domain:
        q = q.where(SecurityFinding.domain.ilike(f"%{domain}%"))
    if assigned_to:
        q = q.where(SecurityFinding.assigned_to.ilike(f"%{assigned_to}%"))
    if overdue == "1":
        q = q.where(SecurityFinding.due_date < date.today(), SecurityFinding.status == "open")
    if date_from:
        try:
            q = q.where(SecurityFinding.first_found >= datetime.fromisoformat(date_from))
        except ValueError:
            pass
    if date_to:
        try:
            q = q.where(SecurityFinding.first_found <= datetime.fromisoformat(date_to + "T23:59:59"))
        except ValueError:
            pass

    # Count for pagination
    count_q = select(func.count()).select_from(q.subquery())
    total = session.exec(count_q).one()
    total_pages = max(1, math.ceil(total / PER_PAGE))
    page = max(1, min(page, total_pages))

    # Sort
    sort_col = _SORT_COLS.get(sort, SecurityFinding.severity)
    if sort == "severity":
        # Custom severity order via CASE — approximate with string sort fallback
        from sqlalchemy import case as sa_case
        sev_case = sa_case(
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
            value=SecurityFinding.severity,
            else_=99,
        )
        q = q.order_by(sev_case if order == "asc" else sev_case.desc())
    elif order == "desc":
        q = q.order_by(sort_col.desc())
    else:
        q = q.order_by(sort_col.asc())

    q = q.offset((page - 1) * PER_PAGE).limit(PER_PAGE)
    findings = session.exec(q).all()

    # Distinct modules for filter dropdown
    mods_q = select(SecurityFinding.module).where(
        SecurityFinding.tenant_id == user.tenant_id
    ).distinct()
    modules = sorted(r for r in session.exec(mods_q).all() if r)

    today = date.today()
    rows = []
    for sf in findings:
        rows.append({
            "sf": sf,
            "due_overdue": bool(sf.due_date and sf.due_date < today and sf.status == "open"),
        })

    return templates.TemplateResponse("tenant_findings.html", {
        "request": request,
        "user": user,
        "rows": rows,
        "total": total,
        "page": page,
        "total_pages": total_pages,
        "per_page": PER_PAGE,
        "sort": sort,
        "order": order,
        "filter_severity": severity or "",
        "filter_status": status or "",
        "filter_module": module or "",
        "filter_domain": domain or "",
        "filter_assigned_to": assigned_to or "",
        "filter_overdue": overdue or "",
        "filter_date_from": date_from or "",
        "filter_date_to": date_to or "",
        "modules": modules,
    })


@router.get("/findings/export")
async def export_findings_csv(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner", "auditor"])),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    module: Optional[str] = None,
    domain: Optional[str] = None,
    assigned_to: Optional[str] = None,
    overdue: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    q = select(SecurityFinding).where(SecurityFinding.tenant_id == user.tenant_id)
    if severity:
        q = q.where(SecurityFinding.severity == severity)
    if status:
        q = q.where(SecurityFinding.status == status)
    if module:
        q = q.where(SecurityFinding.module == module)
    if domain:
        q = q.where(SecurityFinding.domain.ilike(f"%{domain}%"))
    if assigned_to:
        q = q.where(SecurityFinding.assigned_to.ilike(f"%{assigned_to}%"))
    if overdue == "1":
        q = q.where(SecurityFinding.due_date < date.today(), SecurityFinding.status == "open")
    if date_from:
        try:
            q = q.where(SecurityFinding.first_found >= datetime.fromisoformat(date_from))
        except ValueError:
            pass
    if date_to:
        try:
            q = q.where(SecurityFinding.first_found <= datetime.fromisoformat(date_to + "T23:59:59"))
        except ValueError:
            pass

    findings = session.exec(q.order_by(SecurityFinding.severity)).all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["YF-ID", "Domain", "Module", "Issue", "Severity", "Status",
                "First Found", "Last Seen", "Due Date", "Assigned To",
                "Ticket Ref", "Note", "Reopened Count"])
    for sf in findings:
        w.writerow([
            sf.yf_id, sf.domain, sf.module, sf.issue, sf.severity, sf.status,
            sf.first_found.strftime("%Y-%m-%d") if sf.first_found else "",
            sf.last_seen.strftime("%Y-%m-%d") if sf.last_seen else "",
            sf.due_date.strftime("%Y-%m-%d") if sf.due_date else "",
            sf.assigned_to or "", sf.ticket_ref or "",
            sf.status_note or "", sf.reopened_count,
        ])
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings_export.csv"},
    )


# BYOK API-key health check (#19). Real validation for the providers with a
# cheap, well-known "who am I" endpoint; a generic presence check otherwise
# (better than nothing, honest about the difference — see status message).
_KEY_TEST_ENDPOINTS = {
    "shodan_api_key": "https://api.shodan.io/api-info?key={key}",
    "virustotal_api_key": "https://www.virustotal.com/api/v3/users/current",
    "hibp_api_key": "https://haveibeenpwned.com/api/v3/subscription/status",
}


@router.post("/api-keys/test/{key_name}")
async def test_api_key(
    key_name: str,
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
    session: Session = Depends(get_session),
):
    """Test a BYOK key against its provider's API (#19) and persist the
    result via the shared health-check helper (Baustein 2, Welle 0)."""
    from yads.models import TenantApiKey
    from yads.core.integration_health import record_health_check

    row = session.exec(
        select(TenantApiKey).where(TenantApiKey.tenant_id == user.tenant_id, TenantApiKey.key_name == key_name)
    ).first()
    if not row or not row.value:
        raise HTTPException(status_code=404, detail="Key not configured")

    ok, message = False, "No live test available for this provider — key is present."
    endpoint = _KEY_TEST_ENDPOINTS.get(key_name)
    if endpoint:
        try:
            import requests
            headers = {}
            url = endpoint
            if key_name == "shodan_api_key":
                url = endpoint.format(key=row.value)
            elif key_name == "virustotal_api_key":
                headers = {"x-apikey": row.value}
            elif key_name == "hibp_api_key":
                headers = {"hibp-api-key": row.value}
            resp = requests.get(url, headers=headers, timeout=10)
            ok = resp.status_code < 400
            message = f"HTTP {resp.status_code}" if not ok else "Key is valid"
        except Exception as e:
            ok, message = False, f"Request failed: {e}"
    else:
        ok = True  # can't verify, don't falsely mark it failed

    record_health_check(session, row, ok, message)
    return {"key_name": key_name, "status": "ok" if ok else "failed", "message": message}


@router.post("/llm/test")
async def test_llm_connection(
    llm_provider: str = Form(...),
    llm_api_url: Optional[str] = Form(None),
    llm_api_key: Optional[str] = Form(None),
    llm_model: Optional[str] = Form(None),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
):
    """
    Live-test the LLM provider settings currently in the form (not necessarily
    saved yet) with a minimal completion call, mirroring the BYOK
    /api-keys/test/{key_name} pattern above but for the LLM config block.
    """
    from yads.core.llm_service import _run_sync, _DEFAULT_MODELS, _DEFAULT_TIMEOUT

    provider = (llm_provider or "").strip().lower()
    if not provider or provider == "disabled":
        return {"status": "failed", "message": "No provider selected."}

    model = (llm_model or "").strip() or _DEFAULT_MODELS.get(provider, "")
    try:
        reply = _run_sync(
            provider,
            (llm_api_key or "").strip(),
            (llm_api_url or "").strip(),
            model,
            "Respond with exactly one word: OK",
            min(_DEFAULT_TIMEOUT, 20),
        )
        ok = bool(reply and reply.strip())
        message = f"Connected — model responded ({len(reply.strip())} chars)." if ok else "Provider returned an empty response."
        return {"status": "ok" if ok else "failed", "message": message}
    except Exception as e:
        # Don't echo the raw exception (may contain response bodies/headers
        # from an arbitrary tenant-supplied URL) back to the client -- this
        # endpoint is otherwise a fast, convenient SSRF oracle for a
        # malicious tenant_admin to probe internal hosts. Log details
        # server-side, return only the exception class to the UI.
        logger.warning(f"[LLM test] Connection test failed for tenant {user.tenant_id}: {type(e).__name__}: {e}")
        return {"status": "failed", "message": f"Connection failed ({type(e).__name__}) — check provider settings."}


@router.get("/llm/ollama-models")
async def list_ollama_models(
    llm_api_url: str,
    llm_provider: str = "ollama",
    llm_api_key: str = "",
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
):
    """
    Fetch the available-model list for the LLM settings 'select model'
    dropdown. Ollama uses its native /api/tags; openai/custom (any
    OpenAI-compatible endpoint, e.g. an internal llmproxy/Ollama with its
    OpenAI-compat shim enabled) uses the standard /v1/models endpoint.
    Despite the route name (kept for backward compat with the existing
    frontend call), this now covers all providers except anthropic (which
    has no public unauthenticated-discovery model-list endpoint).
    """
    from yads.core.llm_service import _validate_api_url
    import requests

    provider = (llm_provider or "ollama").strip().lower()
    api_key = (llm_api_key or "").strip()

    if provider == "openai":
        base_url = "https://api.openai.com"
    else:
        base_url = (llm_api_url or "").strip() or "http://ollama:11434"

    try:
        _validate_api_url(base_url)
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        if provider == "ollama":
            # allow_redirects=False: an initially-valid URL could otherwise 302
            # to a blocked target (e.g. cloud metadata) and bypass the check above.
            resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=10, allow_redirects=False)
            resp.raise_for_status()
            models = [m.get("name") for m in resp.json().get("models", []) if m.get("name")]
        else:
            resp = requests.get(f"{base_url.rstrip('/')}/v1/models", headers=headers, timeout=10, allow_redirects=False)
            resp.raise_for_status()
            models = [m.get("id") for m in resp.json().get("data", []) if m.get("id")]
        return {"status": "ok", "models": sorted(models)}
    except Exception as e:
        # Same oracle concern as /llm/test above -- don't reflect raw
        # exception/response content for an arbitrary tenant-supplied URL.
        logger.warning(f"[LLM models] Fetch failed for tenant {user.tenant_id} ({provider}): {type(e).__name__}: {e}")
        return {"status": "failed", "message": f"Could not reach provider ({type(e).__name__}).", "models": []}
