from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse
import markdown
import os
import aiofiles
from typing import Optional

from yads.auth.deps import get_current_user_html_optional, get_current_user_html
from yads.models import User

router = APIRouter(
    prefix="/help",
    tags=["help"]
)

from yads.api.templating import templates

def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

@router.get("/", response_class=HTMLResponse)
async def view_user_guide(
    request: Request, 
    user: User = Depends(get_current_user_html_optional)
):
    """
    Renders the User Guide from USER_GUIDE.md
    """
    guide_path = "USER_GUIDE.md"
    
    if not os.path.exists(guide_path):
        # Fallback for Docker environment if path differs, or just error
        # Try adjusting path relative to root if needed.
        # Fallback for Docker environment
        if os.path.exists("/app/USER_GUIDE.md"):
            guide_path = "/app/USER_GUIDE.md"
        # Fallback for dev environment (relative to yads/api/routers/../../..)
        elif os.path.exists("../../USER_GUIDE.md"):
             guide_path = "../../USER_GUIDE.md"
        elif os.path.exists("../../../USER_GUIDE.md"):
             guide_path = "../../../USER_GUIDE.md"
        else:
             # Last resort: Try absolute path in typical dev location
             dev_path = "/home/mrmarco/Documents/gitlab/yads/USER_GUIDE.md"
             if os.path.exists(dev_path):
                 guide_path = dev_path
             else:
                return HTMLResponse("<h1>Error: USER_GUIDE.md not found</h1><p>Please insure the file exists in the application root.</p>", status_code=404)
            
    async with aiofiles.open(guide_path, mode='r') as f:
        content = await f.read()
        
    # Convert Markdown to HTML
    html_content = markdown.markdown(
        content, 
        extensions=['fenced_code', 'tables', 'toc']
    )
    
    from yads.config import settings
    

    return templates.TemplateResponse("help.html", {
        "request": request,
        "content": html_content,
        "user": user,
        "settings": settings  # Fix: Pass settings for base.html footer
    })

@router.get("/about", response_class=HTMLResponse)
async def view_about(request: Request, user: User = Depends(get_current_user_html_optional)):
    """About page with credits and acknowledgements."""
    from yads.config import settings
    return templates.TemplateResponse("about.html", {
        "request": request,
        "user": user,
        "settings": settings
    })


@router.get("/roadmap", response_class=HTMLResponse)
async def view_roadmap(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Renders the Roadmap page.
    """
    from yads.config import settings
    return templates.TemplateResponse("roadmap.html", {"request": request, "user": user, "settings": settings})

@router.get("/bug-report", response_class=HTMLResponse)
async def view_bug_report(request: Request, user: User = Depends(get_current_user_html_optional)):
    """Bug report page with editable form + secure upload."""
    from yads.config import settings
    from yads.database import get_session as _get_session
    from sqlmodel import Session
    from yads.core.license import get_customer_id

    # Check if license has report signing capability
    has_upload = False
    try:
        with Session(__import__('yads.database', fromlist=['engine']).engine) as session:
            has_upload = get_customer_id(session) is not None
    except Exception:
        pass

    return templates.TemplateResponse("bug_report.html", {
        "request": request,
        "user": user,
        "settings": settings,
        "has_upload": has_upload,
    })


@router.post("/bug-report/upload", response_class=HTMLResponse)
async def upload_bug_report(
    request: Request,
    user: User = Depends(get_current_user_html),
    description: str = Form(""),
    affected_url: str = Form(""),
    attach_errors: Optional[str] = Form(None),
    attach_alerts: Optional[str] = Form(None),
):
    """
    Encrypt + sign bug report and POST to support portal.
    Returns HTMX fragment: success card with report ID, or error banner.
    """
    from datetime import datetime, timezone
    from yads.config import settings
    from yads.core.bug_report_crypto import build_report_upload
    from yads.core.license import get_customer_id, get_report_signing_key, get_customer_name
    from sqlmodel import Session
    import httpx
    import importlib

    engine = importlib.import_module('yads.database').engine

    def _err(msg: str) -> HTMLResponse:
        return HTMLResponse(f'''
<div id="upload-result" class="mt-4 p-4 bg-red-900/30 border border-red-700/50 rounded-xl
     text-red-300 text-sm flex items-start gap-3">
  <svg class="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
          d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
  </svg>
  <div><strong class="text-red-400">Upload fehlgeschlagen:</strong> {msg}</div>
</div>''')

    # Load license keys
    try:
        with Session(engine) as session:
            customer_id = get_customer_id(session)
            customer_name = get_customer_name(session) or "Unknown"
            signing_key = get_report_signing_key(session)
    except Exception as e:
        return _err(f"Lizenzfehler: {e}")

    if not customer_id or not signing_key:
        return _err("Lizenz enthält keinen Report-Signing-Key. Bitte Lizenz aktualisieren.")

    # Collect tenant name
    tenant_name = "N/A"
    try:
        if user.tenant_id:
            from sqlmodel import Session as S2
            from yads.models import Tenant
            with S2(engine) as s:
                t = s.get(Tenant, user.tenant_id)
                if t:
                    tenant_name = t.name
    except Exception:
        pass

    # Collect optional auto-data
    scan_errors: list = []
    system_alerts: list = []

    if attach_errors == "on":
        try:
            from yads.core.watcher import get_scan_errors_for_tenant
            import redis as _redis
            rc = _redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
            if user.tenant_id:
                scan_errors = (get_scan_errors_for_tenant(rc, user.tenant_id) or [])[-10:]
        except Exception:
            pass

    if attach_alerts == "on":
        try:
            import json, redis as _redis
            rc = _redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
            raw = rc.get("yads:alerts:active")
            if raw:
                for a in __import__('json').loads(raw):
                    system_alerts.append(f"[{a.get('severity','?').upper()}] {a.get('check_name','?')}: {a.get('message','')}")
        except Exception:
            pass

    report_dict = {
        "description": description.strip(),
        "affected_url": affected_url.strip(),
        "yads_version": settings.VERSION,
        "tenant_name": tenant_name,
        "username": user.username,
        "browser": request.headers.get("user-agent", "")[:200],
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "scan_errors": scan_errors,
        "system_alerts": system_alerts,
    }

    # Encrypt + sign
    try:
        upload_payload = build_report_upload(
            report_dict=report_dict,
            customer_id=customer_id,
            customer_name=customer_name,
            tenant_name=tenant_name,
            yads_version=settings.VERSION,
            signing_key=signing_key,
            dev_public_key_b64=settings.SUPPORT_DEV_PUBLIC_KEY,
        )
    except Exception as e:
        return _err(f"Verschlüsselungsfehler: {e}")

    # POST to support portal
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{settings.SUPPORT_PORTAL_URL}/api/report",
                json=upload_payload,
                headers={"Content-Type": "application/json"},
            )
        if resp.status_code == 200:
            data = resp.json()
            report_id = data.get("report_id", "?")
        else:
            return _err(f"Support-Portal antwortete mit HTTP {resp.status_code}: {resp.text[:200]}")
    except httpx.TimeoutException:
        return _err("Support-Portal nicht erreichbar (Timeout). Bitte E-Mail-Fallback nutzen.")
    except Exception as e:
        return _err(f"Netzwerkfehler: {e}")

    return HTMLResponse(f'''
<div id="upload-result" class="mt-4 p-5 bg-emerald-900/30 border border-emerald-700/50 rounded-xl">
  <div class="flex items-center gap-3 mb-3">
    <svg class="w-6 h-6 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
    </svg>
    <span class="text-emerald-300 font-semibold text-base">Report erfolgreich gesendet</span>
  </div>
  <p class="text-slate-300 text-sm mb-1">Ihre Report-Nummer:</p>
  <p class="text-2xl font-mono font-bold text-white tracking-wider">{report_id}</p>
  <p class="text-slate-400 text-xs mt-3">
    Bitte verwenden Sie diese Nummer in der weiteren Kommunikation mit dem Support.
    Ihr Report wurde verschlüsselt übertragen und wird vertraulich behandelt.
  </p>
</div>''')


@router.get("/sbom", response_class=HTMLResponse)
async def view_sbom(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Renders the Software BOM page.
    """
    import json
    # Try different locations for sbom.json
    possible_paths = ["sbom.json", "/app/sbom.json", "../../sbom.json"]
    sbom_data = None
    
    for p in possible_paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    sbom_data = json.load(f)
                break
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to load sbom: {e}")
                continue
                
    from yads.config import settings
    return templates.TemplateResponse("help/sbom.html", {
        "request": request, 
        "user": user, 
        "settings": settings,
        "sbom": sbom_data
    })

@router.get("/cbom", response_class=HTMLResponse)
async def view_cbom(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Renders the Cryptography BOM page.
    """
    import json
    # Try different locations for cbom.json
    possible_paths = ["cbom.json", "/app/cbom.json", "../../cbom.json"]
    cbom_data = None
    
    for p in possible_paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    cbom_data = json.load(f)
                break
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to load cbom: {e}")
                continue
                
    from yads.config import settings
    return templates.TemplateResponse("help/cbom.html", {
        "request": request, 
        "user": user, 
        "settings": settings,
        "cbom": cbom_data
    })

@router.get("/sbom/download", response_class=JSONResponse)
async def download_sbom(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Downloads the SBOM in CycloneDX JSON format.
    """
    import json

    
    # Try different locations for sbom.json
    possible_paths = ["sbom.json", "/app/sbom.json", "../../sbom.json"]
    
    for p in possible_paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    sbom_data = json.load(f)
                return JSONResponse(
                    content=sbom_data,
                    headers={"Content-Disposition": "attachment; filename=sbom_cyclonedx.json"}
                )
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to load sbom for download: {e}")
                continue
    
    raise HTTPException(status_code=404, detail="SBOM file not found")

@router.get("/cbom/download", response_class=JSONResponse)
async def download_cbom(request: Request, user: User = Depends(get_current_user_html_optional)):
    """
    Downloads the CBOM in CycloneDX JSON format.
    """
    import json

    
    # Try different locations for cbom.json
    possible_paths = ["cbom.json", "/app/cbom.json", "../../cbom.json"]
    
    for p in possible_paths:
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    cbom_data = json.load(f)
                return JSONResponse(
                    content=cbom_data,
                    headers={"Content-Disposition": "attachment; filename=cbom_cyclonedx.json"}
                )
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to load cbom for download: {e}")
                continue
    
    raise HTTPException(status_code=404, detail="CBOM file not found")
