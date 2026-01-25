from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from typing import Optional

from yads.database import get_session
from yads.models import User, Tenant, Webhook
from yads.auth.deps import RoleChecker, get_current_user
from yads.config import settings
from yads.utils.license_deps import require_feature

router = APIRouter(prefix="/tenant-settings", tags=["tenant-settings"])
templates = Jinja2Templates(directory="yads/api/templates")

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
    
    return templates.TemplateResponse("tenant_settings.html", {
        "request": request,
        "tenant": tenant,
        "webhooks": webhooks,
        "user": user
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
    session_timeout_minutes: Optional[int] = Form(None),
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session)
):
    if not user.tenant_id:
        return RedirectResponse("/tenant-settings", status_code=303)

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
    session: Session = Depends(get_session),
    _ = Depends(require_feature("webhooks"))
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
    session: Session = Depends(get_session),
    _ = Depends(require_feature("webhooks"))
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
    session: Session = Depends(get_session),
    _ = Depends(require_feature("webhooks"))
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
