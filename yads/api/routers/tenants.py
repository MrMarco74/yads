
import base64
import re
import secrets
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import selectinload
from sqlmodel import Session, select, func, text

from yads.database import get_session as get_db_session
from yads.models import Tenant, User, Target, APIKey
from yads.auth.deps import PlatformAdminChecker, get_current_user_html, RoleChecker, RequireScope
from yads.auth.security import get_password_hash, generate_api_key

router = APIRouter(prefix="/tenants", tags=["tenants"])
from yads.api.templating import templates

# Inject Globals from main setup usually, but we need settings
from yads.config import settings
from datetime import datetime
templates.env.globals['settings'] = settings
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

@router.get("/", response_class=HTMLResponse, dependencies=[Depends(RoleChecker(["admin"]))])
async def list_tenants(request: Request, session: Session = Depends(get_db_session), user: User = Depends(get_current_user_html)):
    tenants = session.exec(
        select(Tenant)
        .options(selectinload(Tenant.users), selectinload(Tenant.targets), selectinload(Tenant.allowed_users))
        .order_by(Tenant.id)
    ).all()
    
    all_users = session.exec(select(User).order_by(User.username)).all()
    
    return templates.TemplateResponse("tenants.html", {
        "request": request, 
        "tenants": tenants, 
        "user": user,
        "all_users": all_users
    })

class TenantProvisionRequest(BaseModel):
    name: str
    admin_username: Optional[str] = None
    admin_email: Optional[str] = None

    # Optional initial config bundle, reusing the existing .ytcfg
    # export/import mechanism (yads/core/tenant_config.py) instead of a
    # bespoke field list: BYOK keys, LLM config, report branding, webhooks,
    # scan automation and scan profiles all travel in one already-encrypted
    # artifact. Build one with GET /tenant-settings/export-config on any
    # tenant (or a throwaway one) and pass its bytes/password through here.
    # ytcfg stays ciphertext end-to-end -- decrypted only in-memory below.
    ytcfg_b64: Optional[str] = None
    ytcfg_password: Optional[str] = None


def _slugify_username(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return f"{slug or 'tenant'}-admin"


@router.post("/provision", status_code=status.HTTP_201_CREATED, dependencies=[Depends(RequireScope("provision_tenant"))])
async def provision_tenant(
    body: TenantProvisionRequest,
    session: Session = Depends(get_db_session),
):
    """
    Create a new tenant with its initial tenant_admin user and API key.

    Machine-to-machine endpoint (X-API-Key auth, 'provision_tenant' scope) meant to be
    called from automation (e.g. an Ansible playbook), not the browser UI.

    All generated secrets (admin password, API key) are returned ONLY in this response.
    Nothing is logged, printed, or persisted anywhere in plaintext.
    """
    existing = session.exec(select(Tenant).where(Tenant.name == body.name)).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Tenant '{body.name}' already exists")

    username = body.admin_username or _slugify_username(body.name)
    if session.exec(select(User).where(User.username == username)).first():
        raise HTTPException(status_code=409, detail=f"Username '{username}' already taken")

    if bool(body.ytcfg_b64) != bool(body.ytcfg_password):
        raise HTTPException(status_code=400, detail="ytcfg_b64 and ytcfg_password must be provided together")

    config = None
    if body.ytcfg_b64:
        from yads.core.tenant_config import parse_ytcfg
        try:
            ytcfg_bytes = base64.b64decode(body.ytcfg_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="ytcfg_b64 is not valid base64")
        try:
            config = parse_ytcfg(ytcfg_bytes, body.ytcfg_password)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid .ytcfg: {e}")

    tenant = Tenant(name=body.name)
    session.add(tenant)
    session.flush()  # assign tenant.id without committing yet

    plain_password = secrets.token_urlsafe(24)
    admin_user = User(
        username=username,
        email=body.admin_email,
        password_hash=get_password_hash(plain_password),
        role="tenant_admin",
        tenant_id=tenant.id,
        force_password_change=True,
    )
    session.add(admin_user)

    plain_key, prefix, key_hash = generate_api_key()
    api_key = APIKey(
        tenant_id=tenant.id,
        name="Initial provisioning key",
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=["read", "write"],
    )
    session.add(api_key)
    session.flush()

    import_summary = None
    if config is not None:
        from yads.core.tenant_config import apply_config
        # apply_config() commits the session itself -- this is the single
        # commit point for tenant + admin_user + api_key + imported config,
        # so a bad/corrupt ytcfg rolls back the whole provision atomically.
        import_summary = apply_config(config, tenant.id, session)
    else:
        session.commit()

    session.refresh(tenant)
    session.refresh(admin_user)
    session.refresh(api_key)

    return {
        "tenant_id": tenant.id,
        "tenant_name": tenant.name,
        "admin_username": admin_user.username,
        "admin_password": plain_password,  # VITAL: shown only now, forced reset on first login
        "api_key": plain_key,              # VITAL: shown only now
        "api_key_prefix": api_key.key_prefix,
        "config_imported": import_summary,
        "msg": "Store these credentials now. They will not be shown again.",
    }


@router.post("/add", dependencies=[Depends(RoleChecker(["admin"]))])
async def add_tenant(request: Request, name: str = Form(...), session: Session = Depends(get_db_session)):
    try:
        tenant = Tenant(name=name)
        session.add(tenant)
        session.commit()
        return RedirectResponse(url="/tenants?msg=Tenant created", status_code=303)
    except Exception as e:
        session.rollback()
        return RedirectResponse(url=f"/tenants?error={str(e)}", status_code=303)

@router.post("/update", dependencies=[Depends(RoleChecker(["admin"]))])
async def update_tenant(
    tenant_id: int = Form(...),
    name: str = Form(...),
    osint_enabled: bool = Form(False),
    osint_quota: int = Form(0),
    osint_cost: float = Form(0.0),
    max_targets: int = Form(500),
    session: Session = Depends(get_db_session)
):
    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        return RedirectResponse(url="/tenants/?error=Not+found", status_code=303)
    
    tenant.name = name
    tenant.osint_enabled = osint_enabled
    tenant.osint_quota_max = osint_quota
    tenant.osint_cost_per_search = osint_cost
    tenant.max_targets = max(1, max_targets)
    
    session.add(tenant)
    session.commit()
    return RedirectResponse(url="/tenants/?msg=Tenant+updated", status_code=303)

@router.post("/users/update", dependencies=[Depends(RoleChecker(["admin"]))])
async def update_tenant_users(
    tenant_id: int = Form(...),
    user_ids: List[int] = Form(default=[]),
    session: Session = Depends(get_db_session)
):
    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        return RedirectResponse(url="/tenants/?error=Not+found", status_code=303)
    
    # Get users
    if user_ids:
        users = session.exec(select(User).where(User.id.in_(user_ids))).all()
    else:
        users = []
        
    tenant.allowed_users = users
    session.add(tenant)
    session.commit()
    
    return RedirectResponse(url=f"/tenants/?msg=Users+assigned+to+{tenant.name}", status_code=303)

@router.post("/delete", dependencies=[Depends(RoleChecker(["admin"]))])
async def delete_tenant(tenant_id: int = Form(...), session: Session = Depends(get_db_session)):
    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        return RedirectResponse(url="/tenants/?error=Not+found", status_code=303)
        
    # Cascade Delete?
    # Delete users, targets, results linked to tenant.
    # WARN: Destructive.
    
    # 1. Delete dependent data linked to Targets (ChangeEvents, ScanResults, Schedules, ModuleStates)
    # 1a. ChangeEvents (sub-dependency of ScanResult)
    session.execute(text("DELETE FROM changeevent WHERE scan_result_id IN (SELECT id FROM scanresult WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid))"), {"tid": tenant_id})

    # 1b. ScanResults & ModuleStates & Schedules & every other table with a
    # target_id FK (this list must stay in sync with _perform_bulk_delete_from_db
    # and delete_target in api/routers/targets.py -- all three drifted apart
    # before, causing a ForeignKeyViolation 500 whenever a target had rows in
    # a table missing from whichever list was used)
    session.execute(text("DELETE FROM scanresult WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})
    session.execute(text("DELETE FROM modulestate WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})
    session.execute(text("DELETE FROM scanschedule WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})
    session.execute(text("DELETE FROM osintintelligence WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})
    session.execute(text("DELETE FROM compliancetargetstatus WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})
    session.execute(text("DELETE FROM httptraffic WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})
    session.execute(text("DELETE FROM remediationtask WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})
    session.execute(text("DELETE FROM workertask WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})
    session.execute(text("DELETE FROM securityfinding WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})
    session.execute(text("DELETE FROM baseline_snapshot WHERE target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})
    session.execute(text("UPDATE discoverycandidate SET source_target_id = NULL WHERE source_target_id IN (SELECT id FROM target WHERE tenant_id = :tid)"), {"tid": tenant_id})

    # 1c. Targets
    session.execute(text("DELETE FROM target WHERE tenant_id = :tid"), {"tid": tenant_id})

    # 2. Delete Tenant Resources (Webhooks, User Links, Trends)
    session.execute(text("DELETE FROM webhook WHERE tenant_id = :tid"), {"tid": tenant_id})
    session.execute(text("DELETE FROM usertenantlink WHERE tenant_id = :tid"), {"tid": tenant_id})
    session.execute(text("DELETE FROM securitytrend WHERE tenant_id = :tid"), {"tid": tenant_id})

    # 3. Delete Users (excluding Platform Admins)
    session.execute(text("DELETE FROM \"user\" WHERE tenant_id = :tid AND role != 'admin'"), {"tid": tenant_id})
    
    # 3. Delete Tenant
    session.delete(tenant)
    session.commit()
    
    return RedirectResponse(url="/tenants/?msg=Tenant+deleted", status_code=303)

