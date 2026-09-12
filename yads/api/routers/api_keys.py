from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Query
from sqlmodel import Session, select
from typing import List, Optional
from datetime import datetime

from yads.models import User, APIKey
from yads.auth.deps import get_db_session, get_current_user, RoleChecker
from yads.auth.security import generate_api_key

router = APIRouter(prefix="/api-keys", tags=["API Keys"])

# Management permissions: Admins and Tenant Admins
manager_only = RoleChecker(["admin", "tenant_admin"])

VALID_SCOPES = {"read", "write", "scan_execute", "provision_tenant", "destructive"}

@router.post("/", status_code=status.HTTP_201_CREATED, dependencies=[Depends(manager_only)])
async def create_key(
    name: str,
    scopes: List[str] = Query(None),
    expires_in_days: Optional[int] = None,
    tenant_id: Optional[int] = None,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """
    Generate a new API Key. The plain key is returned ONLY once.

    scopes: list of permissions — valid values: read, write, scan_execute

    tenant_id names the tenant the key belongs to. A Platform Admin has no
    tenant of their own, so they must name one: a NULL-tenant key is refused
    by require_tenant_scoped_key on every /api/v1 route, i.e. it would be
    issued dead. A tenant admin may omit it (their own tenant is used) and
    may not name a different one.
    """
    # Validate and sanitize requested scopes
    requested = set(scopes) if scopes else {"read"}
    invalid = requested - VALID_SCOPES
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid scopes: {sorted(invalid)}. Valid: {sorted(VALID_SCOPES)}")
    if not requested:
        raise HTTPException(status_code=400, detail="At least one scope must be selected.")

    # provision_tenant lets a key create arbitrary new tenants via POST /tenants/provision —
    # restrict granting it to Platform Admins so a tenant_admin can't self-escalate.
    if "provision_tenant" in requested and current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only Platform Admins can create API keys with the 'provision_tenant' scope.",
        )

    from yads.models import Tenant

    if current_user.tenant_id is None:
        if tenant_id is None:
            raise HTTPException(
                status_code=400,
                detail="tenant_id is required: a key without a tenant is rejected by every /api/v1 route.",
            )
        if not session.get(Tenant, tenant_id):
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
        ziel_tenant = tenant_id
    else:
        # Without this check the parameter would be a privilege escalation:
        # a tenant admin could issue themselves a key for another tenant's data.
        if tenant_id is not None and tenant_id != current_user.tenant_id:
            raise HTTPException(
                status_code=403,
                detail="Only Platform Admins can create API keys for another tenant.",
            )
        ziel_tenant = current_user.tenant_id

    plain_key, prefix, key_hash = generate_api_key()

    expires_at = None
    if expires_in_days:
        from datetime import timedelta
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    new_key = APIKey(
        tenant_id=ziel_tenant,
        name=name,
        key_prefix=prefix,
        key_hash=key_hash,
        expires_at=expires_at,
        scopes=sorted(requested)
    )
    
    session.add(new_key)
    session.commit()
    session.refresh(new_key)

    return {
        "id": new_key.id,
        "name": new_key.name,
        "tenant_id": new_key.tenant_id,
        "api_key": plain_key,  # VITAL: Show this only now
        "prefix": new_key.key_prefix,
        "expires_at": new_key.expires_at,
        "scopes": new_key.scopes,
        "msg": "Store this key safely. It will not be shown again."
    }

@router.get("/", dependencies=[Depends(manager_only)])
async def list_keys(
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """List API keys — every tenant's for a Platform Admin, the own tenant's
    otherwise. A Platform Admin has tenant_id=NULL, so filtering by their own
    tenant returned an empty list and made the management page useless.

    scopes is part of the response: without it the page shows keys whose
    permissions nobody can see, which is how a key missing 'destructive' went
    unnoticed until it failed in use.
    """
    from yads.models import Tenant

    statement = select(APIKey)
    if current_user.tenant_id is not None:
        statement = statement.where(APIKey.tenant_id == current_user.tenant_id)
    keys = session.exec(statement).all()

    tenant_namen = {t.id: t.name for t in session.exec(select(Tenant)).all()}

    return [
        {
            "id": k.id,
            "name": k.name,
            "tenant_id": k.tenant_id,
            "tenant_name": tenant_namen.get(k.tenant_id),
            "scopes": k.scopes or [],
            "prefix": k.key_prefix,
            "created_at": k.created_at,
            "last_used_at": k.last_used_at,
            "expires_at": k.expires_at,
            "is_active": k.is_active
        }
        for k in keys
    ]

@router.delete("/{key_id}", dependencies=[Depends(manager_only)])
async def delete_key(
    key_id: int,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """Revoke (delete) an API key. A Platform Admin may revoke any tenant's
    key -- comparing against their NULL tenant used to 404 on every key, so
    they could not clean up the keys they are expected to manage."""
    key = session.get(APIKey, key_id)

    if not key or (current_user.tenant_id is not None and key.tenant_id != current_user.tenant_id):
        raise HTTPException(status_code=404, detail="API Key not found")
        
    session.delete(key)
    session.commit()
    
    return {"msg": "API Key revoked successfully"}
