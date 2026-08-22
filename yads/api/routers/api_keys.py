from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from sqlmodel import Session, select
from typing import List, Optional
from datetime import datetime

from yads.models import User, APIKey
from yads.auth.deps import get_db_session, get_current_user, RoleChecker
from yads.auth.security import generate_api_key

router = APIRouter(prefix="/api-keys", tags=["API Keys"])

# Management permissions: Admins and Tenant Admins
manager_only = RoleChecker(["admin", "tenant_admin"])

VALID_SCOPES = {"read", "write", "scan_execute", "provision_tenant"}

@router.post("/", status_code=status.HTTP_201_CREATED, dependencies=[Depends(manager_only)])
async def create_key(
    name: str,
    scopes: List[str] = None,
    expires_in_days: Optional[int] = None,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """
    Generate a new API Key for the current tenant.
    The plain key is returned ONLY once.

    scopes: list of permissions — valid values: read, write, scan_execute
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

    plain_key, prefix, key_hash = generate_api_key()

    expires_at = None
    if expires_in_days:
        from datetime import timedelta
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    new_key = APIKey(
        tenant_id=current_user.tenant_id,
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
        "api_key": plain_key,  # VITAL: Show this only now
        "prefix": new_key.key_prefix,
        "expires_at": new_key.expires_at,
        "msg": "Store this key safely. It will not be shown again."
    }

@router.get("/", dependencies=[Depends(manager_only)])
async def list_keys(
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """List all API keys for the current tenant."""
    statement = select(APIKey).where(APIKey.tenant_id == current_user.tenant_id)
    keys = session.exec(statement).all()
    
    return [
        {
            "id": k.id,
            "name": k.name,
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
    """Revoke (delete) an API key."""
    key = session.get(APIKey, key_id)
    
    if not key or key.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="API Key not found")
        
    session.delete(key)
    session.commit()
    
    return {"msg": "API Key revoked successfully"}
