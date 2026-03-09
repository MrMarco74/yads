"""
Developer Portal — API key management UI + code examples.

Routes:
  GET  /developer              → Portal page (key list + code examples)
  POST /developer/keys/create  → Create new API key
  POST /developer/keys/{id}/revoke → Revoke key
"""
import logging
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import RoleChecker, get_current_user_html
from yads.database import get_session
from yads.models import APIKey, User

logger = logging.getLogger(__name__)
router = APIRouter()

_manager = RoleChecker(["admin", "tenant_admin"])


def _generate_api_key() -> tuple[str, str, str]:
    """Return (plain_key, key_prefix, key_hash)."""
    plain = "yads_" + secrets.token_urlsafe(32)
    prefix = plain[:12]
    key_hash = hashlib.sha256(plain.encode()).hexdigest()
    return plain, prefix, key_hash


@router.get("/developer", response_class=HTMLResponse)
async def developer_portal(
    request: Request,
    msg: str = "",
    error: str = "",
    new_key: str = "",
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    keys = session.exec(
        select(APIKey).where(APIKey.tenant_id == user.tenant_id)
    ).all()
    return templates.TemplateResponse("developer.html", {
        "request": request,
        "user": user,
        "keys": keys,
        "msg": msg,
        "error": error,
        "new_key": new_key,
        "now": datetime.utcnow(),
    })


@router.post("/developer/keys/create", response_class=HTMLResponse)
async def create_api_key(
    request: Request,
    name: str = Form(...),
    expires_in_days: Optional[int] = Form(default=None),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    _: None = Depends(_manager),
):
    if not name.strip():
        return RedirectResponse("/developer?error=Name+is+required", status_code=303)

    plain, prefix, key_hash = _generate_api_key()
    expires_at = None
    if expires_in_days and expires_in_days > 0:
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    key = APIKey(
        tenant_id=user.tenant_id,
        name=name.strip(),
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=["read", "write"],
        expires_at=expires_at,
    )
    session.add(key)
    session.commit()

    from urllib.parse import quote
    return RedirectResponse(
        f"/developer?msg=Key+created&new_key={quote(plain)}",
        status_code=303,
    )


@router.post("/developer/keys/{key_id}/revoke", response_class=HTMLResponse)
async def revoke_api_key(
    key_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    _: None = Depends(_manager),
):
    key = session.get(APIKey, key_id)
    if not key or key.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Key not found")
    session.delete(key)
    session.commit()
    return RedirectResponse("/developer?msg=Key+revoked", status_code=303)
