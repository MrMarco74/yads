from typing import Generator, Annotated, List
from fastapi import Depends, HTTPException, status, Request
from jose import jwt, JWTError
from sqlmodel import Session, select
from yads.config import settings
from yads.database import engine, get_session as get_db_session, redis_client
from yads.models import User, APIKey
from yads.auth.security import hash_api_key
from yads.core.security_audit import log_api_key_access


class LoginRequiredException(Exception):
    pass

async def get_current_user_html(request: Request, session: Session = Depends(get_db_session)) -> User:
    token = request.cookies.get("access_token")
    if not token:
         # Check header as fallback (Bearer) - unlikely for HTML but for consistency
         auth_header = request.headers.get("Authorization")
         if auth_header and auth_header.startswith("Bearer "):
             token = auth_header.split(" ")[1]
    
    if not token:
        raise LoginRequiredException()

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise LoginRequiredException()
    except JWTError:
        raise LoginRequiredException()
        
    user = session.exec(select(User).where(User.username == username)).first()
    if user is None:
        raise LoginRequiredException()
        
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
        
    return user

async def get_current_user_html_optional(request: Request, session: Session = Depends(get_db_session)) -> User | None:
    try:
        return await get_current_user_html(request, session)
    except (LoginRequiredException, HTTPException):
        return None

async def get_current_user(request: Request, session: Session = Depends(get_db_session)) -> User:
    token = request.cookies.get("access_token")
    if not token:
         # Check header as fallback (Bearer)
         auth_header = request.headers.get("Authorization")
         if auth_header and auth_header.startswith("Bearer "):
             token = auth_header.split(" ")[1]
    
    if not token:
        # Redirect logic handled in frontend/login page usually, but here API raises 401
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
    user = session.exec(select(User).where(User.username == username)).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
        
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_active:
         raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: User = Depends(get_current_active_user)):
        if user.role in self.allowed_roles:
            return user
            
        # Admin Superuser Override (optional, but good practice)
        if user.role == "admin":
            return user
            
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted"
        )

class PlatformAdminChecker:
    """
    Checks if user is a Platform Admin (System Admin).
    Definition: role='admin' (regardless of current tenant context)
    """
    def __call__(self, user: User = Depends(get_current_active_user)):
        if user.role == "admin":
            return user
        
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Requires Platform Admin privileges"
        )


async def get_api_key(
    request: Request,
    session: Session = Depends(get_db_session)
) -> APIKey:
    """
    FastAPI dependency to authenticate via X-API-Key header.
    Returns the APIKey object which includes the tenant context.
    """
    # --- TLS Enforcement ---
    # Reject if not HTTPS in production environment
    if not settings.DEBUG and request.url.scheme != "https":
         raise HTTPException(
             status_code=status.HTTP_403_FORBIDDEN,
             detail="SSL/TLS Required for API Key authentication"
         )

    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key missing (X-API-Key header required)"
        )

    # Hash the key to find it in the DB
    key_hash = hash_api_key(api_key)
    
    # We use the prefix as a secondary check/index optimization if needed, 
    # but here we just query by hash.
    statement = select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active == True)
    db_key = session.exec(statement).first()

    if not db_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API Key"
        )

    # Check expiration
    from datetime import datetime
    if db_key.expires_at and db_key.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key has expired"
        )

    # Update last_used_at
    db_key.last_used_at = datetime.utcnow()
    session.add(db_key)
    session.commit()

    # --- Rate Limiting (Redis) ---
    rate_limit_key = f"rate_limit:apikey:{db_key.id}"
    try:
        current_count = redis_client.incr(rate_limit_key)
        if current_count == 1:
            # Set expiry on first request (e.g. 60 requests per minute)
            redis_client.expire(rate_limit_key, 60)
        
        if current_count > 60:
             log_api_key_access(request, db_key, success=False, session=session)
             raise HTTPException(
                 status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                 detail="Rate limit exceeded (60 requests/minute)"
             )
    except Exception as e:
        # Don't block API if Redis is down, but log it
        if isinstance(e, HTTPException): raise

    # --- Audit Logging ---
    log_api_key_access(request, db_key, session=session)
    session.commit()

    return db_key


class RequireScope:
    """
    FastAPI dependency that verifies the authenticated API key has a required scope.

    Usage:
        @router.post("/scan", dependencies=[Depends(RequireScope("scan_execute"))])
        async def trigger_scan(key: APIKey = Depends(get_api_key)): ...
    """
    def __init__(self, required_scope: str):
        self.required_scope = required_scope

    def __call__(self, api_key: APIKey = Depends(get_api_key)) -> APIKey:
        if not api_key.scopes or self.required_scope not in api_key.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key does not have the required scope: '{self.required_scope}'"
            )
        return api_key
