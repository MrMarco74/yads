from typing import Generator, Annotated, List
from fastapi import Depends, HTTPException, status, Request
from jose import jwt, JWTError
from sqlmodel import Session, select
from yads.config import settings
from yads.models import User
from yads.database import engine, get_session as get_db_session


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
