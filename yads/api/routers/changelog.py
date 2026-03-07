from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from typing import List, Optional
from datetime import datetime
import markdown
import textwrap

from yads.database import get_session
from yads.models import User, ChangelogEntry
from yads.auth.deps import get_current_active_user, get_current_user_html_optional
from yads.config import settings

router = APIRouter(
    prefix="/changelog",  # Changed prefix to root /changelog for HTML
    tags=["changelog"]
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
def view_changelog(
    request: Request,
    current_user: User = Depends(get_current_user_html_optional),
    session: Session = Depends(get_session)
):
    """
    Render the full changelog history page.
    Also marks all changes as seen for the current user.
    """
    # Fetch all entries, newest first
    statement = select(ChangelogEntry).order_by(ChangelogEntry.published_at.desc())
    entries = session.exec(statement).all()
    
    # Process markdown content for each entry
    processed_entries = []
    latest_id = 0
    
    for entry in entries:
        if entry.id > latest_id:
            latest_id = entry.id
            
        processed_entries.append({
            "version": entry.version,
            "title": entry.title,
            "published_at": entry.published_at,
            "content": markdown.markdown(textwrap.dedent(entry.content), extensions=['fenced_code', 'tables'])
        })
        
    # Mark as read if user is logged in
    if current_user and latest_id > (current_user.last_seen_changelog_id or 0):
        current_user.last_seen_changelog_id = latest_id
        session.add(current_user)
        session.commit()
    
    return templates.TemplateResponse("changelog.html", {
        "request": request,
        "entries": processed_entries,
        "user": current_user,
        "settings": settings
    })

# Re-expose the API endpoint for compatibility if needed, but under /api/changelog path manually
@router.get("/api/latest", response_model=List[ChangelogEntry])
def get_latest_changes_api(
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session)
):
    """
    Get all changelog entries that have an ID greater than what the user has last seen.
    (Legacy/API support)
    """
    statement = select(ChangelogEntry).where(
        ChangelogEntry.id > (current_user.last_seen_changelog_id or 0)
    ).order_by(ChangelogEntry.published_at.desc())
    
    results = session.exec(statement).all()
    return results

@router.get("/latest", response_model=List[ChangelogEntry])
def get_latest_changes(
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session)
):
    """
    Get all changelog entries that have an ID greater than what the user has last seen.
    """
    statement = select(ChangelogEntry).where(
        ChangelogEntry.id > (current_user.last_seen_changelog_id or 0)
    ).order_by(ChangelogEntry.published_at.desc())
    
    results = session.exec(statement).all()
    return results

@router.post("/ack")
def acknowledge_changes(
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session)
):
    """
    Update the user's last_seen_changelog_id to the generic latest ID in the system.
    """
    # Find the absolute latest changelog ID
    latest_entry = session.exec(select(ChangelogEntry).order_by(ChangelogEntry.id.desc())).first()
    
    if latest_entry:
        current_user.last_seen_changelog_id = latest_entry.id
        session.add(current_user)
        session.commit()
        session.refresh(current_user)
        
    return {"status": "ok", "last_seen_id": current_user.last_seen_changelog_id}
