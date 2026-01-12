from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from typing import List, Optional
from datetime import datetime

from yads.database import get_session
from yads.models import User, ChangelogEntry
from yads.auth.deps import get_current_active_user

router = APIRouter(
    prefix="/api/changelog",
    tags=["changelog"]
)

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
