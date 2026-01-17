from sqlmodel import Session
from datetime import datetime
from yads.models import ChangelogEntry, Notification
import textwrap

def publish_changelog_entry(session: Session, version: str, title: str, content: str, icon: str = "sparkles", color: str = "blue"):
    """
    Creates a ChangelogEntry and a corresponding Notification for all users.
    Idempotent: Checks if version already exists.
    """
    # Check if entry exists
    existing = session.query(ChangelogEntry).filter(ChangelogEntry.version == version).first()
    if existing:
        print(f"Changelog {version} already exists. Skipping.")
        return existing

    # Create Changelog Entry
    entry = ChangelogEntry(
        version=version,
        title=title,
        published_at=datetime.utcnow(),
        content=textwrap.dedent(content)
    )
    session.add(entry)
    
    # Create Notification
    # Using a generic system notification that all users can see (since we list all notifications in the UI)
    notification = Notification(
        title=f"New Update: {title}",
        text=f"YADS has been updated to version {version}. Check the changelog for details.",
        type="update",
        color=color,
        icon=icon,
        created_at=datetime.utcnow()
    )
    session.add(notification)
    
    session.commit()
    print(f"Successfully published Changelog {version} and created notification.")
    return entry
