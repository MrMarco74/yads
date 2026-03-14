from datetime import datetime, timezone

from sqlmodel import Session, func, select

from app.models import BugReport


def generate_report_id(session: Session) -> str:
    """
    Generate a report ID in the format YAD-{YEAR}-{5-digit-zero-padded-counter}.

    The counter is global across all years (total reports in DB + 1).
    Example: YAD-2026-00001
    """
    total = session.exec(select(func.count()).select_from(BugReport)).one()
    counter = total + 1
    year = datetime.now(timezone.utc).year
    return f"YAD-{year}-{counter:05d}"
