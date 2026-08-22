"""
Shared health-check badge for anything credential/connection-based: BYOK OSINT
keys (TenantApiKey) and notification integrations (IntegrationConfig). Both
models carry the same three columns (last_check_at/last_check_status/
last_check_message) so this module can update either without caring which.
"""
from datetime import datetime
from typing import Optional, Union

from sqlmodel import Session

from yads.models import TenantApiKey, IntegrationConfig

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_UNTESTED = "untested"

HealthCheckable = Union[TenantApiKey, IntegrationConfig]


def record_health_check(
    session: Session,
    obj: HealthCheckable,
    ok: bool,
    message: Optional[str] = None,
) -> HealthCheckable:
    """Persist the outcome of testing a key/integration's connectivity."""
    obj.last_check_at = datetime.utcnow()
    obj.last_check_status = STATUS_OK if ok else STATUS_FAILED
    obj.last_check_message = (message or "")[:500] or None
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


def health_badge(obj: HealthCheckable) -> dict:
    """UI-friendly summary for a health-check badge."""
    status = obj.last_check_status or STATUS_UNTESTED
    return {
        "status": status,
        "message": obj.last_check_message,
        "checked_at": obj.last_check_at,
        "color": {"ok": "green", "failed": "red", "untested": "slate"}.get(status, "slate"),
    }
