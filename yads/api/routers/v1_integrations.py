"""API-key-authenticated, tenant-scoped Integrations / Webhooks /
Notifications read surface for yads-mcp (Wave 6). Read-only, and deliberately
secret-safe: webhook URLs are masked (they often carry a token in the path)
and IntegrationConfig.config (tokens/credentials) is never returned — an LLM
agent should be able to see *that* an integration exists and its health,
never the secret that authenticates it.
"""

from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from yads.auth.deps import RequireScope, require_tenant_scoped_key
from yads.database import get_session
from yads.models import APIKey, Webhook, ReportSubscription, IntegrationConfig

router = APIRouter(prefix="/api/v1", tags=["API v1 — Integrations & Notifications"])


def _mask_url(url: str) -> str:
    """Keep scheme://host and the first path segment; mask the rest, since
    webhook URLs frequently embed a secret token in the trailing path."""
    if not url:
        return ""
    try:
        p = urlparse(url)
        host = f"{p.scheme}://{p.netloc}" if p.scheme else p.netloc
        segs = [s for s in (p.path or "").split("/") if s]
        if not segs:
            return host + "/"
        return f"{host}/{segs[0]}/…(masked)"
    except Exception:
        return "…(masked)"


@router.get("/webhooks", dependencies=[Depends(RequireScope("read"))])
async def list_webhooks(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    """Outbound webhooks configured for the tenant. The URL is masked (webhook
    URLs often carry a secret token in the path); event_types and active state
    are shown in full."""
    rows = session.exec(
        select(Webhook).where(Webhook.tenant_id == api_key.tenant_id)
        .order_by(Webhook.created_at.desc())
    ).all()
    items = [{
        "id": w.id,
        "url_masked": _mask_url(w.url),
        "event_types": w.event_types or [],
        "is_active": w.is_active,
        "created_at": w.created_at.isoformat() if w.created_at else None,
    } for w in rows]
    return {"items": items, "total": len(items)}


@router.get("/report-subscriptions", dependencies=[Depends(RequireScope("read"))])
async def list_report_subscriptions(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    """Recurring report-delivery subscriptions for the tenant (name, report
    type, recipients, cadence, last-sent)."""
    rows = session.exec(
        select(ReportSubscription).where(ReportSubscription.tenant_id == api_key.tenant_id)
        .order_by(ReportSubscription.created_at.desc())
    ).all()
    items = [{
        "id": s.id,
        "name": s.name,
        "report_type": s.report_type,
        "recipients": s.recipients or [],
        "frequency": s.frequency,
        "day_of_week": s.day_of_week,
        "day_of_month": s.day_of_month,
        "is_active": s.is_active,
        "last_sent_at": s.last_sent_at.isoformat() if s.last_sent_at else None,
    } for s in rows]
    return {"items": items, "total": len(items)}


@router.get("/integrations", dependencies=[Depends(RequireScope("read"))])
async def list_integrations(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    """External integrations configured for the tenant (Jira, GitHub, SIEM,
    Slack, ...). Reports type/active/updated only — the stored config
    (tokens/credentials) is intentionally never returned."""
    rows = session.exec(
        select(IntegrationConfig).where(IntegrationConfig.tenant_id == api_key.tenant_id)
        .order_by(IntegrationConfig.integration_type.asc())
    ).all()
    items = [{
        "integration_type": i.integration_type,
        "is_active": i.is_active,
        "config_keys": sorted((i.config or {}).keys()),  # names only, never values
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
    } for i in rows]
    return {"items": items, "total": len(items)}
