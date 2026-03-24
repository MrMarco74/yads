"""
Tenant API Key Utilities
========================
Central lookup for per-tenant BYOK API keys.

Priority chain:
  1. TenantApiKey table (dynamic, encrypted)
  2. Legacy Tenant model attribute (backwards compat)
  3. Global env var via settings (platform-wide fallback)
"""
from typing import List, Optional, TYPE_CHECKING

from sqlmodel import Session, select

from yads.models import TenantApiKey

if TYPE_CHECKING:
    from yads.core.base import ApiKeySpec


def get_tenant_api_key(
    session: Session,
    tenant_id: Optional[int],
    key_name: str,
    legacy_attr: Optional[str] = None,
    settings_attr: Optional[str] = None,
) -> Optional[str]:
    """
    Look up an API key for a tenant.
    Falls back to legacy Tenant attribute, then global env var.
    """
    if tenant_id:
        row = session.exec(
            select(TenantApiKey).where(
                TenantApiKey.tenant_id == tenant_id,
                TenantApiKey.key_name == key_name,
            )
        ).first()
        if row and row.value:
            return row.value

    # Legacy: check old Tenant model attribute
    if tenant_id and legacy_attr:
        from yads.models import Tenant
        tenant = session.get(Tenant, tenant_id)
        if tenant:
            val = getattr(tenant, legacy_attr, None)
            if val:
                return val

    # Global fallback: env var
    if settings_attr:
        from yads.config import settings
        return getattr(settings, settings_attr, None)

    return None


def set_tenant_api_key(
    session: Session,
    tenant_id: int,
    key_name: str,
    value: Optional[str],
) -> None:
    """Upsert a TenantApiKey row. Passing None/empty string deletes the entry."""
    row = session.exec(
        select(TenantApiKey).where(
            TenantApiKey.tenant_id == tenant_id,
            TenantApiKey.key_name == key_name,
        )
    ).first()

    if value:
        if row:
            row.value = value
            session.add(row)
        else:
            session.add(TenantApiKey(tenant_id=tenant_id, key_name=key_name, value=value))
    elif row:
        session.delete(row)


def get_all_api_key_specs() -> List["ApiKeySpec"]:
    """
    Aggregate ApiKeySpec declarations from all registered scanner modules.
    Deduplicates by key name (first occurrence wins).
    """
    from yads.core.module_registry import REGISTRY
    from yads.core.base import ApiKeySpec

    seen: dict[str, ApiKeySpec] = {}
    for mod_def in REGISTRY.values():
        try:
            parts = mod_def.module_path.split(":")
            if len(parts) != 2:
                continue
            mod_path, class_name = parts
            mod = __import__(mod_path, fromlist=[class_name])
            cls = getattr(mod, class_name, None)
            if cls is None:
                continue
            for spec in getattr(cls, "api_key_specs", []):
                if spec.name not in seen:
                    seen[spec.name] = spec
        except Exception:
            pass

    return list(seen.values())


def load_tenant_api_keys(session: Session, tenant_id: int) -> dict:
    """Load all TenantApiKey rows for a tenant as a dict {key_name: value}."""
    rows = session.exec(
        select(TenantApiKey).where(TenantApiKey.tenant_id == tenant_id)
    ).all()
    return {r.key_name: r.value for r in rows if r.value}
