"""
Tenant Configuration Export / Import

Exports tenant API keys, LLM config, report branding, webhooks,
scan automation config and scan profiles into a password-encrypted
.ytcfg file (ZIP with manifest.json + config.json.enc).

Import validates fields, shows a diff preview, then applies to the
current tenant — IDs from the file are always ignored.
"""

import io
import json
import zipfile
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Session, select

from yads.core.backup import encrypt_data, decrypt_data

logger = logging.getLogger("yads.tenant_config")

FORMAT_VERSION = "1"

# ── Fields exported from the Tenant row ──────────────────────────────────────
TENANT_FIELDS = [
    # OSINT settings (not runtime quotas)
    "osint_enabled", "osint_quota_max", "osint_cost_per_search",
    # BYOK API keys
    "google_api_key", "google_cse_cx", "nuclei_api_key", "hibp_api_key",
    "hunter_api_key", "github_token", "twitter_bearer_token",
    "shodan_api_key", "censys_api_key", "virustotal_api_key",
    # Session
    "session_timeout_minutes",
    # LLM
    "llm_provider", "llm_api_url", "llm_api_key", "llm_model",
    # Report branding
    "report_logo_url", "report_company_name", "report_primary_color",
    "report_secondary_color", "report_header_text", "report_footer_text",
]


# ── Export ────────────────────────────────────────────────────────────────────

def export_tenant_config(tenant_id: int, password: str, session: Session) -> bytes:
    """
    Build and return a .ytcfg file (bytes) for the given tenant.
    Raises ValueError if tenant not found.
    """
    from yads.models import Tenant, Webhook, TenantScanConfig, ScanProfile, TenantModuleConfig

    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        raise ValueError(f"Tenant {tenant_id} not found")

    # ── Gather data ───────────────────────────────────────────────────────────
    tenant_data = {f: getattr(tenant, f) for f in TENANT_FIELDS}

    webhooks = [
        {"url": w.url, "event_types": w.event_types, "is_active": w.is_active}
        for w in session.exec(select(Webhook).where(Webhook.tenant_id == tenant_id)).all()
    ]

    scan_cfg = session.exec(
        select(TenantScanConfig).where(TenantScanConfig.tenant_id == tenant_id)
    ).first()
    scan_config_data = None
    if scan_cfg:
        scan_config_data = {
            "auto_scan_enabled": scan_cfg.auto_scan_enabled,
            "frequency": scan_cfg.frequency,
            "cron_expression": scan_cfg.cron_expression,
            "scan_types": scan_cfg.scan_types,
            "max_targets_per_run": scan_cfg.max_targets_per_run,
            "max_concurrent_scans": scan_cfg.max_concurrent_scans,
            "scan_window_start": scan_cfg.scan_window_start,
            "scan_window_end": scan_cfg.scan_window_end,
        }

    profiles = [
        {
            "name": p.name,
            "description": p.description,
            "scan_types": p.scan_types,
            "is_default": p.is_default,
            "is_public": p.is_public,
            "icon": p.icon,
            "color": p.color,
        }
        for p in session.exec(
            select(ScanProfile).where(ScanProfile.tenant_id == tenant_id)
        ).all()
    ]

    module_overrides = [
        {"module_name": m.module_name, "enabled": m.enabled}
        for m in session.exec(
            select(TenantModuleConfig).where(TenantModuleConfig.tenant_id == tenant_id)
        ).all()
    ]

    config = {
        "format_version": FORMAT_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "tenant_name": tenant.name,
        "tenant": tenant_data,
        "webhooks": webhooks,
        "scan_config": scan_config_data,
        "scan_profiles": profiles,
        "module_overrides": module_overrides,
    }

    config_bytes = json.dumps(config, indent=2, default=str).encode("utf-8")
    sha256 = hashlib.sha256(config_bytes).hexdigest()

    # ── Encrypt config ────────────────────────────────────────────────────────
    encrypted = encrypt_data(config_bytes, password)

    # ── Build manifest ────────────────────────────────────────────────────────
    manifest = {
        "format_version": FORMAT_VERSION,
        "exported_at": config["exported_at"],
        "tenant_name": tenant.name,
        "config_sha256": sha256,
        "items": {
            "webhooks": len(webhooks),
            "scan_profiles": len(profiles),
            "module_overrides": len(module_overrides),
            "has_scan_config": scan_config_data is not None,
        },
    }

    # ── Pack ZIP ──────────────────────────────────────────────────────────────
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.writestr("config.json.enc", encrypted)
    return buf.getvalue()


# ── Parse & Preview ───────────────────────────────────────────────────────────

def parse_ytcfg(file_bytes: bytes, password: str) -> dict:
    """
    Decrypt and parse a .ytcfg file.
    Returns the config dict.
    Raises ValueError on bad format/password.
    """
    if len(file_bytes) > 1 * 1024 * 1024:  # 1 MB hard limit
        raise ValueError("File too large (max 1 MB)")

    try:
        buf = io.BytesIO(file_bytes)
        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()
            if "manifest.json" not in names or "config.json.enc" not in names:
                raise ValueError("Invalid .ytcfg structure")

            manifest = json.loads(zf.read("manifest.json"))
            encrypted = zf.read("config.json.enc")
    except zipfile.BadZipFile:
        raise ValueError("Not a valid .ytcfg file")

    if manifest.get("format_version") != FORMAT_VERSION:
        raise ValueError(f"Unsupported format version: {manifest.get('format_version')}")

    try:
        config_bytes = decrypt_data(encrypted, password)
    except Exception:
        raise ValueError("Wrong password or corrupted file")

    # Verify SHA256
    actual_sha = hashlib.sha256(config_bytes).hexdigest()
    if actual_sha != manifest.get("config_sha256"):
        raise ValueError("File integrity check failed (SHA256 mismatch)")

    config = json.loads(config_bytes)
    return config


def build_preview(config: dict, tenant_id: int, session: Session) -> dict:
    """
    Compare config-to-import against current tenant state.
    Returns a structured preview dict for the UI.
    """
    from yads.models import Tenant, Webhook, TenantScanConfig, ScanProfile

    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        return {"error": "Tenant not found"}

    # API key changes (only show presence, not actual values)
    api_key_fields = [f for f in TENANT_FIELDS if "key" in f or "token" in f or "cx" in f]
    other_fields = [f for f in TENANT_FIELDS if f not in api_key_fields]

    key_changes = []
    for f in api_key_fields:
        old_val = getattr(tenant, f)
        new_val = config["tenant"].get(f)
        old_set = bool(old_val)
        new_set = bool(new_val)
        if old_set != new_set or (old_set and new_set and old_val != new_val):
            key_changes.append({
                "field": f,
                "from": "set" if old_set else "empty",
                "to": "set" if new_set else "empty",
                "changed": True,
            })

    setting_changes = []
    for f in other_fields:
        old_val = getattr(tenant, f)
        new_val = config["tenant"].get(f)
        if old_val != new_val:
            setting_changes.append({"field": f, "from": old_val, "to": new_val})

    current_webhooks = session.exec(
        select(Webhook).where(Webhook.tenant_id == tenant_id)
    ).all()

    current_profiles = session.exec(
        select(ScanProfile).where(ScanProfile.tenant_id == tenant_id)
    ).all()

    return {
        "source_tenant": config.get("tenant_name", "Unknown"),
        "exported_at": config.get("exported_at", ""),
        "api_key_changes": key_changes,
        "setting_changes": setting_changes,
        "webhooks": {
            "current_count": len(current_webhooks),
            "import_count": len(config.get("webhooks", [])),
            "action": "replace",
        },
        "scan_profiles": {
            "current_count": len(current_profiles),
            "import_count": len(config.get("scan_profiles", [])),
            "action": "replace",
        },
        "scan_config": {
            "importing": config.get("scan_config") is not None,
        },
        "module_overrides": {
            "import_count": len(config.get("module_overrides", [])),
        },
    }


# ── Apply ─────────────────────────────────────────────────────────────────────

def apply_config(config: dict, tenant_id: int, session: Session) -> dict:
    """
    Apply parsed config to the given tenant. Returns a summary dict.
    tenant_id from the file is always ignored — uses the passed tenant_id.
    """
    from yads.models import Tenant, Webhook, TenantScanConfig, ScanProfile, TenantModuleConfig

    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        raise ValueError("Tenant not found")

    # ── Tenant fields ─────────────────────────────────────────────────────────
    for f in TENANT_FIELDS:
        if f in config.get("tenant", {}):
            setattr(tenant, f, config["tenant"][f])
    session.add(tenant)

    # ── Webhooks (replace all) ────────────────────────────────────────────────
    existing_hooks = session.exec(
        select(Webhook).where(Webhook.tenant_id == tenant_id)
    ).all()
    for hook in existing_hooks:
        session.delete(hook)
    session.flush()

    for w in config.get("webhooks", []):
        session.add(Webhook(
            tenant_id=tenant_id,
            url=w["url"],
            event_types=w.get("event_types", []),
            is_active=w.get("is_active", True),
        ))

    # ── Scan config ───────────────────────────────────────────────────────────
    sc_data = config.get("scan_config")
    if sc_data:
        sc = session.exec(
            select(TenantScanConfig).where(TenantScanConfig.tenant_id == tenant_id)
        ).first()
        if not sc:
            sc = TenantScanConfig(tenant_id=tenant_id)
        for k, v in sc_data.items():
            setattr(sc, k, v)
        sc.updated_at = datetime.utcnow()
        session.add(sc)

    # ── Scan profiles (replace all) ───────────────────────────────────────────
    existing_profiles = session.exec(
        select(ScanProfile).where(ScanProfile.tenant_id == tenant_id)
    ).all()
    for p in existing_profiles:
        session.delete(p)
    session.flush()

    for p in config.get("scan_profiles", []):
        session.add(ScanProfile(
            tenant_id=tenant_id,
            name=p["name"],
            description=p.get("description"),
            scan_types=p.get("scan_types", []),
            is_default=p.get("is_default", False),
            is_public=p.get("is_public", False),
            icon=p.get("icon"),
            color=p.get("color", "blue"),
        ))

    # ── Module overrides (replace all) ────────────────────────────────────────
    existing_mods = session.exec(
        select(TenantModuleConfig).where(TenantModuleConfig.tenant_id == tenant_id)
    ).all()
    for m in existing_mods:
        session.delete(m)
    session.flush()

    for m in config.get("module_overrides", []):
        session.add(TenantModuleConfig(
            tenant_id=tenant_id,
            module_name=m["module_name"],
            enabled=m.get("enabled", True),
        ))

    session.commit()

    return {
        "webhooks_imported": len(config.get("webhooks", [])),
        "profiles_imported": len(config.get("scan_profiles", [])),
        "module_overrides_imported": len(config.get("module_overrides", [])),
        "scan_config_imported": sc_data is not None,
    }
