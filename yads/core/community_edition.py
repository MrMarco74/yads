"""
Community Edition (CE) License Management

CE is a free, built-in tier stored entirely in SystemConfig — no external
signing or key exchange required.

Limits:
  - Max 50 targets (globally across all tenants)
  - Max 3 users (per tenant)
  - 30-day active period, then read-only
  - One-time 15-day extension

States:
  - not_activated  : CE was never activated (falls back to old Free Tier limit 5)
  - active         : within the 30-day (or 45-day after extension) window
  - read_only      : expired, data visible but no new scans / targets
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger("yads.ce")

# ── Constants ─────────────────────────────────────────────────────────────────
CE_MAX_TARGETS    = 50
CE_MAX_USERS      = 3
CE_DAYS           = 30
CE_EXTENSION_DAYS = 15

# SystemConfig keys
_KEY_ACTIVATED = "CE_ACTIVATED_AT"
_KEY_EXTENDED  = "CE_EXTENDED"
_KEY_EDITION   = "CE_EDITION"      # "community" when active


# ── Public helpers ────────────────────────────────────────────────────────────

def get_ce_state(session) -> dict:
    """
    Returns a dict describing the current CE state:
      {
        "edition":        "community" | None,
        "status":         "not_activated" | "active" | "read_only",
        "activated_at":   datetime | None,
        "expires_at":     datetime | None,
        "days_remaining": int,
        "extended":       bool,
        "can_extend":     bool,
        "max_targets":    int,
        "max_users":      int,
      }
    """
    from yads.models import SystemConfig

    edition    = _get(session, _KEY_EDITION)
    activated  = _get(session, _KEY_ACTIVATED)
    extended   = _get(session, _KEY_EXTENDED) == "true"

    if edition != "community" or not activated:
        return {
            "edition": None,
            "status": "not_activated",
            "activated_at": None,
            "expires_at": None,
            "days_remaining": 0,
            "extended": False,
            "can_extend": False,
            "max_targets": CE_MAX_TARGETS,
            "max_users": CE_MAX_USERS,
        }

    try:
        activated_at = datetime.fromisoformat(activated)
        if activated_at.tzinfo is None:
            activated_at = activated_at.replace(tzinfo=timezone.utc)
    except ValueError:
        activated_at = datetime.now(timezone.utc)

    total_days = CE_DAYS + (CE_EXTENSION_DAYS if extended else 0)
    expires_at = activated_at + timedelta(days=total_days)
    now = datetime.now(timezone.utc)
    remaining = max(0, (expires_at - now).days)
    is_active = now < expires_at

    return {
        "edition": "community",
        "status": "active" if is_active else "read_only",
        "activated_at": activated_at,
        "expires_at": expires_at,
        "days_remaining": remaining,
        "extended": extended,
        "can_extend": not extended and not is_active,   # only when expired & unused
        "max_targets": CE_MAX_TARGETS,
        "max_users": CE_MAX_USERS,
    }


def activate(session) -> bool:
    """Activate CE mode. Idempotent — safe to call multiple times."""
    from yads.models import SystemConfig

    if _get(session, _KEY_EDITION) == "community":
        return False  # already active

    _set(session, _KEY_EDITION,   "community")
    _set(session, _KEY_ACTIVATED, datetime.now(timezone.utc).isoformat())
    _set(session, _KEY_EXTENDED,  "false")
    session.commit()
    logger.info("Community Edition activated.")
    return True


def extend(session) -> tuple[bool, str]:
    """
    Use the one-time 15-day extension. Only allowed when CE is expired.
    Returns (success, message).
    """
    state = get_ce_state(session)
    if state["edition"] != "community":
        return False, "CE nicht aktiviert."
    if state["extended"]:
        return False, "Verlängerung wurde bereits verwendet."
    if state["status"] == "active":
        return False, "CE ist noch aktiv — Verlängerung erst nach Ablauf möglich."

    _set(session, _KEY_EXTENDED, "true")
    session.commit()
    logger.info("Community Edition extended by 15 days.")
    return True, "Verlängerung aktiviert — CE läuft 15 weitere Tage."


def is_read_only(session) -> bool:
    """True when CE is expired and no further extension is possible."""
    return get_ce_state(session)["status"] == "read_only"


def check_can_add_target(session, current_count: int) -> tuple[bool, str]:
    """
    Returns (allowed, reason). Checks both CE limits and commercial license.
    Call this before creating a new target.
    """
    state = get_ce_state(session)
    if state["edition"] != "community":
        return True, ""  # No CE active — handled by old license logic

    if state["status"] == "read_only":
        return False, (
            "Community Edition abgelaufen — YADS ist im Lesemodus. "
            "Verlängerung verfügbar oder kommerzielle Lizenz einspielen."
        )
    if current_count >= CE_MAX_TARGETS:
        return False, (
            f"Community Edition Limit erreicht ({CE_MAX_TARGETS} Targets). "
            "Bitte eine kommerzielle Lizenz einspielen."
        )
    return True, ""


def check_can_add_user(session, current_user_count: int) -> tuple[bool, str]:
    state = get_ce_state(session)
    if state["edition"] != "community":
        return True, ""
    if current_user_count >= CE_MAX_USERS:
        return False, (
            f"Community Edition erlaubt max. {CE_MAX_USERS} Benutzer. "
            "Bitte eine kommerzielle Lizenz einspielen."
        )
    return True, ""


def check_can_scan(session) -> tuple[bool, str]:
    """
    Returns (allowed, reason). Call this before queuing or executing a scan.
    """
    state = get_ce_state(session)
    if state["edition"] != "community":
        return True, ""
    if state["status"] == "read_only":
        return False, "Community Edition abgelaufen — Scans sind im Lesemodus deaktiviert."
    return True, ""


# ── Private helpers ───────────────────────────────────────────────────────────

def _get(session, key: str) -> Optional[str]:
    from yads.models import SystemConfig
    cfg = session.get(SystemConfig, key)
    return cfg.value if cfg else None


def _set(session, key: str, value: str):
    from yads.models import SystemConfig
    cfg = session.get(SystemConfig, key)
    if cfg:
        cfg.value = value
    else:
        cfg = SystemConfig(key=key, value=value)
    session.add(cfg)
