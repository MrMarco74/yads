"""
Scan Profile / Policy System (#23)

Allows users to save, manage, and apply named scan configurations:
  - Create profiles with selected modules + name/description
  - Apply profile to pre-select modules in the scan UI
  - Set a default profile per tenant
  - Built-in profiles: Quick, Standard, Deep, Recon-only, Threat-focused
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import RoleChecker, get_current_user_html
from yads.database import get_session
from yads.models import ScanProfile, User
from yads.core.module_registry import REGISTRY, get_scan_categories

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Built-in default profiles ──────────────────────────────────────────────
BUILTIN_PROFILES = [
    {
        "name": "Quick Recon",
        "description": "Fast surface overview — DNS, SSL, headers, and WHOIS only.",
        "scan_types": ["dns_scanner", "ssl_scanner", "web_analyzer", "security_headers"],
        "icon": "⚡",
        "color": "sky",
        "is_public": True,
    },
    {
        "name": "Standard Scan",
        "description": "Balanced scan covering web, DNS, certificates, and common vulnerabilities.",
        "scan_types": [
            "dns_scanner", "ssl_scanner", "web_analyzer", "security_headers",
            "cors_scanner", "csp_scanner", "email_security", "tls_deep_scanner",
            "waf_detector", "login_scanner", "cookie_analyzer",
        ],
        "icon": "🔍",
        "color": "blue",
        "is_public": True,
    },
    {
        "name": "Deep Security Audit",
        "description": "Comprehensive scan — all modules including active testing.",
        "scan_types": ["full_scan"],
        "icon": "🛡",
        "color": "indigo",
        "is_public": True,
    },
    {
        "name": "Recon Only",
        "description": "Passive intelligence gathering — DNS history, CT logs, ASN, email harvesting.",
        "scan_types": [
            "dns_scanner", "dns_history_scanner", "ct_monitor", "asn_scanner",
            "typosquat_scanner", "email_harvester", "mobile_app_discovery",
        ],
        "icon": "🔭",
        "color": "emerald",
        "is_public": True,
    },
    {
        "name": "Threat Intelligence",
        "description": "Focus on threat indicators — phishing, credentials, malware, brand abuse.",
        "scan_types": [
            "threat_intel", "phishing_scanner", "leaked_credentials",
            "password_spray_mapper", "subdomain_takeover", "email_harvester",
        ],
        "icon": "🚨",
        "color": "rose",
        "is_public": True,
    },
    {
        "name": "API Security",
        "description": "API-focused scan — REST, GraphQL, WebSocket, authentication surfaces.",
        "scan_types": [
            "api_security_scanner", "graphql_scanner", "websocket_scanner",
            "login_scanner", "cors_scanner", "waf_detector",
        ],
        "icon": "🔌",
        "color": "amber",
        "is_public": True,
    },
]


@router.get("/scan-profiles", response_class=HTMLResponse)
async def list_profiles(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    profiles = session.exec(
        select(ScanProfile).where(
            (ScanProfile.tenant_id == user.tenant_id) | (ScanProfile.is_public == True)
        ).order_by(ScanProfile.is_default.desc(), ScanProfile.name)
    ).all()

    scan_categories = get_scan_categories("sp")

    return templates.TemplateResponse("scan_profiles.html", {
        "request": request,
        "user": user,
        "profiles": profiles,
        "builtin_profiles": BUILTIN_PROFILES,
        "scan_categories": scan_categories,
        "page_title": "Scan Profiles",
    })


@router.post("/scan-profiles/create", response_class=HTMLResponse)
async def create_profile(
    request: Request,
    name: str = Form(...),
    description: str = Form(default=""),
    scan_types: List[str] = Form(default=[]),
    color: str = Form(default="blue"),
    is_default: bool = Form(default=False),
    is_public: bool = Form(default=False),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    name = name.strip()[:80]
    if not name:
        return RedirectResponse(url="/scan-profiles?error=Name+required", status_code=303)

    # Validate scan_types against registry
    valid = {k for k in REGISTRY}
    scan_types = [t for t in scan_types if t in valid or t == "full_scan"]

    # If setting as default, clear existing defaults for this tenant
    if is_default:
        existing_defaults = session.exec(
            select(ScanProfile).where(
                ScanProfile.tenant_id == user.tenant_id,
                ScanProfile.is_default == True,
            )
        ).all()
        for ep in existing_defaults:
            ep.is_default = False
            session.add(ep)

    profile = ScanProfile(
        tenant_id=user.tenant_id,
        created_by=user.id,
        name=name,
        description=description[:300] if description else None,
        scan_types=scan_types,
        color=color,
        is_default=is_default,
        is_public=is_public and (user.role in ("admin", "tenant_admin")),
    )
    session.add(profile)
    session.commit()

    return RedirectResponse(url="/scan-profiles?msg=Profile+created", status_code=303)


@router.post("/scan-profiles/{profile_id}/delete", response_class=HTMLResponse)
async def delete_profile(
    profile_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    profile = session.exec(
        select(ScanProfile).where(
            ScanProfile.id == profile_id,
            ScanProfile.tenant_id == user.tenant_id,
        )
    ).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    session.delete(profile)
    session.commit()
    return RedirectResponse(url="/scan-profiles?msg=Profile+deleted", status_code=303)


@router.post("/scan-profiles/{profile_id}/update", response_class=HTMLResponse)
async def update_profile(
    profile_id: int,
    name: str = Form(...),
    description: str = Form(default=""),
    scan_types: List[str] = Form(default=[]),
    color: str = Form(default="blue"),
    is_default: bool = Form(default=False),
    is_public: bool = Form(default=False),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    """Update an existing scan profile owned by the current tenant."""
    profile = session.exec(
        select(ScanProfile).where(
            ScanProfile.id == profile_id,
            ScanProfile.tenant_id == user.tenant_id,
        )
    ).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    name = name.strip()[:80]
    if not name:
        return RedirectResponse(url="/scan-profiles?error=Name+required", status_code=303)

    valid = {k for k in REGISTRY}
    scan_types = [t for t in scan_types if t in valid or t == "full_scan"]

    if is_default:
        existing_defaults = session.exec(
            select(ScanProfile).where(
                ScanProfile.tenant_id == user.tenant_id,
                ScanProfile.is_default == True,
                ScanProfile.id != profile_id,
            )
        ).all()
        for ep in existing_defaults:
            ep.is_default = False
            session.add(ep)

    profile.name = name
    profile.description = description[:300] if description else None
    profile.scan_types = scan_types
    profile.color = color
    profile.is_default = is_default
    profile.is_public = is_public and (user.role in ("admin", "tenant_admin"))
    from datetime import datetime as _dt
    profile.updated_at = _dt.utcnow()
    session.add(profile)
    session.commit()

    return RedirectResponse(url="/scan-profiles?msg=Profile+updated", status_code=303)


@router.post("/scan-profiles/{profile_id}/set-default", response_class=HTMLResponse)
async def set_default_profile(
    profile_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
):
    # Clear existing defaults
    existing = session.exec(
        select(ScanProfile).where(
            ScanProfile.tenant_id == user.tenant_id,
            ScanProfile.is_default == True,
        )
    ).all()
    for ep in existing:
        ep.is_default = False
        session.add(ep)

    profile = session.exec(
        select(ScanProfile).where(ScanProfile.id == profile_id)
    ).first()
    if profile:
        profile.is_default = True
        session.add(profile)

    session.commit()
    return RedirectResponse(url="/scan-profiles?msg=Default+profile+set", status_code=303)


@router.get("/api/scan-profiles")
async def list_profiles_json(
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    """Return all accessible profiles as JSON — used by the Apply Profile picker in scan panels."""
    profiles = session.exec(
        select(ScanProfile).where(
            (ScanProfile.tenant_id == user.tenant_id) | (ScanProfile.is_public == True)
        ).order_by(ScanProfile.is_default.desc(), ScanProfile.name)
    ).all()
    builtin = [{"id": f"builtin:{p['name']}", "name": p["name"], "scan_types": p["scan_types"], "is_builtin": True} for p in BUILTIN_PROFILES]
    saved = [{"id": p.id, "name": p.name, "scan_types": p.scan_types, "is_default": p.is_default, "is_builtin": False} for p in profiles]
    return {"builtin": builtin, "saved": saved}


@router.get("/api/scan-profiles/{profile_id}")
async def get_profile_json(
    profile_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    """Return profile scan_types as JSON — used by JS to pre-select checkboxes."""
    profile = session.exec(
        select(ScanProfile).where(
            ScanProfile.id == profile_id,
            (ScanProfile.tenant_id == user.tenant_id) | (ScanProfile.is_public == True),
        )
    ).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {"scan_types": profile.scan_types, "name": profile.name}


@router.get("/api/scan-profiles/builtin/{name}")
async def get_builtin_profile(
    name: str,
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    """Return built-in profile scan_types."""
    for p in BUILTIN_PROFILES:
        if p["name"] == name:
            return {"scan_types": p["scan_types"], "name": p["name"]}
    raise HTTPException(status_code=404, detail="Built-in profile not found")
