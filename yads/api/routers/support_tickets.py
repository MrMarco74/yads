"""
Support Tickets — YADS-side proxy router.

Customers can view their own bug report tickets and (Pro feature: support_messaging)
send/receive messages with the support team.

Feature gate: `support_messaging` must be in the license features list for write access.
Community / unlicensed instances see tickets read-only; the reply form is hidden.
"""

import base64
import json
import time
import importlib
import logging
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session

from yads.auth.deps import get_current_user_html
from yads.models import User
from yads.api.templating import templates

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/help/support-tickets", tags=["support_tickets"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_engine():
    return importlib.import_module("yads.database").engine


def _portal_settings():
    from yads.config import settings
    return {
        "url": getattr(settings, "SUPPORT_PORTAL_URL", "").rstrip("/"),
        "verify": (
            False if not getattr(settings, "SUPPORT_PORTAL_VERIFY_SSL", True)
            else getattr(settings, "CUSTOM_CA_CERT_PATH", None) or True
        ),
    }


def _build_auth_headers(customer_id: str, report_id: Optional[str], signing_key) -> dict:
    """Sign the canonical payload and return the three auth headers."""
    ts = time.time()
    payload: dict = {"customer_id": customer_id, "timestamp": ts}
    if report_id:
        payload["report_id"] = report_id
    canonical = json.dumps(payload, sort_keys=True).encode()
    sig = base64.b64encode(signing_key.sign(canonical)).decode()
    return {
        "X-Customer-Id": customer_id,
        "X-Timestamp": str(ts),
        "X-Signature": sig,
    }


def _get_license_info(session: Session) -> tuple[Optional[str], object | None]:
    """Return (customer_id, signing_key_or_None) from the current license."""
    from yads.core.license import get_customer_id, get_report_signing_key
    return get_customer_id(session), get_report_signing_key(session)


def _has_messaging_feature(session: Session) -> bool:
    from yads.models import SystemConfig
    from yads.core.license import license_manager
    conf = session.get(SystemConfig, "license_key")
    if conf and conf.value:
        return license_manager.has_feature(conf.value, "support_messaging")
    return False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_class=HTMLResponse)
async def ticket_list(
    request: Request,
    user: User = Depends(get_current_user_html),
):
    from yads.config import settings
    engine = _get_engine()
    with Session(engine) as session:
        customer_id, signing_key = _get_license_info(session)
        has_messaging = _has_messaging_feature(session)

    ps = _portal_settings()
    tickets = []
    error = None

    if customer_id and signing_key and ps["url"]:
        headers = _build_auth_headers(customer_id, None, signing_key)
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=ps["verify"]) as client:
                resp = await client.get(
                    f"{ps['url']}/api/customer/reports",
                    headers=headers,
                )
            if resp.status_code == 200:
                tickets = resp.json().get("reports", [])
            else:
                error = f"Portal antwortete mit HTTP {resp.status_code}"
        except httpx.TimeoutException:
            error = "Support-Portal nicht erreichbar (Timeout)"
        except Exception as e:
            error = str(e)
    elif not ps["url"]:
        error = "Support-Portal URL nicht konfiguriert (Einstellungen)"
    elif not signing_key:
        error = "Lizenz enthält keinen Report-Signing-Key. Bitte Lizenz aktualisieren."

    return templates.TemplateResponse("support_tickets.html", {
        "request": request,
        "user": user,
        "settings": settings,
        "tickets": tickets,
        "has_messaging": has_messaging,
        "error": error,
    })


@router.get("/{report_id}", response_class=HTMLResponse)
async def ticket_detail(
    request: Request,
    report_id: str,
    user: User = Depends(get_current_user_html),
):
    from yads.config import settings
    engine = _get_engine()
    with Session(engine) as session:
        customer_id, signing_key = _get_license_info(session)
        has_messaging = _has_messaging_feature(session)

    ps = _portal_settings()
    thread = None
    error = None

    if customer_id and signing_key and ps["url"]:
        headers = _build_auth_headers(customer_id, report_id, signing_key)
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=ps["verify"]) as client:
                resp = await client.get(
                    f"{ps['url']}/api/customer/reports/{report_id}/messages",
                    headers=headers,
                )
            if resp.status_code == 200:
                thread = resp.json()
            elif resp.status_code == 403:
                error = "Zugriff verweigert — dieses Ticket gehört nicht zu Ihrer Lizenz."
            elif resp.status_code == 404:
                error = "Ticket nicht gefunden."
            else:
                error = f"Portal antwortete mit HTTP {resp.status_code}"
        except httpx.TimeoutException:
            error = "Support-Portal nicht erreichbar (Timeout)"
        except Exception as e:
            error = str(e)
    elif not signing_key:
        error = "Lizenz enthält keinen Report-Signing-Key."

    return templates.TemplateResponse("support_ticket_detail.html", {
        "request": request,
        "user": user,
        "settings": settings,
        "report_id": report_id,
        "thread": thread,
        "has_messaging": has_messaging,
        "error": error,
    })


@router.post("/{report_id}/message", response_class=HTMLResponse)
async def send_message(
    request: Request,
    report_id: str,
    text: str = Form(""),
    user: User = Depends(get_current_user_html),
):
    """Send a message (Pro feature: support_messaging required)."""
    engine = _get_engine()
    with Session(engine) as session:
        if not _has_messaging_feature(session):
            raise HTTPException(status_code=403, detail="support_messaging feature not in license.")
        customer_id, signing_key = _get_license_info(session)

    if not signing_key:
        raise HTTPException(status_code=400, detail="No signing key in license.")

    text = text.strip()[:4000]
    if not text:
        return RedirectResponse(url=f"/help/support-tickets/{report_id}", status_code=303)

    ps = _portal_settings()
    ts = time.time()
    payload = {"customer_id": customer_id, "report_id": report_id, "timestamp": ts}
    canonical = json.dumps(payload, sort_keys=True).encode()
    sig = base64.b64encode(signing_key.sign(canonical)).decode()

    body = {
        "customer_id": customer_id,
        "text": text,
        "timestamp": ts,
        "signature": sig,
    }

    try:
        async with httpx.AsyncClient(timeout=8.0, verify=ps["verify"]) as client:
            resp = await client.post(
                f"{ps['url']}/api/customer/reports/{report_id}/messages",
                json=body,
            )
        if resp.status_code not in (200, 201):
            logger.warning(f"Portal message send failed: HTTP {resp.status_code} — {resp.text[:200]}")
    except Exception as e:
        logger.warning(f"Portal message send error: {e}")

    return RedirectResponse(url=f"/help/support-tickets/{report_id}", status_code=303)
