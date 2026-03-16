"""
Web-based Setup Wizard
======================
Shown when SETUP_COMPLETE is False (fresh install / wipe+reinstall).
Guides the operator through: token verification → license → admin account → finish.
"""
import os
import logging
from typing import Optional

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from yads.api.templating import templates
from yads.config import settings

router = APIRouter()
logger = logging.getLogger("yads-wizard")

_TOTAL_STEPS = 4
_SETUP_TOKEN = os.environ.get("SETUP_TOKEN", "").strip()


def _token_valid(token: str) -> bool:
    """Return True if the provided token is acceptable."""
    if not _SETUP_TOKEN:
        return True  # No token configured → open
    return token == _SETUP_TOKEN


def _wizard(request: Request, step: int, setup_token: str = "",
            error: str = "", msg: str = ""):
    return templates.TemplateResponse("setup_wizard.html", {
        "request": request,
        "current_step": step,
        "total_steps": _TOTAL_STEPS,
        "setup_token": setup_token,
        "error": error,
        "msg": msg,
    })


# ── GET /wizard ────────────────────────────────────────────────────────────────

@router.get("/wizard", response_class=HTMLResponse)
async def wizard_page(request: Request, step: int = 1, token: str = ""):
    if settings.SETUP_COMPLETE:
        return RedirectResponse(url="/login")
    # If no SETUP_TOKEN configured, skip step 1
    if step == 1 and not _SETUP_TOKEN:
        return RedirectResponse(url="/wizard?step=2&token=open")
    return _wizard(request, step, setup_token=token)


# ── Step 1: Verify token ───────────────────────────────────────────────────────

@router.post("/wizard/verify-token", response_class=HTMLResponse)
async def wizard_verify_token(request: Request, token: str = Form("")):
    if settings.SETUP_COMPLETE:
        return RedirectResponse(url="/login")
    if not _token_valid(token):
        return _wizard(request, 1, error="Ungültiger Setup-Token.")
    return RedirectResponse(url=f"/wizard?step=2&token={token}", status_code=303)


# ── Step 2: Save license ───────────────────────────────────────────────────────

@router.post("/wizard/save-license", response_class=HTMLResponse)
async def wizard_save_license(
    request: Request,
    token: str = Form(""),
    license_key: str = Form(""),
):
    if settings.SETUP_COMPLETE:
        return RedirectResponse(url="/login")
    if not _token_valid(token):
        return _wizard(request, 2, setup_token=token, error="Ungültiger Setup-Token.")

    if license_key.strip():
        import httpx
        try:
            resp = httpx.post(
                f"http://localhost:{os.environ.get('PORT', 8000)}/setup/check-license",
                json={"license_key": license_key.strip()},
                params={"token": token},
                timeout=10,
            )
            if resp.status_code not in (200, 201):
                detail = resp.json().get("detail", resp.text) if resp.headers.get("content-type", "").startswith("application/json") else resp.text
                return _wizard(request, 2, setup_token=token, error=f"Lizenz ungültig: {detail}")
        except Exception as e:
            return _wizard(request, 2, setup_token=token, error=f"Verbindungsfehler: {e}")

    return RedirectResponse(url=f"/wizard?step=3&token={token}", status_code=303)


# ── Step 3: Create admin ───────────────────────────────────────────────────────

@router.post("/wizard/create-admin", response_class=HTMLResponse)
async def wizard_create_admin(
    request: Request,
    token: str = Form(""),
    username: str = Form("admin"),
    password: str = Form(""),
    password2: str = Form(""),
):
    if settings.SETUP_COMPLETE:
        return RedirectResponse(url="/login")
    if not _token_valid(token):
        return _wizard(request, 3, setup_token=token, error="Ungültiger Setup-Token.")
    if password != password2:
        return _wizard(request, 3, setup_token=token, error="Passwörter stimmen nicht überein.")
    if len(password) < 8:
        return _wizard(request, 3, setup_token=token, error="Passwort zu kurz (mindestens 8 Zeichen).")

    import httpx
    try:
        resp = httpx.post(
            f"http://localhost:{os.environ.get('PORT', 8000)}/setup/create-admin",
            json={"username": username.strip(), "password": password},
            params={"token": token},
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            detail = resp.json().get("detail", resp.text) if resp.headers.get("content-type", "").startswith("application/json") else resp.text
            return _wizard(request, 3, setup_token=token, error=f"Admin-Erstellung fehlgeschlagen: {detail}")
    except Exception as e:
        return _wizard(request, 3, setup_token=token, error=f"Verbindungsfehler: {e}")

    return RedirectResponse(url=f"/wizard?step=4&token={token}", status_code=303)


# ── Step 4: Finish ─────────────────────────────────────────────────────────────

@router.post("/wizard/finish", response_class=HTMLResponse)
async def wizard_finish(request: Request, token: str = Form("")):
    if settings.SETUP_COMPLETE:
        return RedirectResponse(url="/login")
    if not _token_valid(token):
        return _wizard(request, 4, setup_token=token, error="Ungültiger Setup-Token.")

    import httpx
    try:
        resp = httpx.post(
            f"http://localhost:{os.environ.get('PORT', 8000)}/setup/finish",
            params={"token": token},
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            detail = resp.json().get("detail", resp.text) if resp.headers.get("content-type", "").startswith("application/json") else resp.text
            return _wizard(request, 4, setup_token=token, error=f"Finish fehlgeschlagen: {detail}")
    except Exception as e:
        return _wizard(request, 4, setup_token=token, error=f"Verbindungsfehler: {e}")

    return RedirectResponse(url="/login?msg=setup_complete", status_code=303)
