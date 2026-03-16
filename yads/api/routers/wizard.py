"""
Web-based Setup Wizard
======================
Shown when SETUP_COMPLETE is False (fresh install / wipe+reinstall).
Guides the operator through: license (optional) → admin account → finish.
"""
import os
import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from yads.api.templating import templates
from yads.config import settings

router = APIRouter()
logger = logging.getLogger("yads-wizard")

_TOTAL_STEPS = 3


def _wizard(request: Request, step: int, error: str = "", msg: str = ""):
    return templates.TemplateResponse("setup_wizard.html", {
        "request": request,
        "current_step": step,
        "total_steps": _TOTAL_STEPS,
        "error": error,
        "msg": msg,
    })


@router.get("/wizard", response_class=HTMLResponse)
async def wizard_page(request: Request, step: int = 1):
    if settings.SETUP_COMPLETE:
        return RedirectResponse(url="/login")
    return _wizard(request, step)


@router.post("/wizard/save-license", response_class=HTMLResponse)
async def wizard_save_license(request: Request, license_key: str = Form("")):
    if settings.SETUP_COMPLETE:
        return RedirectResponse(url="/login")
    if license_key.strip():
        import httpx
        try:
            resp = httpx.post(
                f"http://localhost:{os.environ.get('PORT', 8000)}/setup/check-license",
                json={"license_key": license_key.strip()},
                timeout=10,
            )
            if resp.status_code not in (200, 201):
                detail = resp.json().get("detail", resp.text) if "application/json" in resp.headers.get("content-type", "") else resp.text
                return _wizard(request, 1, error=f"Lizenz ungültig: {detail}")
        except Exception as e:
            return _wizard(request, 1, error=f"Verbindungsfehler: {e}")
    return RedirectResponse(url="/wizard?step=2", status_code=303)


@router.post("/wizard/create-admin", response_class=HTMLResponse)
async def wizard_create_admin(
    request: Request,
    username: str = Form("admin"),
    password: str = Form(""),
    password2: str = Form(""),
):
    if settings.SETUP_COMPLETE:
        return RedirectResponse(url="/login")
    if password != password2:
        return _wizard(request, 2, error="Passwörter stimmen nicht überein.")
    if len(password) < 8:
        return _wizard(request, 2, error="Passwort zu kurz (mindestens 8 Zeichen).")
    import httpx
    try:
        resp = httpx.post(
            f"http://localhost:{os.environ.get('PORT', 8000)}/setup/create-admin",
            json={"username": username.strip(), "password": password},
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            detail = resp.json().get("detail", resp.text) if "application/json" in resp.headers.get("content-type", "") else resp.text
            return _wizard(request, 2, error=f"Admin-Erstellung fehlgeschlagen: {detail}")
    except Exception as e:
        return _wizard(request, 2, error=f"Verbindungsfehler: {e}")
    return RedirectResponse(url="/wizard?step=3", status_code=303)


@router.post("/wizard/finish", response_class=HTMLResponse)
async def wizard_finish(request: Request):
    if settings.SETUP_COMPLETE:
        return RedirectResponse(url="/login")
    import httpx
    try:
        resp = httpx.post(
            f"http://localhost:{os.environ.get('PORT', 8000)}/setup/finish",
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            detail = resp.json().get("detail", resp.text) if "application/json" in resp.headers.get("content-type", "") else resp.text
            return _wizard(request, 3, error=f"Finish fehlgeschlagen: {detail}")
    except Exception as e:
        return _wizard(request, 3, error=f"Verbindungsfehler: {e}")
    return RedirectResponse(url="/login?msg=setup_complete", status_code=303)
