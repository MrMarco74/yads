"""
POST /api/contact  — public contact form from yads-security.com / yads-security.de
GET  /api/admin/contacts — admin listing for the Support Watcher

Security layers (because script kiddies):
  - CORS: only yads-security.com and yads-security.de
  - Rate limit: 3 requests / hour / IP (in-memory)
  - Honeypot: hidden 'website' field — non-empty = bot → silently drop
  - Input sanitization: strip all HTML tags, max lengths
  - SQLi: SQLModel parameterized queries (safe by design)
  - Suspicious pattern detection: log and reject obvious attack strings
"""

import html
import json
import logging
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlmodel import Session, select

from app.database import get_session
from app.models import ContactRequest

logger = logging.getLogger(__name__)
router = APIRouter()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_ORIGINS = {
    "https://yads-security.com",
    "https://www.yads-security.com",
    "https://yads-security.de",
    "https://www.yads-security.de",
}

MAX_NAME    = 120
MAX_EMAIL   = 200
MAX_COMPANY = 200
MAX_MESSAGE = 2000
MAX_TOPIC   = 40

VALID_TOPICS = {"demo", "support", "sales", "general", "other"}

# Rate limit: 3 submissions / hour / IP
_RATE_DATA: dict[str, list[float]] = defaultdict(list)
_RATE_LOCK  = Lock()
_RATE_LIMIT = 3
_RATE_WINDOW = 3600

# Patterns that smell like attack strings — log and reject
_ATTACK_RE = re.compile(
    r"(<\s*script|javascript\s*:|on\w+\s*=|<\s*iframe|<\s*img[^>]+onerror|"
    r"union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|"
    r"exec\s*\(|eval\s*\(|base64_decode|<\?php|\.\./\.\./)",
    re.IGNORECASE,
)

# Generates IDs like CON-2026-00042
_COUNTER_FILE = "/app/data/contact_counter.txt"


def _next_contact_id() -> str:
    year = datetime.now(timezone.utc).year
    try:
        with open(_COUNTER_FILE) as f:
            n = int(f.read().strip()) + 1
    except (FileNotFoundError, ValueError):
        n = 1
    try:
        os.makedirs(os.path.dirname(_COUNTER_FILE), exist_ok=True)
        with open(_COUNTER_FILE, "w") as f:
            f.write(str(n))
    except OSError:
        pass
    return f"CON-{year}-{n:05d}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate(ip: str) -> None:
    now = time.monotonic()
    with _RATE_LOCK:
        stamps = [t for t in _RATE_DATA[ip] if now - t < _RATE_WINDOW]
        if len(stamps) >= _RATE_LIMIT:
            raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")
        stamps.append(now)
        _RATE_DATA[ip] = stamps


def _sanitize(value: str, max_len: int) -> str:
    """Strip HTML tags, escape entities, enforce max length."""
    # Remove tags
    cleaned = re.sub(r"<[^>]+>", "", value)
    # Escape remaining HTML entities
    cleaned = html.escape(cleaned, quote=True)
    # Collapse excessive whitespace / newlines
    cleaned = re.sub(r"\r\n|\r", "\n", cleaned)
    cleaned = re.sub(r"\n{4,}", "\n\n\n", cleaned)
    return cleaned[:max_len].strip()


def _check_attack(fields: list[str]) -> bool:
    """Return True if any field looks like an attack string."""
    combined = " ".join(fields)
    return bool(_ATTACK_RE.search(combined))


def _cors_headers(origin: str | None) -> dict:
    allowed = origin if origin in ALLOWED_ORIGINS else "https://yads-security.com"
    return {
        "Access-Control-Allow-Origin": allowed,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.options("/api/contact")
async def contact_preflight(request: Request):
    origin = request.headers.get("origin")
    return JSONResponse(content={}, headers=_cors_headers(origin))


@router.post("/api/contact", status_code=201)
async def submit_contact(request: Request):
    """Public contact form endpoint. No auth required."""
    ip     = _client_ip(request)
    origin = request.headers.get("origin")

    # Rate limit
    _check_rate(ip)

    # Parse JSON body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON body.")

    # Honeypot — bots fill 'website', humans don't see it
    if body.get("website"):
        logger.warning("Honeypot triggered from %s", ip)
        # Silently return 201 so bots think it worked
        return JSONResponse(
            status_code=201,
            content={"status": "received"},
            headers=_cors_headers(origin),
        )

    # Extract + sanitize
    name    = _sanitize(str(body.get("name",    "")), MAX_NAME)
    email   = _sanitize(str(body.get("email",   "")), MAX_EMAIL)
    company = _sanitize(str(body.get("company", "")), MAX_COMPANY)
    message = _sanitize(str(body.get("message", "")), MAX_MESSAGE)
    topic   = _sanitize(str(body.get("topic",   "general")), MAX_TOPIC).lower()

    if topic not in VALID_TOPICS:
        topic = "general"

    # Required fields
    if not name or not email or not message:
        raise HTTPException(status_code=422, detail="name, email, and message are required.")

    # Basic email format check
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise HTTPException(status_code=422, detail="Invalid email address.")

    # Attack pattern check — log and reject
    if _check_attack([name, email, company, message]):
        logger.warning("Attack pattern detected from %s: %s", ip,
                       json.dumps({"name": name[:40], "email": email[:40]}))
        raise HTTPException(status_code=400, detail="Invalid input.")

    # Persist
    contact_id = _next_contact_id()
    from app.database import engine
    with Session(engine) as session:
        entry = ContactRequest(
            contact_id=contact_id,
            name=name,
            email=email,
            company=company,
            topic=topic,
            message=message,
            client_ip=ip,
        )
        session.add(entry)
        session.commit()

    logger.info("Contact %s from %s (%s)", contact_id, name, ip)
    return JSONResponse(
        status_code=201,
        content={"status": "received", "contact_id": contact_id},
        headers=_cors_headers(origin),
    )


@router.get("/api/admin/contacts", status_code=200)
async def admin_list_contacts(request: Request):
    """Admin listing — requires Bearer token (same ADMIN_TOKEN)."""
    from app.routers.admin_keys import _check_bearer
    _check_bearer(request.headers.get("Authorization"))

    from app.database import engine
    with Session(engine) as session:
        contacts = session.exec(
            select(ContactRequest).order_by(ContactRequest.submitted_at.desc()).limit(200)
        ).all()

    return {
        "contacts": [
            {
                "contact_id":   c.contact_id,
                "name":         c.name,
                "email":        c.email,
                "company":      c.company,
                "topic":        c.topic,
                "message":      c.message[:200],
                "submitted_at": c.submitted_at.isoformat(),
                "status":       c.status,
            }
            for c in contacts
        ]
    }
