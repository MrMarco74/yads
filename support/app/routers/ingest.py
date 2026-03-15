"""
POST /api/report — ingest encrypted bug reports from YADS customers.

No application-level authentication; the Ed25519 signature IS the auth.
Rate limited per IP (max 10 requests/hour, in-memory).
"""

import json
import time
from collections import defaultdict
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import Session

from app.crypto import verify_and_decrypt
from app.database import get_session
from app.models import BugReport
from app.report_id import generate_report_id

router = APIRouter()

# ---------------------------------------------------------------------------
# Simple in-memory rate limiter (IP-based, max 10/hour)
# ---------------------------------------------------------------------------
_rate_data: dict[str, list[float]] = defaultdict(list)
_rate_lock = Lock()
_RATE_LIMIT = 10
_RATE_WINDOW = 3600  # seconds


def _check_rate_limit(ip: str) -> None:
    """Raise HTTPException(429) if IP has exceeded the rate limit."""
    now = time.monotonic()
    with _rate_lock:
        # Purge timestamps outside the window
        timestamps = [t for t in _rate_data[ip] if now - t < _RATE_WINDOW]
        if len(timestamps) >= _RATE_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: max {_RATE_LIMIT} reports per hour.",
            )
        timestamps.append(now)
        _rate_data[ip] = timestamps


def _get_client_ip(request: Request) -> str:
    """Return the real client IP, honoring X-Forwarded-For if set."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post("/api/report", status_code=200)
async def ingest_report(
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Accept an encrypted + signed bug report.

    Returns {"report_id": "YAD-2026-00001", "status": "received"} on success.
    Returns HTTP 403 on signature failure.
    Returns HTTP 422 on any other error.
    """
    # Rate limiting
    client_ip = _get_client_ip(request)
    _check_rate_limit(client_ip)

    # Parse JSON body
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Request body must be valid JSON.")

    # Validate top-level structure
    if not isinstance(payload, dict) or "envelope" not in payload or "signature" not in payload:
        raise HTTPException(
            status_code=422,
            detail="Invalid payload structure: expected {envelope, signature}.",
        )

    # Verify signature + decrypt
    try:
        report_data = verify_and_decrypt(payload, session)
    except ValueError as exc:
        msg = str(exc)
        if "signature" in msg.lower():
            raise HTTPException(status_code=403, detail=msg)
        raise HTTPException(status_code=422, detail=msg)

    # Extract metadata from envelope
    envelope = payload["envelope"]
    customer_id = envelope.get("customer_id", "")
    customer_name = envelope.get("customer_name", "")
    tenant_name = envelope.get("tenant_name", "")
    yads_version = envelope.get("yads_version", "")

    # Extract description preview (first 300 chars)
    raw_description = report_data.get("description", "")
    description_preview = str(raw_description)[:300]

    # Extract topic (optional, max 80 chars)
    topic = str(report_data.get("topic", ""))[:80]

    # Generate report ID and persist
    report_id = generate_report_id(session)

    bug_report = BugReport(
        report_id=report_id,
        customer_id=customer_id,
        customer_name=customer_name,
        tenant_name=tenant_name,
        yads_version=yads_version,
        status="new",
        topic=topic,
        description=description_preview,
        full_report=json.dumps(report_data, ensure_ascii=False),
    )
    session.add(bug_report)
    session.commit()

    return {"report_id": report_id, "status": "received"}
