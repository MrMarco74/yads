"""
Admin endpoints for managing CustomerKey entries.

Triple protection:
  1. Bearer token (ADMIN_TOKEN env var)
  2. IP allowlist (ADMIN_IP_ALLOWLIST env var, CIDR notation)
  3. Ed25519 request signature (ADMIN_PUBLIC_KEY env var + X-Signature / X-Timestamp headers)
"""

import base64
import ipaddress
import json
import os
import time
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session, select

from app.database import get_session
from app.models import CustomerKey

router = APIRouter()

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

_ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
_ADMIN_IP_ALLOWLIST_RAW = os.environ.get(
    "ADMIN_IP_ALLOWLIST", "2a02:8071:63f1:10c0::/64,127.0.0.1"
)
_ADMIN_PUBLIC_KEY_B64 = os.environ.get("ADMIN_PUBLIC_KEY", "")


def _parse_allowlist() -> list:
    """Parse the comma-separated CIDR / IP allowlist."""
    networks = []
    for entry in _ADMIN_IP_ALLOWLIST_RAW.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass  # Skip invalid entries silently
    return networks


_ALLOWLIST = _parse_allowlist()


# ---------------------------------------------------------------------------
# Guard helpers
# ---------------------------------------------------------------------------

def _get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_bearer(authorization: Optional[str]) -> None:
    if not _ADMIN_TOKEN:
        raise HTTPException(status_code=500, detail="ADMIN_TOKEN not configured on server.")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header.")
    token = authorization[len("Bearer "):]
    if token != _ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token.")


def _check_ip(request: Request) -> None:
    client_ip_str = _get_client_ip(request)
    if not _ALLOWLIST:
        return  # No allowlist configured = open (misconfiguration, but don't block)
    try:
        client_addr = ipaddress.ip_address(client_ip_str)
    except ValueError:
        raise HTTPException(status_code=403, detail=f"Cannot parse client IP: {client_ip_str!r}")
    for network in _ALLOWLIST:
        if client_addr in network:
            return
    raise HTTPException(status_code=403, detail=f"IP {client_ip_str} not in allowlist.")


def _check_request_signature(
    body_bytes: bytes,
    x_signature: Optional[str],
    x_timestamp: Optional[str],
) -> None:
    """
    Verify Ed25519 signature of the raw request body.
    Signed message: body_bytes
    Header X-Timestamp must be within 60 seconds of now.
    """
    if not _ADMIN_PUBLIC_KEY_B64:
        raise HTTPException(status_code=500, detail="ADMIN_PUBLIC_KEY not configured on server.")

    if not x_signature:
        raise HTTPException(status_code=401, detail="Missing X-Signature header.")
    if not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing X-Timestamp header.")

    # Check timestamp freshness
    try:
        ts = float(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="X-Timestamp must be a unix timestamp.")

    now = time.time()
    if abs(now - ts) > 60:
        raise HTTPException(
            status_code=401,
            detail=f"X-Timestamp too old or too far in the future (delta={abs(now - ts):.0f}s).",
        )

    # Verify signature
    try:
        pub_raw = base64.b64decode(_ADMIN_PUBLIC_KEY_B64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_raw)
        sig_bytes = base64.b64decode(x_signature)
        pub_key.verify(sig_bytes, body_bytes)
    except InvalidSignature:
        raise HTTPException(status_code=403, detail="Admin request signature verification failed.")
    except Exception as exc:
        raise HTTPException(status_code=403, detail=f"Signature error: {exc}")


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class UpsertKeyRequest(BaseModel):
    customer_id: str
    public_key_b64: str
    customer_name: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/api/admin/keys", status_code=200)
async def upsert_customer_key(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_signature: Optional[str] = Header(default=None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(default=None, alias="X-Timestamp"),
    session: Session = Depends(get_session),
):
    """
    Register or update a customer's Ed25519 public key.

    Triple-protected: Bearer token + IP allowlist + Ed25519 request signature.
    """
    # Guard 1: Bearer token
    _check_bearer(authorization)

    # Guard 2: IP allowlist
    _check_ip(request)

    # Guard 3: Request signature (signed over raw body)
    body_bytes = await request.body()
    _check_request_signature(body_bytes, x_signature, x_timestamp)

    # Parse body
    try:
        body = UpsertKeyRequest.model_validate_json(body_bytes)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid request body: {exc}")

    # Upsert into CustomerKey table
    existing = session.exec(
        select(CustomerKey).where(CustomerKey.customer_id == body.customer_id)
    ).first()

    now = datetime.now(timezone.utc)

    if existing:
        existing.public_key_b64 = body.public_key_b64
        existing.customer_name = body.customer_name
        existing.last_sync = now
        session.add(existing)
    else:
        new_key = CustomerKey(
            customer_id=body.customer_id,
            customer_name=body.customer_name,
            public_key_b64=body.public_key_b64,
            registered_at=now,
            last_sync=now,
        )
        session.add(new_key)

    session.commit()
    return {"status": "ok", "customer_id": body.customer_id}


@router.get("/api/admin/keys", status_code=200)
async def list_customer_keys(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    session: Session = Depends(get_session),
):
    """
    List all registered customer keys.

    Protected by Bearer token + IP allowlist only (read-only, no body to sign).
    """
    _check_bearer(authorization)
    _check_ip(request)

    keys = session.exec(select(CustomerKey)).all()
    return {
        "keys": [
            {
                "customer_id": k.customer_id,
                "customer_name": k.customer_name,
                "registered_at": k.registered_at.isoformat(),
                "last_sync": k.last_sync.isoformat() if k.last_sync else None,
            }
            for k in keys
        ]
    }
