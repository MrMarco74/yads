"""
Self-service key registration endpoint.

Allows a YADS instance to register its Ed25519 report-signing public key
by proving ownership of a valid, signed YADS license.

No admin credentials required — the license signature itself is the proof.
The portal verifies the license using the YADS license authority public key
(LICENSE_AUTHORITY_PUBLIC_KEY env var, same as YADS's LICENSE_PUBLIC_KEY).
"""

import base64
import json
import os
import time
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select
from datetime import datetime, timezone

from app.database import get_session
from app.models import CustomerKey

router = APIRouter()

# The YADS license authority public key — same value as YADS LICENSE_PUBLIC_KEY.
# Must be set in the support portal environment to enable self-registration.
_LICENSE_AUTHORITY_PUBLIC_KEY_B64 = os.environ.get("LICENSE_AUTHORITY_PUBLIC_KEY", "")

# Optional: rate-limit self-registration attempts (max per customer_id per hour)
_RATE_LIMIT_PER_HOUR = 10
_rate_cache: dict[str, list[float]] = {}


class SelfRegisterRequest(BaseModel):
    license_token: str


def _load_license_authority_key() -> Optional[Ed25519PublicKey]:
    if not _LICENSE_AUTHORITY_PUBLIC_KEY_B64:
        return None
    try:
        raw = base64.b64decode(_LICENSE_AUTHORITY_PUBLIC_KEY_B64)
        try:
            return serialization.load_pem_public_key(raw)
        except Exception:
            return serialization.load_der_public_key(raw)
    except Exception:
        return None


def _verify_license(license_token: str) -> Optional[dict]:
    """Verify a YADS license token and return its payload dict, or None."""
    authority_key = _load_license_authority_key()
    if not authority_key:
        return None

    try:
        payload_b64, signature_b64 = license_token.strip().split(".")

        # Verify signature
        payload_bytes = payload_b64.encode("utf-8")
        sig_pad = len(signature_b64) % 4
        if sig_pad:
            signature_b64 += "=" * (4 - sig_pad)
        signature = base64.urlsafe_b64decode(signature_b64)
        authority_key.verify(signature, payload_bytes)

        # Decode payload
        pay_pad = len(payload_b64) % 4
        if pay_pad:
            payload_b64 += "=" * (4 - pay_pad)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))

        # Check expiry
        if "exp" in payload and payload["exp"] < time.time():
            return None

        return payload

    except (InvalidSignature, Exception):
        return None


def _derive_public_key_b64(report_signing_key_b64: str) -> Optional[str]:
    """Derive Ed25519 public key (base64 raw) from the private key seed in the license."""
    try:
        raw_seed = base64.b64decode(report_signing_key_b64)
        private_key = Ed25519PrivateKey.from_private_bytes(raw_seed)
        pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(pub_bytes).decode()
    except Exception:
        return None


def _check_rate_limit(customer_id: str) -> None:
    now = time.time()
    window = now - 3600
    timestamps = [t for t in _rate_cache.get(customer_id, []) if t > window]
    if len(timestamps) >= _RATE_LIMIT_PER_HOUR:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded — max {_RATE_LIMIT_PER_HOUR} registrations per hour.",
        )
    timestamps.append(now)
    _rate_cache[customer_id] = timestamps


@router.post("/api/register-key", status_code=200)
async def self_register_key(
    body: SelfRegisterRequest,
    session: Session = Depends(get_session),
):
    """
    Self-service: register the Ed25519 report-signing public key for a YADS instance.

    The caller submits their license token. The portal verifies the license signature
    using the YADS license authority public key, then derives and registers the
    report-signing public key from the license payload.

    Returns 200 on success (idempotent — safe to call on every license save).
    Returns 503 if LICENSE_AUTHORITY_PUBLIC_KEY is not configured on the portal.
    Returns 403 if the license token is invalid or expired.
    """
    if not _LICENSE_AUTHORITY_PUBLIC_KEY_B64:
        raise HTTPException(
            status_code=503,
            detail="Self-registration not available: LICENSE_AUTHORITY_PUBLIC_KEY not configured.",
        )

    payload = _verify_license(body.license_token)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid or expired license token.")

    customer_id = payload.get("customer_id")
    customer_name = payload.get("sub") or payload.get("customer_name") or "Unknown"
    report_signing_key_b64 = payload.get("report_signing_key")

    if not customer_id:
        raise HTTPException(status_code=422, detail="License has no customer_id.")
    if not report_signing_key_b64:
        raise HTTPException(status_code=422, detail="License has no report_signing_key.")

    _check_rate_limit(customer_id)

    public_key_b64 = _derive_public_key_b64(report_signing_key_b64)
    if not public_key_b64:
        raise HTTPException(status_code=422, detail="Failed to derive public key from license.")

    # Upsert CustomerKey
    now = datetime.now(timezone.utc)
    existing = session.exec(
        select(CustomerKey).where(CustomerKey.customer_id == customer_id)
    ).first()

    if existing:
        existing.public_key_b64 = public_key_b64
        existing.customer_name = customer_name
        existing.last_sync = now
        session.add(existing)
    else:
        session.add(CustomerKey(
            customer_id=customer_id,
            customer_name=customer_name,
            public_key_b64=public_key_b64,
            registered_at=now,
            last_sync=now,
            is_eos=False,
        ))

    session.commit()
    return {"status": "ok", "customer_id": customer_id, "customer_name": customer_name}
