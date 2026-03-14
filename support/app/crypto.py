"""
Crypto helpers for the YADS Support Portal.

Decrypt and verify incoming bug reports:
1. Ed25519 signature verification (proves the report is from a known customer)
2. X25519 ECDH + HKDF-SHA256 + AES-256-GCM decryption

Matches the exact scheme used in yads/core/bug_report_crypto.py.
"""

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from sqlmodel import Session, select

from app.models import CustomerKey


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _derive_aes_key(shared_secret: bytes) -> bytes:
    """Derive a 32-byte AES key from ECDH shared secret using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"yads-bugreport-v1",
    )
    return hkdf.derive(shared_secret)


def _load_dev_private_key() -> X25519PrivateKey:
    """
    Load the developer's X25519 private key from the path given by the
    DEV_PRIVATE_KEY_FILE env var (default: /app/keys/dev_x25519_private.key).

    The file must contain the raw 32-byte key, base64-encoded (single line).
    """
    key_path = os.environ.get("DEV_PRIVATE_KEY_FILE", "/app/keys/dev_x25519_private.key")
    try:
        raw_b64 = Path(key_path).read_text(encoding="utf-8").strip()
        raw_bytes = base64.b64decode(raw_b64)
        return X25519PrivateKey.from_private_bytes(raw_bytes)
    except FileNotFoundError:
        raise ValueError(f"Developer private key not found at {key_path}")
    except Exception as exc:
        raise ValueError(f"Failed to load developer private key: {exc}") from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_and_decrypt(upload_payload: dict, session: Session) -> dict:
    """
    Verify Ed25519 signature and decrypt the AES-256-GCM ciphertext.

    Expected upload_payload structure (matches build_report_upload):
    {
        "envelope": {
            "customer_id": "...",
            "customer_name": "...",
            "tenant_name": "...",
            "yads_version": "...",
            "encrypted": {
                "ephemeral_pub_b64": "...",
                "nonce_b64": "...",
                "ciphertext_b64": "..."
            }
        },
        "signature": "<base64 Ed25519 signature over canonical JSON of envelope>"
    }

    Returns the decrypted report dict.
    Raises ValueError with a clear message on any failure.
    """
    # --- 1. Extract customer_id ---
    envelope = upload_payload.get("envelope")
    signature_b64 = upload_payload.get("signature")

    if not isinstance(envelope, dict) or not signature_b64:
        raise ValueError("Malformed payload: missing 'envelope' or 'signature'")

    customer_id = envelope.get("customer_id")
    if not customer_id:
        raise ValueError("Malformed envelope: missing 'customer_id'")

    # --- 2. Look up Ed25519 public key ---
    customer_key = session.exec(
        select(CustomerKey).where(CustomerKey.customer_id == customer_id)
    ).first()
    if customer_key is None:
        raise ValueError(f"Unknown customer_id: {customer_id!r}")

    # --- 3. Verify Ed25519 signature ---
    try:
        pub_raw = base64.b64decode(customer_key.public_key_b64)
        ed_pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        canonical = json.dumps(envelope, sort_keys=True, ensure_ascii=False).encode("utf-8")
        sig_bytes = base64.b64decode(signature_b64)
        ed_pub.verify(sig_bytes, canonical)
    except InvalidSignature:
        raise ValueError("Ed25519 signature verification failed")
    except Exception as exc:
        raise ValueError(f"Signature check error: {exc}") from exc

    # --- 4. Load dev X25519 private key ---
    dev_private = _load_dev_private_key()

    # --- 5. ECDH + HKDF + AES-256-GCM decrypt ---
    encrypted = envelope.get("encrypted")
    if not isinstance(encrypted, dict):
        raise ValueError("Malformed envelope: missing 'encrypted' block")

    try:
        ephemeral_pub_raw = base64.b64decode(encrypted["ephemeral_pub_b64"])
        nonce = base64.b64decode(encrypted["nonce_b64"])
        ciphertext = base64.b64decode(encrypted["ciphertext_b64"])
    except (KeyError, Exception) as exc:
        raise ValueError(f"Malformed encrypted block: {exc}") from exc

    try:
        ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_raw)
        shared_secret = dev_private.exchange(ephemeral_pub)
        aes_key = _derive_aes_key(shared_secret)
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError(f"Decryption failed: {exc}") from exc

    # --- 6. Parse and return ---
    try:
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Decrypted payload is not valid JSON: {exc}") from exc
