"""
Bug Report Crypto

Encrypt-then-Sign for secure bug report upload to support.yads-security.com:

1. ENCRYPTION  (X25519 ECDH + AES-256-GCM)
   - Ephemeral X25519 keypair generated per report
   - ECDH with developer's static public key → shared secret
   - HKDF → AES-256-GCM key
   - Report JSON encrypted; only developer can decrypt with their private key

2. SIGNATURE  (Ed25519)
   - Entire encrypted payload signed with customer's license signing key
   - Support portal verifies signature using stored public key for that customer_id
   - Proves authenticity: report came from a legitimate licensed customer
"""

import base64
import json
import os
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


def _derive_aes_key(shared_secret: bytes) -> bytes:
    """Derive a 32-byte AES key from ECDH shared secret using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"yads-bugreport-v1",
    )
    return hkdf.derive(shared_secret)


def encrypt_report(report_dict: dict, dev_public_key_b64: str) -> dict:
    """
    Encrypt report_dict with the developer's X25519 public key.

    Returns a dict with:
      ephemeral_pub_b64, nonce_b64, ciphertext_b64
    """
    # Load developer public key (raw 32 bytes)
    dev_pub_raw = base64.b64decode(dev_public_key_b64)
    dev_public_key = X25519PublicKey.from_public_bytes(dev_pub_raw)

    # Generate ephemeral keypair
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    # ECDH → shared secret → AES key
    shared_secret = ephemeral_private.exchange(dev_public_key)
    aes_key = _derive_aes_key(shared_secret)

    # Encrypt
    nonce = os.urandom(12)
    plaintext = json.dumps(report_dict, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    ephemeral_pub_raw = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return {
        "ephemeral_pub_b64": base64.b64encode(ephemeral_pub_raw).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
    }


def sign_payload(payload_dict: dict, signing_key: Ed25519PrivateKey) -> str:
    """
    Sign the canonical JSON of payload_dict with customer's Ed25519 key.
    Returns base64-encoded signature.
    """
    canonical = json.dumps(payload_dict, sort_keys=True, ensure_ascii=False).encode("utf-8")
    signature = signing_key.sign(canonical)
    return base64.b64encode(signature).decode()


def build_report_upload(
    report_dict: dict,
    customer_id: str,
    customer_name: str,
    tenant_name: str,
    yads_version: str,
    signing_key: Ed25519PrivateKey,
    dev_public_key_b64: str,
) -> dict:
    """
    Build the full upload payload: encrypt report + sign everything.

    Returns the dict ready for JSON POST to /api/report.
    """
    # Envelope: public metadata + encrypted body
    envelope = {
        "customer_id": customer_id,
        "customer_name": customer_name,
        "tenant_name": tenant_name,
        "yads_version": yads_version,
        "encrypted": encrypt_report(report_dict, dev_public_key_b64),
    }

    # Sign the entire envelope
    signature = sign_payload(envelope, signing_key)

    return {
        "envelope": envelope,
        "signature": signature,
    }
