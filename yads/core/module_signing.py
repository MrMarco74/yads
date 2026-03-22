"""
YADS Official Module Signing
=============================

Provides the YADS-official Ed25519 public key for verifying first-party
module packages, plus the shared verification and auto-signing logic used
by the Plugin Manager upload endpoint and the startup integrity checker.

Public key resolution order (first non-None wins):
  1. settings.MODULE_SIGNING_PUBLIC_KEY  — operator override (custom key)
  2. YADS_OFFICIAL_PUBLIC_KEY            — hardcoded first-party YADS key
  3. None                                — no key configured, unsigned allowed

Auto-signing (Plugin Manager):
  If settings.MODULE_SIGNING_PRIVATE_KEY_PATH points to a valid PEM file,
  the Plugin Manager signs every uploaded ZIP automatically and stores the
  signature in InstalledModule.signature. No external tool needed.

Runtime integrity:
  The SHA-256 hash of each installed .py file is stored in InstalledModule.file_hash
  at upload time and re-verified on every startup via recheck_file_integrity().

Key rotation:
  Generate a new keypair, update YADS_OFFICIAL_PUBLIC_KEY below,
  re-sign all official module packages and ship a new release.
"""

import base64
import hashlib
import logging
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import HTTPException

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# YADS official module-signing public key (Ed25519, PEM, base64-encoded).
# The corresponding private key lives at MODULE_SIGNING_PRIVATE_KEY_PATH
# and is NEVER committed to the repository.
# ---------------------------------------------------------------------------
YADS_OFFICIAL_PUBLIC_KEY: Optional[str] = (
    "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQVdZem9MU0QvMmYyTlpq"
    "dmZwVzVLYklWZENqU3JvdmNNcXdPYUZFenVxY0k9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
)

# ---------------------------------------------------------------------------
# Cached private key (loaded once at first use)
# ---------------------------------------------------------------------------
_cached_private_key: Optional[Ed25519PrivateKey] = None
_private_key_loaded: bool = False


def _load_pubkey(b64: str) -> Optional[Ed25519PublicKey]:
    try:
        raw = base64.b64decode(b64)
        try:
            return serialization.load_pem_public_key(raw)  # type: ignore[return-value]
        except ValueError:
            return serialization.load_der_public_key(raw)  # type: ignore[return-value]
    except Exception as e:
        logger.error("Failed to load module signing public key: %s", e)
        return None


def _resolve_pubkey() -> Optional[Ed25519PublicKey]:
    """Return the active Ed25519 public key using the resolution order."""
    from yads.config import settings

    if settings.MODULE_SIGNING_DISABLED:
        return None

    # 1. Operator override
    if settings.MODULE_SIGNING_PUBLIC_KEY:
        return _load_pubkey(settings.MODULE_SIGNING_PUBLIC_KEY)

    # 2. Hardcoded YADS official key
    if YADS_OFFICIAL_PUBLIC_KEY:
        return _load_pubkey(YADS_OFFICIAL_PUBLIC_KEY)

    return None


def load_signing_key() -> Optional[Ed25519PrivateKey]:
    """
    Load and cache the Ed25519 private key from MODULE_SIGNING_PRIVATE_KEY_PATH.

    Called once at startup (or lazily on first upload). Returns None if no
    key path is configured or the file cannot be read. Logs an error on failure.
    """
    global _cached_private_key, _private_key_loaded
    if _private_key_loaded:
        return _cached_private_key

    _private_key_loaded = True
    from yads.config import settings

    path = settings.MODULE_SIGNING_PRIVATE_KEY_PATH
    if not path:
        return None

    try:
        pem = open(path, "rb").read()
        _cached_private_key = serialization.load_pem_private_key(pem, password=None)  # type: ignore[assignment]
        logger.info("Module signing private key loaded from %s", path)
    except Exception as e:
        logger.error("Failed to load module signing private key from %s: %s", path, e)
        _cached_private_key = None

    return _cached_private_key


def sign_zip(zip_bytes: bytes) -> Optional[str]:
    """
    Sign zip_bytes with the configured private key.

    Returns the base64url-encoded signature (no padding), or None if no
    private key is configured. Never raises.
    """
    key = load_signing_key()
    if key is None:
        return None

    try:
        digest = hashlib.sha256(zip_bytes).digest()
        raw_sig = key.sign(digest)
        return base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()
    except Exception as e:
        logger.error("Auto-signing of module ZIP failed: %s", e)
        return None


def verify_module_signature(zip_bytes: bytes, signature_b64: Optional[str]) -> None:
    """
    Verify an Ed25519 signature over SHA-256(zip_bytes) at upload time.

    If no public key is active, all uploads are allowed (dev mode).
    If a key is active but no signature provided, HTTP 403 is raised.
    If the signature is invalid, HTTP 400 is raised.
    """
    pub = _resolve_pubkey()
    if pub is None:
        return  # No key configured — unsigned modules allowed

    if not signature_b64:
        raise HTTPException(
            status_code=403,
            detail=(
                "Module signing is enforced. "
                "Upload must include a valid Ed25519 signature. "
                "Configure MODULE_SIGNING_PRIVATE_KEY_PATH on this instance "
                "to enable automatic signing via the Plugin Manager."
            ),
        )

    try:
        sig_padded = signature_b64 + "=" * (-len(signature_b64) % 4)
        sig = base64.urlsafe_b64decode(sig_padded)
        digest = hashlib.sha256(zip_bytes).digest()
        pub.verify(sig, digest)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid module signature.")


def compute_file_hash(filepath: str) -> str:
    """Return the hex-encoded SHA-256 hash of a file on disk."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def recheck_file_integrity(filepath: str, stored_hash: Optional[str], module_name: str) -> bool:
    """
    Re-verify the installed .py file against its stored SHA-256 hash at startup.

    Returns True if integrity is confirmed (or no hash stored yet — graceful).
    Returns False if the file has been tampered with; logs CRITICAL and deactivates.
    """
    if not stored_hash:
        logger.warning(
            "Module '%s' has no stored file hash. "
            "Re-upload via Plugin Manager to register its integrity baseline.",
            module_name,
        )
        return True

    try:
        actual = compute_file_hash(filepath)
    except OSError as e:
        logger.error("Cannot read module file '%s' for integrity check: %s", filepath, e)
        return False

    if actual != stored_hash:
        logger.critical(
            "INTEGRITY VIOLATION: Module '%s' file hash mismatch! "
            "Expected %s, got %s. The module file may have been tampered with. "
            "Module has been deactivated.",
            module_name, stored_hash, actual,
        )
        return False

    return True
