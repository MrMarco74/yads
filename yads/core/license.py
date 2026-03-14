
import json
import base64
import time
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from yads.config import settings
import logging

logger = logging.getLogger(__name__)

class LicenseVerifier:
    def __init__(self):
        self.public_key_b64 = settings.LICENSE_PUBLIC_KEY
        self.public_key = self._load_public_key()

    def _load_public_key(self) -> Optional[ed25519.Ed25519PublicKey]:
        if not self.public_key_b64:
            logger.warning("No LICENSE_PUBLIC_KEY configured.")
            return None
        try:
            public_bytes = base64.b64decode(self.public_key_b64)
            try:
                return serialization.load_pem_public_key(public_bytes)
            except ValueError:
                # Try DER
                return serialization.load_der_public_key(public_bytes)
        except Exception as e:
            logger.error(f"Failed to load license public key: {e}")
            return None

    def verify(self, license_key: str) -> Optional[Dict[str, Any]]:
        """
        Verifies the license key (Payload.Signature).
        Returns the payload dict if valid and not expired.
        Returns None if invalid.
        """
        if not license_key or not self.public_key:
            return None

        try:
            payload_b64, signature_b64 = license_key.split(".")
            
            # Verify Signature
            payload_bytes = payload_b64.encode('utf-8')
            
            # Robust Padding for Signature
            sig_pad = len(signature_b64) % 4
            if sig_pad > 0:
                signature_b64 += '=' * (4 - sig_pad)
            signature = base64.urlsafe_b64decode(signature_b64)
            
            self.public_key.verify(signature, payload_bytes)
            
            # Decode Payload
            pay_pad = len(payload_b64) % 4
            if pay_pad > 0:
                payload_b64 += '=' * (4 - pay_pad)
                
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            data = json.loads(payload_json)
            
            # Check Expiry
            if "exp" in data and data["exp"] < time.time():
                logger.warning("License expired.")
                return None
            
            return data

        except Exception as e:
            logger.error(f"License verification failed: {e}")
            return None

    def has_feature(self, license_key: str, feature: str) -> bool:
        data = self.verify(license_key)
        if not data:
            return False
        
        features = data.get("features", [])
        if feature in features:
            return True
            
        return False

    def get_license_status(self, session) -> Dict[str, Any]:
        """
        Returns a rich status object for UI warnings:
        {
            "tier": "CE" | "Commercial",
            "status": "active" | "warning" | "error",
            "message": "...",
            "target_count": 123,
            "max_targets": 500,
            "pct_used": 24.6,
            "expires_at": datetime | None
        }
        """
        from yads.models import Target, SystemConfig
        from yads.core.community_edition import get_ce_state
        from sqlmodel import select, func

        # 1. Total Target Count
        target_count = session.exec(select(func.count()).select_from(Target)).one()

        # 2. Check Commercial License
        license_conf = session.get(SystemConfig, "license_key")
        lic_data = None
        if license_conf and license_conf.value:
            lic_data = self.verify(license_conf.value)

        if lic_data:
            max_targets = lic_data.get("max_targets", 5)
            # Use float to avoid integer division issues in other Python versions if any
            pct = (target_count / max_targets) * 100 if max_targets > 0 else 100
            
            exp_ts = lic_data.get("exp")
            from datetime import datetime
            expires_at = datetime.fromtimestamp(exp_ts) if exp_ts else None
            
            status = "active"
            message = ""
            if pct >= 100:
                status = "error"
                message = f"Lizenzlimit erreicht ({target_count}/{max_targets}). Keine neuen Scans möglich."
            elif pct >= 80:
                status = "warning"
                message = f"Lizenzlimit fast erreicht ({target_count}/{max_targets})."

            return {
                "tier": "Commercial",
                "status": status,
                "message": message,
                "target_count": target_count,
                "max_targets": max_targets,
                "pct_used": round(pct, 1),
                "expires_at": expires_at
            }

        # 3. Fallback to Community Edition
        ce = get_ce_state(session)
        if ce["edition"] == "community":
            max_targets = ce["max_targets"]
            pct = (target_count / max_targets) * 100 if max_targets > 0 else 100
            
            status = "active"
            message = ""
            if ce["status"] == "read_only":
                status = "error"
                message = "Community Edition abgelaufen. System im Lesemodus."
            elif pct >= 100:
                status = "error"
                message = f"CE-Limit erreicht ({target_count}/{max_targets})."
            elif pct >= 80:
                status = "warning"
                message = f"CE-Limit fast erreicht ({target_count}/{max_targets})."
            elif ce["days_remaining"] < 5:
                 status = "warning"
                 message = f"Community Edition läuft in {ce['days_remaining']} Tagen ab."

            return {
                "tier": "CE",
                "status": status,
                "message": message,
                "target_count": target_count,
                "max_targets": max_targets,
                "pct_used": round(pct, 1),
                "expires_at": ce["expires_at"]
            }

        # 4. No License / Classic Free tier (legacy)
        return {
            "tier": "Free",
            "status": "warning" if target_count >= 5 else "active",
            "message": "Keine Lizenz aktiv. (Limit: 5 Targets)" if target_count >= 5 else "",
            "target_count": target_count,
            "max_targets": 5,
            "pct_used": (target_count / 5) * 100,
            "expires_at": None
        }


license_manager = LicenseVerifier()


def _get_license_payload(session) -> Optional[Dict[str, Any]]:
    """Return decoded license payload dict, or None."""
    from yads.models import SystemConfig
    conf = session.get(SystemConfig, "license_key")
    if not conf or not conf.value:
        return None
    return license_manager.verify(conf.value)


def get_customer_id(session) -> Optional[str]:
    """Return customer_id from license payload, or None."""
    payload = _get_license_payload(session)
    return payload.get("customer_id") if payload else None


def get_report_signing_key(session):
    """
    Return Ed25519PrivateKey for bug report signing, or None.
    The key is stored as base64-encoded raw 32-byte seed in the license payload.
    """
    payload = _get_license_payload(session)
    if not payload:
        return None
    key_b64 = payload.get("report_signing_key")
    if not key_b64:
        return None
    try:
        raw = base64.b64decode(key_b64)
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as e:
        logger.error(f"Failed to load report signing key: {e}")
        return None


def get_customer_name(session) -> Optional[str]:
    """Return customer name (sub field) from license payload, or None."""
    payload = _get_license_payload(session)
    return payload.get("sub") if payload else None
