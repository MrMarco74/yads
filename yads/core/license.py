
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
            return serialization.load_pem_public_key(public_bytes)
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
            signature = base64.urlsafe_b64decode(signature_b64 + "==")
            
            self.public_key.verify(signature, payload_bytes)
            
            # Decode Payload
            payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode('utf-8')
            data = json.loads(payload_json)
            
            # Check Expiry
            if "exp" in data and data["exp"] < time.time():
                logger.warning("License expired.")
                return None
            
            return data

        except Exception as e:
            logger.error(f"License verification failed: {e}")
            return None

license_manager = LicenseVerifier()
