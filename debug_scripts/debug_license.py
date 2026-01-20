
import sys
import os
import base64
import json
import logging

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# The Key Provided by User
TEST_LICENSE_KEY = "eyJzdWIiOiAiTWFyY28gQURNSU4iLCAibWF4X3RhcmdldHMiOiA1MDAwMDAwLCAiZXhwIjogMTgwMDQ3ODQ0NCwgImlhdCI6IDE3Njg5NDI0NDQsICJmZWF0dXJlcyI6IFsicmVwb3J0cyIsICJhcGkiLCAic2NoZWR1bGVkX3NjYW5zIiwgIm9zaW50IiwgIndlYmhvb2tzIl19.t5yLGUpUTO0REUsJXyVqM0bSTAM7KBwgFHePNTF9NyBVjtUMdQJWS_dBlQzaB8fl0JTlcNu-1abpbpB0gTq9Dw"

# The Public Key currently in config.py (Decoded from my previous step)
# "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQUlERXowK3pCRFd1OHNTSzJPMnNyR1A3WHVBVTR3MFhRL0c0WGhQWkFVNk09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
CONFIG_PUBLIC_KEY_B64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQUlERXowK3pCRFd1OHNTSzJPMnNyR1A3WHVBVTR3MFhRL0c0WGhQWkFVNk09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="

def test_verify():
    print("--- Debugging License Verification ---")
    
    # 1. Load Public Key
    try:
        public_bytes = base64.b64decode(CONFIG_PUBLIC_KEY_B64)
        print(f"Loaded Public Key Bytes: {len(public_bytes)} bytes")
        # print(public_bytes.decode('utf-8'))
        
        public_key = serialization.load_pem_public_key(public_bytes)
        print("Successfully loaded PEM Public Key via serialization.")
    except Exception as e:
        print(f"FAILED to load Public Key: {e}")
        return

    # 1b. Load Private Key to check consistency
    try:
        with open("license_manager/license_private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        derived_public = private_key.public_key()
        derived_bytes = derived_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(f"Derived Public Key from Private Key: {len(derived_bytes)} bytes")
        
        # Check if derived matches loaded
        if derived_bytes.strip() == public_bytes.strip():
            print("MATCH: license_private.pem corresponds to the public key in config/file.")
        else:
            print("MISMATCH: license_private.pem does NOT match license_public.pem!")
            print(f"Public Config: {public_bytes[:20]}...")
            print(f"Derived Priv:  {derived_bytes[:20]}...")

    except Exception as e:
        print(f"Could not load/check private key: {e}")

    # 2. Verify License
    try:
        payload_b64, signature_b64 = TEST_LICENSE_KEY.split(".")
        print(f"Split Key OK. Payload len: {len(payload_b64)}, Sig len: {len(signature_b64)}")
        
        # Decode Sig
        signature = base64.urlsafe_b64decode(signature_b64 + "==")
        print(f"Signature Bytes: {len(signature)} bytes (Expected 64 for Ed25519)")
        
        # Verify with Config Key
        try:
            public_key.verify(signature, payload_b64.encode('utf-8'))
            print("Signature OK with Config Public Key!")
        except Exception as e:
            print(f"Signature FAILED with Config Public Key: {e}")

        # Verify with Derived Private Key (if available)
        if 'derived_public' in locals():
            try:
                derived_public.verify(signature, payload_b64.encode('utf-8'))
                print("Signature OK with DERIVED Public Key (from private.pem)!")
            except Exception as e:
                print(f"Signature FAILED with DERIVED Public Key: {e}")
        
        # Decode Payload
        payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode('utf-8')
        data = json.loads(payload_json)
        print("Payload:", json.dumps(data, indent=2))
        
    except Exception as e:
        print(f"VERIFICATION ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_verify()
