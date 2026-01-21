
import os
import sys
import json
import base64
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# 1. Load Private Key from file
try:
    with open("license_manager/license_private.pem", "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    print("[OK] Loaded Private Key")
except Exception as e:
    print(f"[FAIL] Load Private Key: {e}")
    sys.exit(1)

# 2. Load Public Key from Config
try:
    # Manual extraction to simulate config import
    import re
    with open("yads/config.py", "r") as f:
        content = f.read()
    match = re.search(r'LICENSE_PUBLIC_KEY: str = "(.*)"', content)
    if not match:
        print("[FAIL] Could not find LICENSE_PUBLIC_KEY in config.py")
        sys.exit(1)
        
    pub_b64 = match.group(1)
    pub_bytes = base64.b64decode(pub_b64)
    pub_key = serialization.load_pem_public_key(pub_bytes)
    print("[OK] Loaded Public Key from Config string")
except Exception as e:
    print(f"[FAIL] Load Public Key: {e}")
    sys.exit(1)

# 3. Test Specific Key provided by user
user_key = "eyJzdWIiOiAiTWFyY28gQURNSU4iLCAibWF4X3RhcmdldHMiOiA1MDAwMDAwLCAiZXhwIjogMTgwMDQ4MjYyNywgImlhdCI6IDE3Njg5NDY2MjcsICJmZWF0dXJlcyI6IFsicmVwb3J0cyIsICJhcGkiLCAic2NoZWR1bGVkX3NjYW5zIiwgIm9zaW50IiwgIndlYmhvb2tzIiwgInRlbmFudHMiXX0.lnPSGb3YAJTnpnjP2xmULOwtkomksxsmy49F2EaO9m-gsVjVi96HzQuyceZBA2HYfr_zkH41l3DnpkvKeyjZBQ"

print(f"Testing User Key: {user_key}")

try:
    parts = user_key.split(".")
    payload_b64 = parts[0]
    sig_b64 = parts[1]
    
    # Re-pad signature
    sig_pad = len(sig_b64) % 4
    if sig_pad > 0:
        sig_b64 += '=' * (4 - sig_pad)
        
    sig_bytes = base64.urlsafe_b64decode(sig_b64)
    
    # Re-pad payload for decoding (just to check content)
    pay_pad = len(payload_b64) % 4
    if pay_pad > 0:
        payload_b64 += '=' * (4 - pay_pad)
    
    # Verify
    pub_key.verify(sig_bytes, parts[0].encode('utf-8'))
    print(f"[PASS] Signature VALID for User Key")
    
    print("Payload:", base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
    
except Exception as e:
    print(f"[FAIL] User Key Verification Failed: {e}")
    # Also verify if the Private Key on disk matches this signature?
    # If config pub key fails, maybe private key signs it OK?
    try:
        priv_key.public_key().verify(sig_bytes, parts[0].encode('utf-8'))
        print("[WARN] Signed with local Private Key (ON DISK), but Config Public Key rejected it.")
        print("       This means Public Key in Config != Private Key on Disk.")
    except Exception as e2:
        print(f"[FAIL] Also failed with local Private Key: {e2}")

