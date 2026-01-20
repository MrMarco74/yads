
import sys
import json
import base64
import time
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def sign_license(private_key_b64, customer, max_targets, expiry_days=365):
    # Load Private Key
    try:
        private_bytes = base64.b64decode(private_key_b64)
        private_key = serialization.load_pem_private_key(
            private_bytes,
            password=None
        )
    except Exception as e:
        print(f"Error loading private key: {e}")
        return

    # Create Payload
    expiration = int(time.time()) + (expiry_days * 86400)
    payload = {
        "sub": customer,
        "max_targets": int(max_targets),
        "exp": expiration,
        "iat": int(time.time())
    }
    
    payload_json = json.dumps(payload).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode('utf-8').rstrip('=')

    # Sign Payload
    signature = private_key.sign(payload_b64.encode('utf-8'))
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

    # Construct License Key
    license_key = f"{payload_b64}.{signature_b64}"
    
    print("\n--- LICENSE KEY ---")
    print(license_key)
    print("\n--- DETAILS ---")
    print(f"Customer: {customer}")
    print(f"Max Targets: {max_targets}")
    print(f"Expires: {expiration}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sign a YADS License")
    parser.add_argument("--key", required=True, help="Base64 encoded Private Key")
    parser.add_argument("--customer", required=True, help="Customer Name")
    parser.add_argument("--limit", required=True, type=int, help="Max Targets")
    parser.add_argument("--days", type=int, default=365, help="Validity in days")
    
    args = parser.parse_args()
    sign_license(args.key, args.customer, args.limit, args.days)
