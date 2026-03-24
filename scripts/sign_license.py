
import sys
import json
import base64
import time
import uuid
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_report_signing_keypair():
    """Generate a fresh Ed25519 keypair for bug report signing."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return (
        base64.b64encode(private_raw).decode(),
        base64.b64encode(public_raw).decode()
    )


def sign_license(private_key_b64, customer, max_targets, expiry_days=365,
                 customer_id=None, report_signing_private=None, report_signing_public=None,
                 domains=None):
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

    # Generate customer_id if not provided
    if not customer_id:
        customer_id = str(uuid.uuid4())

    # Generate report signing keypair if not provided
    if not report_signing_private:
        report_signing_private, report_signing_public = generate_report_signing_keypair()
        print(f"\n[+] Generated report signing keypair for customer.")

    # Create Payload
    expiration = int(time.time()) + (expiry_days * 86400)
    payload = {
        "sub": customer,
        "customer_id": customer_id,
        "max_targets": int(max_targets),
        "exp": expiration,
        "iat": int(time.time()),
        "report_signing_key": report_signing_private,
    }
    if domains:
        payload["domains"] = sorted(set(domains))

    payload_json = json.dumps(payload, sort_keys=True).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode('utf-8').rstrip('=')

    # Sign Payload
    signature = private_key.sign(payload_b64.encode('utf-8'))
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

    # Construct License Key
    license_key = f"{payload_b64}.{signature_b64}"

    print("\n--- LICENSE KEY ---")
    print(license_key)
    print("\n--- DETAILS ---")
    print(f"Customer     : {customer}")
    print(f"Customer ID  : {customer_id}")
    print(f"Max Targets  : {max_targets}")
    print(f"Expires      : {expiration}")
    print(f"\n--- REPORT SIGNING KEY (Public) ---")
    print(f"Store this in the License Manager / Support Portal:")
    print(f"customer_id  : {customer_id}")
    print(f"public_key   : {report_signing_public}")
    if domains:
        print(f"\n[+] Embedded {len(payload['domains'])} allowed domains in license payload.")

    return license_key, customer_id, report_signing_public


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sign a YADS License")
    parser.add_argument("--key", required=True, help="Base64 encoded Private Key (PEM)")
    parser.add_argument("--customer", required=True, help="Customer Name")
    parser.add_argument("--limit", required=True, type=int, help="Max Targets")
    parser.add_argument("--days", type=int, default=365, help="Validity in days")
    parser.add_argument("--customer-id", default=None, help="Existing customer UUID (optional)")
    parser.add_argument("--domains-file", default=None,
                        help="Path to a text file with one domain per line to embed as allowed domains")

    args = parser.parse_args()

    domains = None
    if args.domains_file:
        with open(args.domains_file) as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"[+] Loaded {len(domains)} domains from {args.domains_file}")

    sign_license(args.key, args.customer, args.limit, args.days,
                 customer_id=args.customer_id, domains=domains)
