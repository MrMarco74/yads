"""
Generate Ed25519 keypair for YADS activation code signing.

Run once:
    python scripts/generate_activation_keypair.py

Output:
  - Prints base64-encoded PEM private key → use as --key argument for sign_activation.py
  - Prints ACTIVATION_PUBLIC_KEY value → add to YADS config.env / docker-compose env

Keep the private key secret. The public key goes into YADS as ACTIVATION_PUBLIC_KEY.
The license keypair (sign_license.py) must remain separate.
"""

import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Private key as base64-encoded PEM (input format for sign_activation.py --key)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_b64 = base64.b64encode(private_pem).decode()

    # Public key as base64-encoded PEM (input format for ACTIVATION_PUBLIC_KEY)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_b64 = base64.b64encode(public_pem).decode()

    print("=" * 60)
    print("YADS Activation Keypair generated.")
    print("=" * 60)
    print()
    print("PRIVATE KEY (for sign_activation.py --key, keep secret!):")
    print("-" * 60)
    print(private_b64)
    print()
    print("PUBLIC KEY (add to YADS config.env / docker-compose env):")
    print("-" * 60)
    print(f"ACTIVATION_PUBLIC_KEY={public_b64}")
    print()
    print("Usage:")
    print("  python scripts/sign_activation.py --key <PRIVATE_KEY_ABOVE> --request-code <CODE>")
    print("  or for manual activation:")
    print("  python scripts/sign_activation.py --key <PRIVATE_KEY_ABOVE> --customer-id <UUID> --instance-uuid <UUID>")


if __name__ == "__main__":
    main()
