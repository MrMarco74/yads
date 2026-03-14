"""
Generate X25519 keypair for YADS Support Portal bug report encryption.

Run once:
    python scripts/generate_support_keypair.py

Output:
  - support/keys/dev_x25519_private.key  (keep secret, deploy to PROD manually)
  - prints public key → paste into yads/config.py as SUPPORT_DEV_PUBLIC_KEY
"""

import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


def main():
    # Generate X25519 keypair
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize private key (PEM)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key (raw 32 bytes → base64)
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    public_b64 = base64.b64encode(public_raw).decode()

    # Write private key to support/keys/
    keys_dir = Path(__file__).parent.parent / "support" / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    key_path = keys_dir / "dev_x25519_private.key"
    key_path.write_bytes(private_pem)
    key_path.chmod(0o600)

    print("=" * 60)
    print("X25519 Keypair generated successfully.")
    print("=" * 60)
    print(f"\nPrivate key saved to: {key_path}")
    print("⚠️  Keep this file secret. Deploy it manually to PROD.")
    print("   It must NOT be committed to git (already in .gitignore).")
    print()
    print("Add the following to yads/config.py (SUPPORT_DEV_PUBLIC_KEY):")
    print("-" * 60)
    print(f"SUPPORT_DEV_PUBLIC_KEY: str = \"{public_b64}\"")
    print("-" * 60)
    print()
    print("And to your support portal config / docker-compose env:")
    print(f"SUPPORT_DEV_PUBLIC_KEY={public_b64}")


if __name__ == "__main__":
    main()
