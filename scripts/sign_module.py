#!/usr/bin/env python3
"""
Custom Module Signing Tool
==========================

Signs YADS custom module ZIPs with an Ed25519 private key so that the
upload endpoint can verify authenticity when MODULE_SIGNING_PUBLIC_KEY
is configured.

Usage
-----
# Generate a new keypair (run once, store private key securely):
  python scripts/sign_module.py --keygen

# Sign a module ZIP:
  python scripts/sign_module.py --sign my_module.zip --key module_signing.key

# Verify a signature (optional sanity check):
  python scripts/sign_module.py --verify my_module.zip --pub module_signing.pub --sig <base64>

The printed base64 signature is passed as the `signature` form field when
uploading via the UI or API.
"""

import argparse
import base64
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _load_private_key(key_path: Path) -> Ed25519PrivateKey:
    raw = key_path.read_bytes()
    return serialization.load_pem_private_key(raw, password=None)  # type: ignore[return-value]


def _load_public_key(pub_path: Path) -> Ed25519PublicKey:
    raw = pub_path.read_bytes()
    return serialization.load_pem_public_key(raw)  # type: ignore[return-value]


def cmd_keygen(args: argparse.Namespace) -> None:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = Path(args.out_key)
    pub_path = Path(args.out_pub)

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    pub_b64 = base64.b64encode(pub_pem).decode()

    print(f"Private key → {priv_path}")
    print(f"Public key  → {pub_path}")
    print()
    print("Set this in config.env (or data/config.env):")
    print(f"  MODULE_SIGNING_PUBLIC_KEY={pub_b64}")
    print()
    print("Keep the private key secret. Never commit it to the repository.")


def cmd_sign(args: argparse.Namespace) -> None:
    zip_path = Path(args.zip)
    if not zip_path.exists():
        print(f"ERROR: {zip_path} does not exist", file=sys.stderr)
        sys.exit(1)

    zip_bytes = zip_path.read_bytes()
    key = _load_private_key(Path(args.key))
    digest = hashlib.sha256(zip_bytes).digest()
    raw_sig = key.sign(digest)
    sig_b64 = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()

    print(f"Module : {zip_path}")
    print(f"SHA-256: {hashlib.sha256(zip_bytes).hexdigest()}")
    print()
    print("Signature (pass as 'signature' form field on upload):")
    print(sig_b64)

    # Write .sig file if requested (useful in CI pipelines)
    if args.out_sig:
        sig_path = Path(args.out_sig)
        sig_path.write_text(sig_b64)
        print(f"\nSignature written to: {sig_path}")


def cmd_verify(args: argparse.Namespace) -> None:
    zip_path = Path(args.zip)
    pub = _load_public_key(Path(args.pub))

    sig_padded = args.sig + "=" * (-len(args.sig) % 4)
    raw_sig = base64.urlsafe_b64decode(sig_padded)
    digest = hashlib.sha256(zip_path.read_bytes()).digest()

    try:
        pub.verify(raw_sig, digest)
        print("Signature VALID.")
    except Exception as e:
        print(f"Signature INVALID: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="YADS custom module signing tool")
    sub = parser.add_subparsers(dest="cmd")

    kg = sub.add_parser("--keygen", help="Generate Ed25519 keypair")
    kg.set_defaults(func=cmd_keygen)
    kg.add_argument("--out-key", default="module_signing.key", help="Private key output path")
    kg.add_argument("--out-pub", default="module_signing.pub", help="Public key output path")

    sg = sub.add_parser("--sign", help="Sign a module ZIP")
    sg.set_defaults(func=cmd_sign)
    sg.add_argument("zip", help="Path to module ZIP")
    sg.add_argument("--key", required=True, help="Path to Ed25519 private key (PEM)")
    sg.add_argument("--out-sig", default=None, metavar="FILE",
                    help="Write the base64 signature to FILE (e.g. my_module.sig) — useful for CI pipelines")

    vf = sub.add_parser("--verify", help="Verify a signature")
    vf.set_defaults(func=cmd_verify)
    vf.add_argument("zip", help="Path to module ZIP")
    vf.add_argument("--pub", required=True, help="Path to Ed25519 public key (PEM)")
    vf.add_argument("--sig", required=True, help="Base64url signature to verify")

    # Support both --keygen and positional subcommand syntax
    args, _ = parser.parse_known_args()

    if not args.cmd:
        # Try treating sys.argv[1] as a flag-style subcommand
        if len(sys.argv) > 1 and sys.argv[1].startswith("--"):
            cmd = sys.argv[1].lstrip("-")
            sys.argv = [sys.argv[0], f"--{cmd}"] + sys.argv[2:]
            args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
