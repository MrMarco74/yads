
import sys
import json
import base64
import time
import uuid
import argparse
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def _load_private_key(private_key_b64: str):
    """Load Ed25519 private key from base64-encoded PEM bytes (same as sign_license.py)."""
    try:
        private_bytes = base64.b64decode(private_key_b64)
        private_key = serialization.load_pem_private_key(private_bytes, password=None)
    except Exception as e:
        print(f"Error loading private key: {e}")
        sys.exit(1)
    return private_key


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding fix."""
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


def _sign_payload(private_key, payload: dict) -> str:
    """Serialize payload as compact JSON, sign it, return response code string."""
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64url_encode(payload_json)
    signature = private_key.sign(payload_b64.encode("utf-8"))
    signature_b64 = _b64url_encode(signature)
    return f"{payload_b64}.{signature_b64}"


def _print_result(response_code: str, instance_uuid: str, customer_id: str,
                  activated_at: int, exp: int, install_index: int) -> None:
    activated_str = datetime.fromtimestamp(activated_at, tz=timezone.utc).strftime("%Y-%m-%d")
    valid_until_str = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%d")

    print("\n--- ACTIVATION RESPONSE CODE ---")
    print(response_code)
    print("\n--- DETAILS ---")
    print(f"Instance UUID : {instance_uuid}")
    print(f"Customer ID   : {customer_id}")
    print(f"Activated     : {activated_str}")
    print(f"Valid until   : {valid_until_str}")
    print(f"Install index : {install_index}")
    print()
    print("Paste this code into the YADS Support Portal under:")
    print("  Installationen → Aktivierungsanfragen → [Antwort einfügen]")
    print("Or send it directly to the customer.")


def sign_from_request_code(private_key_b64: str, request_code: str,
                            valid_days: int, install_index: int) -> None:
    """Decode an activation request code, build and sign the response."""
    private_key = _load_private_key(private_key_b64)

    # Decode request code (base64url JSON, no signature)
    try:
        request_json = _b64url_decode(request_code)
        request = json.loads(request_json)
    except Exception as e:
        print(f"Error decoding request code: {e}")
        sys.exit(1)

    required = {"instance_uuid", "customer_id", "version"}
    missing = required - set(request.keys())
    if missing:
        print(f"Request code is missing required fields: {missing}")
        sys.exit(1)

    now = int(time.time())
    response_payload = {
        "instance_uuid": request["instance_uuid"],
        "customer_id": request["customer_id"],
        "activated_at": now,
        "exp": now + valid_days * 86400,
        "install_index": install_index,
    }

    print(f"\n[+] Signing activation for instance {request['instance_uuid']}")
    print(f"    Customer ID  : {request['customer_id']}")
    print(f"    Version      : {request.get('version', '?')}")
    print(f"    Install type : {request.get('install_type', '?')}")
    print(f"    Submitted    : {request.get('submitted_at', '?')}")

    response_code = _sign_payload(private_key, response_payload)
    _print_result(
        response_code,
        response_payload["instance_uuid"],
        response_payload["customer_id"],
        response_payload["activated_at"],
        response_payload["exp"],
        install_index,
    )


def sign_manual(private_key_b64: str, customer_id: str, instance_uuid: str,
                valid_days: int, install_index: int) -> None:
    """Manually pre-approve an activation without a request code (airgapped delivery)."""
    private_key = _load_private_key(private_key_b64)

    now = int(time.time())
    response_payload = {
        "instance_uuid": instance_uuid,
        "customer_id": customer_id,
        "activated_at": now,
        "exp": now + valid_days * 86400,
        "install_index": install_index,
    }

    print(f"\n[+] Generating manual activation (no request code).")

    response_code = _sign_payload(private_key, response_payload)
    _print_result(
        response_code,
        response_payload["instance_uuid"],
        response_payload["customer_id"],
        response_payload["activated_at"],
        response_payload["exp"],
        install_index,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sign a YADS Activation Response (offline developer tool).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  1. From request code (customer sends code, you sign it):
       python sign_activation.py --key <b64_pem> --request-code <code> [--valid-days 365] [--install-index 1]

  2. Manual pre-approval (airgapped / no request code):
       python sign_activation.py --key <b64_pem> --customer-id <uuid> --instance-uuid <uuid> [--valid-days 365] [--install-index 1]
        """,
    )
    parser.add_argument(
        "--key",
        required=True,
        help="Base64-encoded PEM private key (same format as sign_license.py --key)",
    )
    parser.add_argument(
        "--request-code",
        metavar="CODE",
        default=None,
        help="Base64url-encoded activation request code from the installer/customer",
    )
    parser.add_argument(
        "--customer-id",
        metavar="UUID",
        default=None,
        help="Customer UUID (required for manual mode when no --request-code is provided)",
    )
    parser.add_argument(
        "--instance-uuid",
        metavar="UUID",
        default=None,
        help="Instance UUID (required for manual mode when no --request-code is provided)",
    )
    parser.add_argument(
        "--valid-days",
        type=int,
        default=365,
        help="Activation validity in days (default: 365)",
    )
    parser.add_argument(
        "--install-index",
        type=int,
        default=1,
        help="Install index number, e.g. 1 for the first installation (default: 1)",
    )

    args = parser.parse_args()

    if args.request_code:
        sign_from_request_code(
            private_key_b64=args.key,
            request_code=args.request_code,
            valid_days=args.valid_days,
            install_index=args.install_index,
        )
    elif args.customer_id and args.instance_uuid:
        sign_manual(
            private_key_b64=args.key,
            customer_id=args.customer_id,
            instance_uuid=args.instance_uuid,
            valid_days=args.valid_days,
            install_index=args.install_index,
        )
    else:
        parser.error(
            "Provide either --request-code OR both --customer-id and --instance-uuid."
        )
