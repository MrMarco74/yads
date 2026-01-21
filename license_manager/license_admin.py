#!/usr/bin/env python3
import os
import sys
import json
import base64
import time
import argparse
from datetime import datetime, timedelta

# Import Core Logic from existing scripts if possible, or reimplement to be standalone
# To make it truly standalone (portable), we should include the logic here or import from local modules if available.
# Since it's for the vendor who has the repo, importing is fine.
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: 'cryptography' library is required. Install it via: pip install cryptography")
    sys.exit(1)

# --- ANSI Colors ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Paths ---
# Default to looking in current dir or scripts dir
KEYS_DIR = "keys"
PRIVATE_KEY_FILE = "license_private.pem"
PUBLIC_KEY_FILE = "license_public.pem"

# --- Operations ---

def setup_keys():
    print(f"\n{Colors.HEADER}--- Setup / Generate Keys ---{Colors.ENDC}")
    if os.path.exists(PRIVATE_KEY_FILE):
        print(f"{Colors.WARNING}Private key '{PRIVATE_KEY_FILE}' already exists.{Colors.ENDC}")
        confirm = input("Overwrite? (y/N): ").lower()
        if confirm != 'y':
            print("Aborted.")
            return

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save Private
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save Public
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"{Colors.GREEN}Successfully generated keys:{Colors.ENDC}")
    print(f" - {PRIVATE_KEY_FILE}")
    print(f" - {PUBLIC_KEY_FILE}")
    
    # Show Public Key Checksum/String for Config
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # The config expects the Base64 of the DER or PEM?
    # Our previous logic in config.py used:
    # `load_pem_public_key` if PEM header is present, OR raw bytes?
    # Let's check `core/license.py`. It uses `serialization.load_pem_public_key` or `load_der_public_key`.
    # Wait, the config just had a string "MC4CAQAwBQYDK2VwBCIEIEd+Rxi8lKTrZdDx6uUopHQ2O5tbbrsHOz8O+QX5yCn6"
    # That looks like DER base64.
    
    encoded = base64.b64encode(pub_bytes).decode('utf-8')
    print(f"\n{Colors.BLUE}Public Key (for YADS Config):{Colors.ENDC}")
    print(encoded)

def load_private_key():
    if not os.path.exists(PRIVATE_KEY_FILE):
        print(f"{Colors.FAIL}Error: '{PRIVATE_KEY_FILE}' not found. Run Setup first.{Colors.ENDC}")
        return None
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key():
    # Try to find file, else ask user
    if os.path.exists(PUBLIC_KEY_FILE):
        with open(PUBLIC_KEY_FILE, "rb") as f:
            return serialization.load_pem_public_key(f.read())
    return None

def issue_license():
    print(f"\n{Colors.HEADER}--- Issue New License ---{Colors.ENDC}")
    priv_key = load_private_key()
    if not priv_key: return

    customer = input("Customer Name: ").strip()
    if not customer:
        print("Customer name required.")
        return

    try:
        limit = int(input("Max Targets (default 5): ") or "5")
    except ValueError:
        print("Invalid number.")
        return

    try:
        days = int(input("Validity (Days, default 365): ") or "365")
    except ValueError:
        print("Invalid number.")
        return

    exp = int(time.time()) + (days * 86400)
    
    # Features
    available_features = ["reports", "api", "scheduled_scans", "osint", "webhooks", "tenants"]
    print(f"\n{Colors.BOLD}Select Features (comma-separated, or 'all'):{Colors.ENDC}")
    print(f"Available: {', '.join(available_features)}")
    feat_input = input("Features > ").strip().lower()
    
    selected_features = []
    if feat_input == 'all':
        selected_features = available_features
    elif feat_input:
        parts = [f.strip() for f in feat_input.split(',')]
        for p in parts:
            if p in available_features:
                selected_features.append(p)
            else:
                print(f"{Colors.WARNING}Ignored unknown feature: {p}{Colors.ENDC}")
    
    # Payload
    payload = {
        "sub": customer,
        "max_targets": limit,
        "exp": exp,
        "iat": int(time.time()),
        "features": selected_features
    }
    payload_json = json.dumps(payload).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode('utf-8').rstrip('=')
    
    # Sign
    signature = priv_key.sign(payload_b64.encode('utf-8'))
    sig_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    
    license_key = f"{payload_b64}.{sig_b64}"
    
    print(f"\n{Colors.GREEN}License Generated!{Colors.ENDC}")
    print(f"Customer: {customer}")
    print(f"Limits: {limit} targets")
    print(f"Expires: {datetime.fromtimestamp(exp)}")
    print(f"\n{Colors.BOLD}License Key:{Colors.ENDC}")
    print(f"{Colors.CYAN}{license_key}{Colors.ENDC}")

def verify_license():
    print(f"\n{Colors.HEADER}--- Verify License ---{Colors.ENDC}")
    key_input = input("Paste License Key: ").strip()
    if not key_input: return
    
    # Load Public Key locally for check
    # Or ask output from setup?
    # For standalone verification, we need the public key.
    pub_key = load_public_key()
    if not pub_key:
        print(f"{Colors.WARNING}Public key file not found. Verification might fail if I can't check signature.{Colors.ENDC}")
        # Could allow user to paste public key string
        pub_str = input("Paste Public Key (Base64 DER) or Enter to skip sig check (Debug only): ").strip()
        if pub_str:
            try:
                der = base64.b64decode(pub_str)
                pub_key = serialization.load_der_public_key(der)
            except Exception as e:
                print(f"Invalid Key: {e}")
                return
    
    try:
        parts = key_input.split('.')
        if len(parts) != 2:
            raise ValueError("Invalid format (expected payload.signature)")
            
        payload_b64 = parts[0]
        sig_b64 = parts[1]
        
        # Add padding back
        payload_b64 += '=' * (-len(payload_b64) % 4)
        sig_b64 += '=' * (-len(sig_b64) % 4)
        
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        sig_bytes = base64.urlsafe_b64decode(sig_b64)
        
        if pub_key:
            try:
                pub_key.verify(sig_bytes, parts[0].encode('utf-8'))
                print(f"{Colors.GREEN}[OK] Signature Verified.{Colors.ENDC}")
            except Exception:
                print(f"{Colors.FAIL}[FAIL] Invalid Signature!{Colors.ENDC}")
        else:
             print(f"{Colors.WARNING}[WARN] Skipping Signature Check (No Public Key){Colors.ENDC}")

        data = json.loads(payload_bytes)
        print(json.dumps(data, indent=2))
        
        # Check Expiry
        exp = data.get("exp", 0)
        remaining = exp - time.time()
        if remaining < 0:
            print(f"{Colors.FAIL}EXPIRED on {datetime.fromtimestamp(exp)}{Colors.ENDC}")
        else:
             days_left = remaining / 86400
             print(f"{Colors.GREEN}Valid until {datetime.fromtimestamp(exp)} ({days_left:.1f} days left){Colors.ENDC}")
             
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

def main():
    while True:
        print(f"\n{Colors.BOLD}=== YADS License Manager ==={Colors.ENDC}")
        print(f"{Colors.BLUE}Working Directory: {os.getcwd()}{Colors.ENDC}")
        if os.path.exists(PRIVATE_KEY_FILE):
             print(f"{Colors.GREEN}Key File Path:     {os.path.abspath(PRIVATE_KEY_FILE)} (Found){Colors.ENDC}")
        else:
             print(f"{Colors.FAIL}Key File Path:     {os.path.abspath(PRIVATE_KEY_FILE)} (NOT FOUND){Colors.ENDC}")
             
        print("1. Issue License")
        print("2. Verify License")
        print("3. Setup / Generate Keys")
        print("q. Quit")
        
        choice = input("\nSelect > ").strip().lower()
        
        if choice == '1': issue_license()
        elif choice == '2': verify_license()
        elif choice == '3': setup_keys()
        elif choice == 'q': break
        else: print("Invalid choice.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting.")
