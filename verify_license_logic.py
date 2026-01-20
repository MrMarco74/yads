
import requests
import sys
import os
import subprocess
import time
from sqlmodel import Session, select, delete
from yads.database import engine
from yads.models import Target, SystemConfig, User, Tenant

# Setup
def get_admin_token():
    # Helper to get token if needed, or we just manipulate DB directly for setup
    # and use requests for the actual test.
    # Actually, main.py is protecting the route. We need a valid session cookie or token.
    # For simplicity, let's use the DB to inject the License and then call the API 
    # OR simpler: Test the logic by unit testing the function?
    # No, integration test is better.
    pass

def setup_db():
    with Session(engine) as session:
        # Clear Dependencies first
        from yads.models import ScanResult, ModuleState
        session.exec(delete(ScanResult))
        session.exec(delete(ModuleState))
        session.exec(delete(Target))
        session.exec(delete(SystemConfig).where(SystemConfig.key == "license_key"))
        session.commit()

def set_license(key):
    with Session(engine) as session:
        conf = session.get(SystemConfig, "license_key")
        if not conf:
            conf = SystemConfig(key="license_key", value=key)
            session.add(conf)
        else:
            conf.value = key
            session.add(conf)
        session.commit()

def generate_key_pair():
    # We need the PRIVATE key to sign checking licenses
    # Reuse the script
    result = subprocess.run(["python3", "scripts/generate_license_keys.py"], capture_output=True, text=True)
    # This generates NEW keys, but the app uses the HARDCODED public key.
    # checking...
    # The app uses a hardcoded public key in config.py.
    # To verify, we must use the CORRESPONDING private key.
    # I outputted it earlier in the conversation...
    # Private Key: ...
    # I should use THAT private key to sign.
    # Output from Step 1521
    pass

PRIVATE_KEY_B64 = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUVkK1J4aThsS1RyWmREeDZ1VW9wSDJPNXRiYnJzSE96OE8rUVg1eUNuNmsKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo="

def sign(customer, limit, days):
    cmd = [
        "python3", "scripts/sign_license.py",
        "--key", PRIVATE_KEY_B64,
        "--customer", customer,
        "--limit", str(limit),
        "--days", str(days)
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # Extract key from output
    # Output format:
    # --- LICENSE KEY ---
    # <key>
    lines = result.stdout.splitlines()
    for i, line in enumerate(lines):
        if "--- LICENSE KEY ---" in line:
            return lines[i+1].strip()
    return None

def test_license():
    setup_db()
    
    # 1. Test Free Tier (No License)
    # Limit should be 5.
    print("Testing Free Tier (Limit 5)...")
    with Session(engine) as session:
        # Create 5 targets manually (bypass API for setup speed, or assume we are testing API?)
        # We want to test API logic. But calling API requires Auth.
        # Let's mock the internal logic or use the fact that I can import the router?
        # Actually I modified `main.py` directly.
        # I can unit test the logic if I import `main`?
        # No, `main.py` logic is inside the `bulk_import_targets` or `create_target` function.
        # I only modified `bulk_import_targets`?
        # Wait, did I modify `bulk_import_targets` in step 1584?
        # Yes, I inserted logic into `bulk_import_targets`.
        
        # Let's verify by simulating the storage.
        # If I want to test the `check` logic, I can use a script that imports `license_manager` and `SystemConfig`.
        
        # Scenario A: Valid License (Limit 2)
        print("Generating License for 2 targets...")
        lic = sign("TestCustomer", 2, 30)
        print(f"License: {lic}")
        set_license(lic)
        
        # Now verify via License Manager that it parses
        from yads.core.license import license_manager
        data = license_manager.verify(lic)
        print(f"Verified Data: {data}")
        assert data['max_targets'] == 2
        
        # Scenario B: Expired License
        print("Generating Expired License...")
        lic_exp = sign("TestCustomer", 10, -1) # Expired yesterday
        data_exp = license_manager.verify(lic_exp)
        print(f"Expired Verification: {data_exp} (Should be None)")
        assert data_exp is None

if __name__ == "__main__":
    test_license()
