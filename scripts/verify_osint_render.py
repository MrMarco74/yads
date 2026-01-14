import sys
import os
from unittest.mock import MagicMock

# Mock necessary modules before importing yads
sys.path.append(os.getcwd())

# Attempt import
try:
    from yads.api.routers.osint import templates
    from yads.config import settings
except Exception as e:
    print(f"Import failed: {e}")
    sys.exit(1)

# Mock Request
request = MagicMock()
request.path = "/osint"
request.url.path = "/osint"
request.scope = {"type": "http"}

# Mock User
class MockUser:
    username = "test_admin"
    role = "admin"
    tenant_id = None
    allowed_tenants = []

user = MockUser()

# Render Template
try:
    # We rely on the fact that get_available_tenants is now in globals
    # We might fail if DB is not reachable for get_available_tenants, 
    # but that's a different error than "UndefinedError".
    # Assuming DB is reachable or we catch that specific error.
    
    # Actually, base.html calls get_available_tenants() immediately if user.role == admin
    # So we might hit DB.
    
    content = templates.get_template("osint.html").render(
        request=request,
        user=user,
        active_tab="osint"
    )
    
    print("SUCCESS: Template rendered successfully.")
    # Check if sidebar is present (implies base.html loaded)
    if "OSINT Search" in content:
        print("Verified: OSINT Search link found in rendered output.")
        
except Exception as e:
    print(f"FAILURE: Template verification failed: {e}")
    sys.exit(1)
