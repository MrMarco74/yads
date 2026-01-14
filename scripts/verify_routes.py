from fastapi import FastAPI
from yads.api.main import app
import sys

# Check routes
found = False
for route in app.routes:
    if route.path == "/osint/search":
        print(f"Verified Route: {route.path} -> {route.name}")
        found = True

if found:
    print("SUCCESS: OSINT router registered.")
    sys.exit(0)
else:
    print("FAILURE: OSINT router NOT found.")
    sys.exit(1)
