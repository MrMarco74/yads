import sys
import os
sys.path.append(os.getcwd())

from fastapi import FastAPI
from fastapi.testclient import TestClient

try:
    print("Importing schedules...")
    from yads.api.routers import schedules
    print("Schedules imported.")
    
    print("Importing osint...")
    from yads.api.routers import osint
    print("Osint imported.")
    
    print("Importing reports...")
    from yads.api.routers import reports
    print("Reports imported.")

    print("Success.")
except Exception as e:
    print(f"FAILED: {e}")
    import traceback
    traceback.print_exc()
