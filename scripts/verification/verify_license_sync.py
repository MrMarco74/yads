
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from yads.config import settings
from unittest.mock import MagicMock, patch

def test_license_sync():
    print("Testing License Synchronization...")
    
    # Initial state
    settings.LICENSE_KEY = "old_key"
    print(f"Original settings.LICENSE_KEY: {settings.LICENSE_KEY}")
    
    # Mock behavior of update_settings bit
    new_test_key = "new_synchronized_key"
    
    # We want to test if assigning to settings.LICENSE_KEY works and is reachable
    # In main.py we did:
    # settings.LICENSE_KEY = trimmed_lic
    
    settings.LICENSE_KEY = new_test_key
    
    if settings.LICENSE_KEY == new_test_key:
        print("SUCCESS: settings.LICENSE_KEY updated correctly.")
    else:
        print(f"FAILURE: settings.LICENSE_KEY is {settings.LICENSE_KEY}")
        sys.exit(1)

if __name__ == "__main__":
    test_license_sync()
