
import os
import sys
from unittest.mock import MagicMock

# Ensure we can import support items if needed
sys.path.append(os.getcwd())

# Import the templates object from support/app/routers/ui.py
try:
    from support.app.routers.ui import templates as support_templates
    print("Support templates imported successfully.")
except ImportError as e:
    print(f"Import failed: {e}")
    sys.exit(1)

def test_support_render():
    print("Testing support template rendering with csrf_token global...")
    mock_request = MagicMock()
    mock_request.scope = {"csrf_token": "support_test_token"}
    
    try:
        # Check if the global is registered
        if 'csrf_token' in support_templates.env.globals:
            print("csrf_token GLobal is registered in support templates!")
        else:
            print("csrf_token Global is NOT registered in support templates!")
            
    except Exception as e:
        print(f"Test failed: {e}")

if __name__ == "__main__":
    test_support_render()
