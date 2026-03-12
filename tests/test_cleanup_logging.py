import pytest
import logging
from unittest.mock import patch, MagicMock
import sys
import os

# Ensure the project root is in the path to find yads and debug_scripts
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

# Dynamically import run_cleanup from debug_scripts/cleanup_wildcards.py
# This assumes debug_scripts is directly in the project root after the sys.path.insert
try:
    from debug_scripts.cleanup_wildcards import run_cleanup
    # We need to re-import the logger to ensure we get the (potentially updated) one
    # or mock it directly in the test.
    from debug_scripts import cleanup_wildcards
except ImportError:
    # Fallback for environments where debug_scripts might be treated differently
    # Or if the module is not found, provide a clear error.
    print("Error: Could not import cleanup_wildcards. Make sure debug_scripts is accessible.")
    sys.exit(1)


@pytest.fixture
def mock_session():
    with patch('yads.database.SessionLocal') as mock_session_local:
        with patch('yads.database.engine') as mock_engine:
            mock_session_obj = MagicMock()
            mock_session_local.return_value = mock_session_obj
            yield mock_session_obj

@pytest.fixture
def mock_targets():
    # Mock Target objects for testing
    mock_target1 = MagicMock()
    mock_target1.id = 1
    mock_target1.domain = "example.com"

    mock_target2 = MagicMock()
    mock_target2.id = 2
    mock_target2.domain = "sub.example.org"

    # A "malicious" domain to test log injection if f-strings were still used
    mock_target3 = MagicMock()
    mock_target3.id = 3
    mock_target3.domain = "malicious.com\nCRITICAL: ATTACK DETECTED!"
    
    return [mock_target1, mock_target2, mock_target3]

def test_cleanup_logging_security(mock_session, mock_targets, caplog):
    caplog.set_level(logging.INFO)

    # Mock the session.exec calls to return our mock targets
    mock_session.exec.return_value.all.return_value = mock_targets

    # Mock dns.resolver components to avoid actual network calls
    with patch('dns.resolver.Resolver') as MockResolver:
        with patch('debug_scripts.cleanup_wildcards.detect_wildcard', return_value=set()): # Assume no wildcards for simplicity
            mock_resolver_instance = MockResolver.return_value
            mock_resolver_instance.resolve.return_value = [MagicMock(address='192.0.2.1')]

            # Run the cleanup function
            run_cleanup()

            # Assertions for secure logging
            # The key is to check if the message in the log record is the format string
            # and the parameters are passed separately.
            # This test will PASS only after steps 2 and 3 are applied to cleanup_wildcards.py
            # Otherwise, if f-strings are still used, the 'malicious' part would be in the message directly.
            
            # Search for the specific log entry for processing targets
            found_log_entry = False
            for record in caplog.records:
                if "Processed {}/{} (Deleted: {})" in record.message:
                    found_log_entry = True
                    assert record.args == (0, len(mock_targets), 0) # Initial values
                    # More robust check: ensure no unexpected newlines in the raw message field if it was an f-string
                    assert '\n' not in record.message # The raw format string should not contain newlines
                
                # Check that malicious input from target.domain is handled as data, not as part of the format string
                if "Deleting Wildcard Target:" in record.message and "malicious.com\nCRITICAL: ATTACK DETECTED!" in record.args:
                     # If SecureLogger is used, the malicious string will be in args, not the format string
                     assert '\n' in record.args[0] # The domain itself can contain a newline
                     assert '\n' not in record.message # But the format string should not
                     
            assert found_log_entry, "Expected log entry 'Processed {}/{} (Deleted: {})' not found"

            # Additionally, verify that the 'malicious' domain did not cause any log injection
            # This check is more effective if the logger is fully replaced
            # The default logging setup often sanitizes newlines, but explicit parameterized logging is safer.
            # For now, we check the raw message and args if available.
            assert not any("CRITICAL: ATTACK DETECTED!" in record.message for record in caplog.records if "Processed" not in record.message)
