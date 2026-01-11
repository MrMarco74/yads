import logging
import sys
from unittest.mock import MagicMock, patch
from datetime import datetime

# Set up logging to stdout
logging.basicConfig(level=logging.INFO)

# Import the class
from yads.modules.infrastructure_scanner import InfrastructureScanner
from yads.models import ScanResult, Target

def test_fallback():
    print("--- Testing Fallback Logic ---")
    
    # 1. Mock DB Session
    mock_db = MagicMock()
    
    # Mock Target Lookup
    mock_target = Target(id=1, domain="example.com")
    
    # Mock Previous Result (Valid GeoIP)
    mock_prev_result = ScanResult(
        target_id=1, 
        module_name="infrastructure_scanner",
        scanned_at=datetime.utcnow(),
        data={
            "ip": "1.2.3.4",
            "cloud_provider": "MockCloud",
            "geoip": {"country_name": "Mockland"}
        }
    )
    
    # Setup mock returns
    # First call: select(Target)... -> return mock_target
    # Second call: select(ScanResult)... -> return mock_prev_result
    # This is tricky with fluent SQLModel/SQLAlchemy mocks, so let's mock the .exec().first() chain
    
    # We will patch self.db.exec to simply return our objects depending on query type? 
    # Or cleaner: Mock the calls inside run_scan via patching the scanner's db attribute
    
    scanner = InfrastructureScanner(db_session=mock_db)
    
    # We need to ensure socket.gethostbyname returns the SAME IP "1.2.3.4"
    with patch("socket.gethostbyname", return_value="1.2.3.4"):
        
        # We need to ensure IPWhois works or fails? 
        # Let's say IPWhois works for ASN but we want GeoIP (API) to fail.
        # IPWhois is not used for GeoIP in my implemented logic (it does ASN).
        # GeoIP is via requests.get(ip-api.com).
        
        # Mock IPWhois to return minimal ASN data so it doesn't crash
        with patch("yads.modules.infrastructure_scanner.IPWhois") as MockIPWhois:
            instance = MockIPWhois.return_value
            instance.lookup_rdap.return_value = {"asn": "12345", "asn_description": "Mock ASN"}
            
            # CRITICAL: Mock requests.get to FAIL for GeoIP
            with patch("requests.get", side_effect=Exception("API Validation Timeout")):
                
                # However, requests is also used for bucket check. We don't care about buckets here.
                # So side_effect=Exception is fine, it will just fail all requests.
                
                # For the DB mock:
                # scanner.db.exec(stmt).first()
                # We can configure the mock to return an object that has .first() returning our desired data
                
                # Mocking the `select` outcomes in sequence is hard. 
                # Instead, let's manually assign the return values to side_effect of first()
                
                row1 = MagicMock()
                row1.first.return_value = mock_target
                
                row2 = MagicMock()
                row2.first.return_value = mock_prev_result
                
                mock_db.exec.side_effect = [row1, row2, row1, row2] # Sequence of calls
                
                # Run Scan
                print("Running scan with mocked API failure...")
                result = scanner.run_scan("example.com")
                
                print("\n--- Result Analysis ---")
                print("IP:", result.get("ip"))
                print("GeoIP:", result.get("geoip"))
                print("CloudProvider:", result.get("cloud_provider"))
                
                # Assertions
                if result.get("ip") == "1.2.3.4":
                   print("PASS: IP matches")
                else:
                   print("FAIL: IP mismatch")
                   
                if result.get("geoip") == {"country_name": "Mockland"}:
                    print("PASS: Fallback GeoIP worked!")
                else:
                    print("FAIL: Fallback GeoIP missing or incorrect")
                    
                if result.get("cloud_provider") == "MockCloud":
                    print("PASS: Fallback CloudProvider worked!")
                else:
                    print("FAIL: CloudProvider missing")

if __name__ == "__main__":
    test_fallback()
