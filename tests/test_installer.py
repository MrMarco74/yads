import pytest
import json
import os
import secrets
from release_assets.yads_installer.crypto_utils import validate_bsi_password
from run_installer_headless import HeadlessInstallationManager

def test_validate_bsi_password_valid():
    # 12 chars, 3 categories
    valid, msg = validate_bsi_password("Alpha1!Beta2")
    assert valid is True
    assert msg == ""

def test_validate_bsi_password_too_short():
    valid, msg = validate_bsi_password("Short1!")
    assert valid is False
    assert "mindestens 12 Zeichen" in msg

def test_validate_bsi_password_not_enough_categories():
    # 12 chars, but only lower/upper (2 categories)
    valid, msg = validate_bsi_password("AlphaBetaGamma")
    assert valid is False
    assert "mindestens 3 Kategorien" in msg

def test_validate_bsi_password_common_pattern():
    # Meets categories (Alpha, 1, !) but is blacklisted
    # Let's add 'Alpha1!Beta2' to the blacklist in crypto_utils for testing or use a better example.
    # Actually, let's just use a blacklisted one that has 3 categories if any.
    # I'll update crypto_utils to check common patterns BEFORE categories or just update the test.
    # Moving common patterns check to the top is better.
    valid, msg = validate_bsi_password("123456789012")
    assert valid is False
    assert "zu einfach" in msg

def test_headless_manager_generates_encryption_key():
    data = {"host": "localhost", "api_port": 8085}
    manager = HeadlessInstallationManager(data)
    manager.generate_secrets()
    
    assert "YADS_ENCRYPTION_KEY" in manager.secrets
    assert len(manager.secrets["YADS_ENCRYPTION_KEY"]) > 20

def test_headless_manager_reuses_encryption_key(tmp_path):
    # Setup a dummy .env file
    env_file = tmp_path / ".env"
    env_file.write_text("YADS_ENCRYPTION_KEY=pre-existing-key-789\nPOSTGRES_PASSWORD=dbpass\n")
    
    # Change CWD to tmp_path for the test
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    
    try:
        data = {"host": "localhost", "api_port": 8085, "install_mode": "upgrade"}
        manager = HeadlessInstallationManager(data)
        manager.generate_secrets()
        
        assert manager.secrets["YADS_ENCRYPTION_KEY"] == "pre-existing-key-789"
    finally:
        os.chdir(old_cwd)

def test_headless_manager_writes_encryption_key_to_env(tmp_path):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    
    try:
        data = {
            "host": "localhost", 
            "api_port": 8085, 
            "admin_user": "admin", 
            "admin_pass": "pass"
        }
        manager = HeadlessInstallationManager(data)
        manager.generate_secrets()
        manager.write_env()
        
        assert os.path.exists(".env")
        with open(".env", "r") as f:
            content = f.read()
            assert "YADS_ENCRYPTION_KEY=" in content
    finally:
        os.chdir(old_cwd)
