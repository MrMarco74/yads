import pytest
from yads.config import settings
from yads.models import User
from sqlmodel import select

@pytest.mark.auth
def test_admin_mfa_enforcement_redirect(client, db_session):
    """Verify that an admin without MFA is redirected to setup."""
    # Enable MFA globally for this test
    old_mfa_setting = settings.MFA_ENABLED
    settings.MFA_ENABLED = True
    
    try:
        # Ensure admin has MFA disabled
        admin = db_session.exec(select(User).where(User.username == "admin")).first()
        admin.mfa_enabled = False
        db_session.add(admin)
        db_session.commit()
        
        # Log in as admin
        client.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            follow_redirects=True,
        )
        
        # Try to access a protected page
        r = client.get("/targets", follow_redirects=False)
        
        # Should redirect to /mfa/setup
        assert r.status_code in (302, 303)
        assert r.headers["location"] == "/mfa/setup"
        
    finally:
        settings.MFA_ENABLED = old_mfa_setting

@pytest.mark.auth
def test_admin_with_mfa_not_redirected(client, db_session):
    """Verify that an admin WITH MFA is NOT redirected to setup."""
    old_mfa_setting = settings.MFA_ENABLED
    settings.MFA_ENABLED = True
    
    try:
        # Ensure admin has MFA enabled
        admin = db_session.exec(select(User).where(User.username == "admin")).first()
        admin.mfa_enabled = True
        db_session.add(admin)
        db_session.commit()
        
        # Log in as admin
        client.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            follow_redirects=True,
        )
        
        # Try to access a protected page
        r = client.get("/targets", follow_redirects=False)
        
        # Should NOT redirect to /mfa/setup (might be 200 or redirect to dashboard, but NOT setup)
        if r.status_code in (302, 303):
            assert r.headers["location"] != "/mfa/setup"
        else:
            assert r.status_code == 200
            
    finally:
        settings.MFA_ENABLED = old_mfa_setting
