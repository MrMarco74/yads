import pytest
from yads.config import settings
from yads.models import User
from sqlmodel import select


def _admin_token_client(app):
    """Per Token angemeldeter Admin, ohne Login-Formular.

    Mit global aktiviertem MFA liefert ein Formular-Login absichtlich keine
    Session, sondern die MFA-Challenge -- der Test konnte sich also gar nicht
    anmelden und pruefte in Wahrheit die Antwort eines Unangemeldeten. Geprueft
    werden soll die Enforcement-Weiche in get_current_user, und die greift auf
    einer per Token authentifizierten Anfrage.
    """
    from starlette.testclient import TestClient
    from yads.auth.security import create_access_token

    c = TestClient(app, raise_server_exceptions=False)
    c.cookies.set("access_token", create_access_token("admin"))
    return c

@pytest.mark.auth
def test_admin_mfa_enforcement_redirect(app, db_session):
    """Verify that an admin without MFA is redirected to setup."""
    # Enable MFA globally for this test
    old_mfa_setting = settings.MFA_ENABLED
    settings.MFA_ENABLED = True
    
    try:
        # Ensure admin has MFA disabled
        admin = db_session.exec(select(User).where(User.username == "admin")).first()
        old_mfa_enabled = admin.mfa_enabled
        admin.mfa_enabled = False
        db_session.add(admin)
        db_session.commit()
        
        # Dashboard statt /targets/table: der Redirect auf /mfa/setup kommt
        # aus get_current_user_html. /targets/table haengt an der
        # API-Variante get_current_user und antwortet mit 403 MFA_REQUIRED --
        # der Test prueft beide Wege, damit klar bleibt, dass es zwei sind.
        c = _admin_token_client(app)
        r = c.get("/", follow_redirects=False)
        assert r.status_code in (302, 303, 307)
        assert r.headers["location"] == "/mfa/setup"

        assert c.get("/targets/table", follow_redirects=False).status_code == 403
        
    finally:
        settings.MFA_ENABLED = old_mfa_setting
        # mfa_enabled wurde bisher nur gesetzt und nie zurueckgenommen -- der
        # Wert blieb fuer alle spaeteren Tests stehen.
        admin.mfa_enabled = old_mfa_enabled
        db_session.add(admin)
        db_session.commit()

@pytest.mark.auth
def test_admin_with_mfa_not_redirected(app, db_session):
    """Verify that an admin WITH MFA is NOT redirected to setup."""
    old_mfa_setting = settings.MFA_ENABLED
    settings.MFA_ENABLED = True
    
    try:
        # Ensure admin has MFA enabled
        admin = db_session.exec(select(User).where(User.username == "admin")).first()
        old_mfa_enabled = admin.mfa_enabled
        admin.mfa_enabled = True
        db_session.add(admin)
        db_session.commit()
        
        # Try to access a protected page
        r = _admin_token_client(app).get("/targets/table", follow_redirects=False)
        
        # Should NOT redirect to /mfa/setup (might be 200 or redirect to dashboard, but NOT setup)
        if r.status_code in (302, 303):
            assert r.headers["location"] != "/mfa/setup"
        else:
            assert r.status_code == 200
            
    finally:
        settings.MFA_ENABLED = old_mfa_setting
        # mfa_enabled wurde bisher nur gesetzt und nie zurueckgenommen -- der
        # Wert blieb fuer alle spaeteren Tests stehen.
        admin.mfa_enabled = old_mfa_enabled
        db_session.add(admin)
        db_session.commit()
