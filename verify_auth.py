

from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select
from yads.api.main import app, get_session
from yads.models import User, SystemConfig
from yads.auth.security import get_password_hash
import os
import pyotp

# Use Postgres for testing (JSONB support)
# sqlite_file_name = "database_test.db"
# sqlite_url = f"sqlite:///{sqlite_file_name}"
sqlite_url = "postgresql://yads:yads@db:5432/yads_test"
engine = create_engine(sqlite_url)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
def teardown_db():
    pass

def get_session_override():
    with Session(engine) as session:
        yield session

app.dependency_overrides[get_session] = get_session_override

client = TestClient(app)

def setup_module(module):
    create_db_and_tables()
    # Create Users
    with Session(engine) as session:
        admin = User(username="admin", password_hash=get_password_hash("admin"), role="admin", is_active=True)
        scanner = User(username="scanner", password_hash=get_password_hash("scanner"), role="scanner", is_active=True)
        viewer = User(username="viewer", password_hash=get_password_hash("viewer"), role="viewer", is_active=True)
        
        # MFA User
        secret = pyotp.random_base32()
        mfa_user = User(username="mfa_user", password_hash=get_password_hash("password"), role="admin", is_active=True, mfa_enabled=True, mfa_secret=secret)
        
        session.add(admin)
        session.add(scanner)
        session.add(viewer)
        session.add(mfa_user)
        session.commit()

def teardown_module(module):
    teardown_db()

def login(username, password):
    response = client.post("/login", data={"username": username, "password": password})
    return response

def test_login_success():
    response = login("admin", "admin")
    assert response.status_code == 200 # Redirects behave as 200 in TestClient unless follow_redirects=False? No, usually OK.
    # Actually TestClient follows redirects by default?
    # Our login returns RedirectResponse(303). TestClient follows?
    # Let's check cookies.
    assert "access_token" in client.cookies

def test_login_fail():
    response = login("admin", "wrongpassword")
    # Should render template (200) with error
    assert response.status_code == 200
    assert "Invalid username or password" in response.text
    assert "access_token" not in response.cookies

def test_rbac_admin_access():
    # Login as admin
    login("admin", "admin")
    response = client.get("/users/")
    assert response.status_code == 200
    assert "User Management" in response.text

def test_rbac_viewer_denied():
    # Login as viewer
    client.cookies.clear()
    login("viewer", "viewer")
    
    # Try Admin Route
    response = client.get("/users/")
    assert response.status_code == 403
    
    # Try Scanner Route (Trigger Scan) -> Need a target first?
    # But route protection happens before arguments check usually?
    # depends.
    # Let's try /scans/stop-all which is Scanner+
    response = client.post("/scans/stop-all")
    assert response.status_code == 403

def test_rbac_scanner_allowed():
    client.cookies.clear()
    login("scanner", "scanner")
    
    # Scanner CAN stop scans
    response = client.post("/scans/stop-all")
    assert response.status_code == 200 or response.status_code == 303 # Success Redirect

    # Scanner COMPUTES denied for Users
    response = client.get("/users/")
    assert response.status_code == 403

def test_mfa_flow():
    client.cookies.clear()
    # 1. Login init
    response = login("mfa_user", "password")
    assert "MFA Code" in response.text
    assert "access_token" not in client.cookies
    
    # 2. Submit Code
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == "mfa_user")).first()
        totp = pyotp.TOTP(user.mfa_secret)
        code = totp.now()
        
    response = client.post("/login", data={"username": "mfa_user", "password": "password", "otp_code": code})
    assert "access_token" in client.cookies

def test_rbac_logs_queue_denied():
    # Login as viewer
    client.cookies.clear()
    login("viewer", "viewer")
    
    # Try Logs
    response = client.get("/logs")
    assert response.status_code == 403
    
    # Try Logs Stream
    response = client.get("/api/logs/stream")
    # This might return JSON {detail: Forbidden} or 403
    assert response.status_code == 403
    
    # Try Queue
    response = client.get("/queue")
    assert response.status_code == 403
    
    # Try Queue Control
    response = client.post("/queue/control", data={"action": "stop"})
    assert response.status_code == 403

if __name__ == "__main__":
    # Manually run tests if executed as script
    setup_module(None)
    try:
        print("Running test_login_success...")
        test_login_success()
        print("PASS")
        
        print("Running test_login_fail...")
        test_login_fail()
        print("PASS")
        
        print("Running test_rbac_admin_access...")
        test_rbac_admin_access()
        print("PASS")
        
        print("Running test_rbac_viewer_denied...")
        test_rbac_viewer_denied()
        print("PASS")
        
        print("Running test_rbac_scanner_allowed...")
        test_rbac_scanner_allowed()
        print("PASS")
        
        print("Running test_mfa_flow...")
        test_mfa_flow()
        print("PASS")

        print("Running test_rbac_logs_queue_denied...")
        test_rbac_logs_queue_denied()
        print("PASS")
        
        print("ALL TESTS PASSED")
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
    finally:
        teardown_module(None)
