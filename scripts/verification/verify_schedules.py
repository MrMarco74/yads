import requests
import sys
from sqlmodel import Session, select, create_engine
from yads.models import Target, Tenant, ScanSchedule, User
from yads.config import settings
from yads.database import engine

# Setup
def setup_test_data():
    import uuid
    uid = uuid.uuid4().hex[:6]
    
    with Session(engine) as session:
        # Create Dummy Tenant
        t = Tenant(name=f"ScheduleTestTenant-{uid}")
        session.add(t)
        session.commit()
        session.refresh(t)

        # Create Dummy Target
        tg = Target(domain=f"schedule-test-{uid}.com", tenant_id=t.id)
        session.add(tg)
        session.commit()
        session.refresh(tg)
        
        # Create Admin User
        from yads.auth.security import get_password_hash
        u = User(username=f"scheduletestadmin-{uid}", password_hash=get_password_hash("test"), role="admin", is_active=True, tenant_id=t.id)
        session.add(u)
        session.commit()
        session.refresh(u)
        
        return t.id, tg.id, u.username, "test", tg.domain

def test_api():
    try:
        tenant_id, target_id, username, password, target_domain = setup_test_data()
        
        # Login (Cookie Based)
        auth_data = {"username": username, "password": password}
        s = requests.Session()
        # The auth router is included at root? Yes app.include_router(auth.router)
        # Check if prefix is set in auth.py? No.
        r = s.post("http://localhost:8000/login", data=auth_data, allow_redirects=False)
        
        # Expect 303 Redirect and 'access_token' cookie
        if r.status_code not in [303, 302]:
            print(f"Login Failed: Status {r.status_code}, {r.text}")
            return False
            
        if "access_token" not in s.cookies:
             print("Login Failed: No access_token cookie received")
             return False
             
        print("Login: OK")
        
        # 1. Test POST /schedules/add
        payload = {"target_id": target_id, "frequency": "daily"}
        r = s.post("http://localhost:8000/schedules/add", data=payload, allow_redirects=False)
        if r.status_code not in [303, 302]: # Redirect expected
            print(f"Add Schedule Failed: Status {r.status_code}, {r.text}")
            return False
        print("Add Schedule: OK")
        
        # 2. Test GET /schedules (HTML)
        r = s.get("http://localhost:8000/schedules/")
        if r.status_code != 200:
            print(f"Get Schedules Failed: Status {r.status_code}")
            return False
        if target_domain not in r.text:
            print(f"Get Schedules: Target {target_domain} not found in HTML")
            # print(r.text) # Debug
            return False
        print("Get Schedules: OK")
        
        # Verify DB
        with Session(engine) as session:
            sched = session.exec(select(ScanSchedule).where(ScanSchedule.target_id == target_id)).first()
            if not sched:
                print("DB Verification: Schedule not found in DB")
                return False
            schedule_id = sched.id
            print(f"DB Verification: Schedule {schedule_id} found")

        # 3. Test POST /schedules/delete/{id}
        r = s.post(f"http://localhost:8000/schedules/delete/{schedule_id}", allow_redirects=False)
        if r.status_code not in [303, 302]:
             print(f"Delete Schedule Failed: Status {r.status_code}, {r.text}")
             return False
        print("Delete Schedule: OK")

        return True

    except Exception as e:
        print(f"Test Exception: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if test_api():
        sys.exit(0)
    else:
        sys.exit(1)
