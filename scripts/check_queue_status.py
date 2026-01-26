import sys
import os
from sqlmodel import Session, select, func

# Add project root to path
sys.path.append(os.getcwd())

from yads.database import engine
from yads.models import SystemConfig, Tenant, Target

def check_status():
    with Session(engine) as session:
        # 1. Check Queue Status
        config = session.get(SystemConfig, "QUEUE_ACTIVE")
        print(f"QUEUE_ACTIVE SystemConfig: {config.value if config else 'Not Set (Default False)'}")
        
        # 2. Check Tenant
        tenant_name = "a customer"
        tenant = session.exec(select(Tenant).where(Tenant.name == tenant_name)).first()
        
        if not tenant:
            print(f"❌ Tenant '{tenant_name}' NOT FOUND in database!")
            # List all tenants
            tenants = session.exec(select(Tenant)).all()
            print("Available Tenants:")
            for t in tenants:
                print(f" - ID: {t.id}, Name: {t.name}")
            return
            
        print(f"✅ Tenant '{tenant_name}' found. ID: {tenant.id}")
        
        # 3. Check Targets for Tenant
        total_targets = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == tenant.id)).one()
        queued_targets = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == tenant.id, Target.scan_status == "queued")).one()
        running_targets = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == tenant.id, Target.scan_status == "running")).one()
        
        print(f"Targets Stats for Tenant {tenant.id}:")
        print(f" - Total: {total_targets}")
        print(f" - Queued: {queued_targets}")
        print(f" - Running: {running_targets}")

if __name__ == "__main__":
    try:
        check_status()
    except Exception as e:
        print(f"Error: {e}")
