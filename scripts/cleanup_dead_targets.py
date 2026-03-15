import sys
import os
import asyncio
from sqlmodel import Session, select, text
from yads.database import engine
from yads.models import Target, ScanResult, Tenant

def cleanup_dead_targets(tenant_name_filter=None):
    with Session(engine) as session:
        # 1. Resolve Tenant
        tenant_query = select(Tenant)
        if tenant_name_filter:
            tenant_query = tenant_query.where(Tenant.name.ilike(f"%{tenant_name_filter}%"))
        
        tenants = session.exec(tenant_query).all()
        if not tenants:
            print(f"No tenant found matching '{tenant_name_filter}'")
            return

        for tenant in tenants:
            print(f"\nAnalyzing Tenant: {tenant.name} (ID: {tenant.id})")
            
            # 2. Find Candidates (Latest Scan = 0.0.0.0)
            # We use Python for clarity and safety over complex SQL for now, 
            # unless dataset is huge (it's not).
            
            targets = session.exec(select(Target).where(Target.tenant_id == tenant.id)).all()
            dead_targets = []
            
            print(f"  Total Targets: {len(targets)}")
            
            for t in targets:
                # Get latest infrastructure scan
                result = session.exec(
                    select(ScanResult)
                    .where(ScanResult.target_id == t.id, ScanResult.module_name == "infrastructure_scanner")
                    .order_by(ScanResult.scanned_at.desc())
                    .limit(1)
                ).first()
                
                is_dead = False
                current_ip = "N/A"
                
                if result and result.data:
                    current_ip = result.data.get("ip")
                    if current_ip == "0.0.0.0":
                        is_dead = True
                
                # Option: verify if they have NO successful scan ever?
                # User specifically asked for 0.0.0.0 detection.
                
                if is_dead:
                    dead_targets.append((t, current_ip))

            if not dead_targets:
                print("  ✅ No '0.0.0.0' targets found. All targets have valid IPs or haven't been scanned.")
                continue

            # 3. List
            print(f"  ⚠️ Found {len(dead_targets)} targets with IP 0.0.0.0:")
            for t, ip in dead_targets:
                print(f"    - [ID: {t.id}] {t.domain} (Current IP: {ip})")

            # 4. Ask User
            confirm = input(f"  ❓ Delete these {len(dead_targets)} targets from database? (y/N): ")
            if confirm.lower() == 'y':
                print("  🗑️ Deleting...")
                ids = [t.id for t, _ in dead_targets]

                # Cleanup Dependencies — use parameterized ANY to avoid f-string SQL
                session.exec(text("DELETE FROM scanresult WHERE target_id = ANY(:ids)"), {"ids": ids})
                session.exec(text("DELETE FROM modulestate WHERE target_id = ANY(:ids)"), {"ids": ids})
                session.exec(text("DELETE FROM target WHERE id = ANY(:ids)"), {"ids": ids})
                session.commit()
                print("  ✅ Deleted.")
            else:
                print("  Skipped.")

if __name__ == "__main__":
    search = sys.argv[1] if len(sys.argv) > 1 else None
    cleanup_dead_targets(search)
