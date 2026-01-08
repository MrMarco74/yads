import os
from sqlmodel import Session, select, create_engine
from yads.models import Target

# Use env var or default
db_url = os.getenv("DATABASE_URL", "postgresql://yads:yads@db:5432/yads")
engine = create_engine(db_url)

def check_target(t_id):
    with Session(engine) as session:
        target = session.get(Target, t_id)
        if target:
            print(f"ID: {target.id}")
            print(f"Domain: {target.domain}")
            print(f"Status: {target.scan_status}")
            print(f"Progress: {target.scan_progress}")
        else:
            print(f"Target {t_id} not found")

if __name__ == "__main__":
    check_target(621878)
