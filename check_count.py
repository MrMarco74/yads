
from sqlmodel import select, Session, func
from yads.database import SessionLocal, engine
from yads.models import Target

def check_target_count():
    with SessionLocal() as session:
        count = session.exec(select(func.count()).select_from(Target)).one()
        print(f"Total Active Targets: {count}")
        
        # Sample some targets
        targets = session.exec(select(Target).limit(10)).all()
        print("Sample Targets:")
        for t in targets:
            print(f" - {t.domain}")

if __name__ == "__main__":
    check_target_count()
