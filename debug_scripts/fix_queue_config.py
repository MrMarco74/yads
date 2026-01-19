
from sqlmodel import Session, select, create_engine
from yads.models import SystemConfig
from yads.config import settings
import sys

# Docker compose db: user=yads, pass=yads, db=yads, port 5432.
db_url = "postgresql://yads:yads@localhost:5432/yads"

try:
    engine = create_engine(db_url)
    with Session(engine) as session:
        print("Checking QUEUE_ACTIVE...")
        queue_active = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
        
        should_update = False
        if not queue_active:
            print("QUEUE_ACTIVE is MISSING. Creating it...")
            queue_active = SystemConfig(key="QUEUE_ACTIVE", value="true", description="Master switch for queue processing")
            session.add(queue_active)
            should_update = True
        elif queue_active.value.lower() != "true":
            print(f"QUEUE_ACTIVE is currently '{queue_active.value}'. Updating to 'true'...")
            queue_active.value = "true"
            session.add(queue_active)
            should_update = True
        else:
            print("QUEUE_ACTIVE is already 'true'.")
            
        if should_update:
            session.commit()
            session.refresh(queue_active)
            print(f"SUCCESS: QUEUE_ACTIVE set to: {queue_active.value}")
        
except Exception as e:
    print(f"Error connecting/writing to DB: {e}")
    sys.exit(1)
