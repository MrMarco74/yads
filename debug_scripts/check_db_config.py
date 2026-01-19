
from sqlmodel import Session, select, create_engine
from yads.models import SystemConfig
from yads.config import settings

# Override DB URL if needed for local execution (assuming running from host accessing docker db might fail if not exposed, but user has port 5432 exposed in compose)
# However, settings.DATABASE_URL might be 'postgresql://user:password@localhost:5432/yads_db' or similar. 
# In docker-compose it is `postgres:15-alpine` with exposed port 5432.
# Let's try pointing to localhost since I am on the host.

# Checking config.py: DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/yads_db")
# Docker compose db: user=yads, pass=yads, db=yads, port 5432.
# So localhost url should be: postgresql://yads:yads@localhost:5432/yads

db_url = "postgresql://yads:yads@localhost:5432/yads"

try:
    engine = create_engine(db_url)
    with Session(engine) as session:
        results = session.exec(select(SystemConfig)).all()
        print("SystemConfig entries:")
        for r in results:
            print(f"  {r.key}: {r.value}")
        
        queue_active = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
        if not queue_active:
            print("\nWARNING: QUEUE_ACTIVE is MISSING!")
        else:
            print(f"\nQUEUE_ACTIVE is: {queue_active.value}")
            
except Exception as e:
    print(f"Error connecting to DB: {e}")
