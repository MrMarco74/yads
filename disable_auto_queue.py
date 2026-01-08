import os
from sqlmodel import Session, create_engine, select
from yads.models import SystemConfig

# Use env var or default
db_url = os.getenv("DATABASE_URL", "postgresql://yads:yads@db:5432/yads")
engine = create_engine(db_url)

def update_config():
    with Session(engine) as session:
        config = session.get(SystemConfig, "AUTO_QUEUE_SUBDOMAINS")
        if not config:
            config = SystemConfig(key="AUTO_QUEUE_SUBDOMAINS", value="false")
            session.add(config)
            print("Created config: AUTO_QUEUE_SUBDOMAINS=false")
        else:
            config.value = "false"
            session.add(config)
            print("Updated config: AUTO_QUEUE_SUBDOMAINS=false")
        session.commit()

if __name__ == "__main__":
    update_config()
