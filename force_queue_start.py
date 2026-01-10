from sqlmodel import Session, select, create_engine
from yads.models import SystemConfig
from yads.config import settings
import sys

# Configure stdout encoding to utf-8
sys.stdout.reconfigure(encoding='utf-8')

engine = create_engine(settings.DATABASE_URL)

def force_start():
    with Session(engine) as session:
        conf = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
        if not conf:
            conf = SystemConfig(key="QUEUE_ACTIVE", value="true")
            session.add(conf)
            print("Created QUEUE_ACTIVE key.")
        else:
            print(f"Current Value: {conf.value}")
            conf.value = "true"
            session.add(conf)
            print("Updated Value to 'true'.")
            
        session.commit()
        session.refresh(conf)
        print(f"New Value: {conf.value}")

if __name__ == "__main__":
    force_start()
