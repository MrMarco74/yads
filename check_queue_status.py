from sqlmodel import Session, select, create_engine
from yads.models import SystemConfig
from yads.config import settings
import sys

# Configure stdout encoding to utf-8
sys.stdout.reconfigure(encoding='utf-8')

engine = create_engine(settings.DATABASE_URL)

def check_status():
    with Session(engine) as session:
        conf = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
        if conf:
            print(f"QUEUE_ACTIVE Key Found.")
            print(f"Value: '{conf.value}'")
            print(f"Type: {type(conf.value)}")
        else:
            print("QUEUE_ACTIVE Key NOT Found (Default: True)")

if __name__ == "__main__":
    check_status()
