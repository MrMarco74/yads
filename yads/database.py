
from sqlmodel import SQLModel, Session, create_engine
from yads.config import settings

# engine is a global connection pool
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)

def create_db_and_tables(engine_override=None):
    use_engine = engine_override or engine
    SQLModel.metadata.create_all(use_engine)

def get_session():
    with Session(engine) as session:
        yield session
