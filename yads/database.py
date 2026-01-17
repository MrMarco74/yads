
from sqlmodel import SQLModel, Session, create_engine
from yads.config import settings

# engine is a global connection pool
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
