from sqlmodel import create_engine, Session
from sqlalchemy.orm import sessionmaker
from yads.config import settings

# Create the database engine
engine = create_engine(settings.DATABASE_URL, echo=False)

# Create a Session factory
# This allows usage like: with SessionLocal() as session:
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=Session)
