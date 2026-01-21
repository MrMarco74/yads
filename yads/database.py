
from sqlmodel import SQLModel, Session, create_engine
from yads.config import settings
import redis

# engine is a global connection pool
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)

# Centralized Redis connection pool
# decode_responses=True is standard for our usage (HTMX, version strings, logic)
redis_pool = redis.ConnectionPool.from_url(settings.REDIS_URL, decode_responses=True)
redis_client = redis.Redis(connection_pool=redis_pool)

def create_db_and_tables(engine_override=None):
    use_engine = engine_override or engine
    SQLModel.metadata.create_all(use_engine)

def get_session():
    with Session(engine) as session:
        yield session

def get_redis():
    """Helper to get the global redis client."""
    return redis_client
