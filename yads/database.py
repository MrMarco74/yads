
from sqlmodel import SQLModel, Session, create_engine, text
import time
import logging
from yads.config import settings
import redis

# engine is a global connection pool.
#
# idle_in_transaction_session_timeout: defends against the recurring
# "yads.scheduler leaves a session idle in transaction" issue (a SELECT
# that opens a transaction never gets an explicit commit/rollback if the
# scheduler thread's process is killed non-gracefully mid-tick). Without
# this, such a session can sit open indefinitely and block the next
# container restart's `ALTER TABLE` migrations. Postgres now force-kills
# any connection idle-in-transaction past 5 minutes, which is far longer
# than any legitimate transaction in this codebase takes.
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"options": "-c idle_in_transaction_session_timeout=300000"},
)

# Centralized Redis connection pool
# decode_responses=True is standard for our usage (HTMX, version strings, logic)
redis_pool = redis.ConnectionPool.from_url(settings.REDIS_URL, decode_responses=True)
redis_client = redis.Redis(connection_pool=redis_pool)

def create_db_and_tables(engine_override=None):
    # Import all models to ensure they are registered in SQLModel.metadata
    # before create_all() is called. This is necessary because SQLModel only
    # knows about models that have been imported (class definition executed).
    from yads.models import (  # noqa: F401
        ComplianceScanRun, BrandWatch, ShadowDomainCandidate
    )

    use_engine = engine_override or engine
    SQLModel.metadata.create_all(use_engine)

def get_session():
    with Session(engine) as session:
        yield session

def get_redis():
    """Helper to get the global redis client."""
    return redis_client

def wait_for_db(max_retries=30, delay=2):
    """
    Blocks until the database is ready to accept connections.
    """
    logger = logging.getLogger("yads.database")
    for i in range(max_retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                logger.info("Database is ready.")
                return True
        except Exception as e:
            logger.warning(f"Database not ready (attempt {i+1}/{max_retries}): {e}")
            time.sleep(delay)
    
    logger.error("Database connection timed out.")
    return False
