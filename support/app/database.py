import os
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

# Use /app/data/support.db in Docker, fall back to ./data/support.db for dev
_db_path_docker = Path("/app/data/support.db")
_db_path_dev = Path(__file__).parent.parent / "data" / "support.db"

if _db_path_docker.parent.exists() and os.access(str(_db_path_docker.parent), os.W_OK):
    DB_PATH = _db_path_docker
else:
    _db_path_dev.parent.mkdir(parents=True, exist_ok=True)
    DB_PATH = _db_path_dev

DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)


def create_db_tables() -> None:
    """Create all SQLModel tables."""
    SQLModel.metadata.create_all(engine)


def get_session():
    """FastAPI dependency: yields a DB session."""
    with Session(engine) as session:
        yield session
