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
    """Create all SQLModel tables and run lightweight column migrations."""
    SQLModel.metadata.create_all(engine)
    _migrate_columns()


def _migrate_columns() -> None:
    """Add any missing columns to existing tables and backfill data (idempotent)."""
    import json as _json
    from sqlalchemy import text

    with engine.connect() as conn:
        # Add topic column to bugreport if not present
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(bugreport)"))}
        if "topic" not in cols:
            conn.execute(text("ALTER TABLE bugreport ADD COLUMN topic TEXT NOT NULL DEFAULT ''"))
            conn.commit()

        # Add EOS columns to customerkey if not present
        ck_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(customerkey)"))}
        if "is_eos" not in ck_cols:
            conn.execute(text("ALTER TABLE customerkey ADD COLUMN is_eos INTEGER NOT NULL DEFAULT 0"))
            conn.commit()
        if "eos_since" not in ck_cols:
            conn.execute(text("ALTER TABLE customerkey ADD COLUMN eos_since TEXT"))
            conn.commit()
            # Backfill: derive topic from full_report JSON if topic field is present
            rows = conn.execute(text("SELECT id, full_report FROM bugreport")).fetchall()
            for row_id, full_report in rows:
                try:
                    data = _json.loads(full_report)
                    topic = str(data.get("topic", ""))[:80]
                except Exception:
                    topic = ""
                if topic:
                    conn.execute(
                        text("UPDATE bugreport SET topic = :t WHERE id = :id"),
                        {"t": topic, "id": row_id},
                    )
            conn.commit()

        # ContactRequest: add notes column + migrate legacy statuses
        cr_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(contactrequest)"))}
        if "notes" not in cr_cols:
            conn.execute(text("ALTER TABLE contactrequest ADD COLUMN notes TEXT NOT NULL DEFAULT ''"))
            conn.commit()
        # Migrate old statuses (new/read/replied) to new ones (offen/in_arbeit)
        conn.execute(text(
            "UPDATE contactrequest SET status = 'offen'    WHERE status IN ('new', 'read')"
        ))
        conn.execute(text(
            "UPDATE contactrequest SET status = 'in_arbeit' WHERE status = 'replied'"
        ))
        conn.commit()

        # ContactRequest: add is_archived column
        cr_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(contactrequest)"))}
        if "is_archived" not in cr_cols:
            conn.execute(text("ALTER TABLE contactrequest ADD COLUMN is_archived INTEGER NOT NULL DEFAULT 0"))
            # Auto-archive existing spam entries
            conn.execute(text("UPDATE contactrequest SET is_archived = 1 WHERE status = 'spam'"))
            conn.commit()

        # category_id on bugreport (ReportCategory table created by SQLModel.metadata.create_all)
        br_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(bugreport)"))}
        if "category_id" not in br_cols:
            conn.execute(text("ALTER TABLE bugreport ADD COLUMN category_id INTEGER REFERENCES reportcategory(id)"))
            conn.commit()

        # InstallationReport: add missing columns (idempotent)
        ir_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(installationreport)"))}
        if ir_cols:  # table exists
            if "install_type" not in ir_cols:
                conn.execute(text("ALTER TABLE installationreport ADD COLUMN install_type TEXT NOT NULL DEFAULT 'unknown'"))
                conn.commit()
            if "customer_id" not in ir_cols:
                conn.execute(text("ALTER TABLE installationreport ADD COLUMN customer_id TEXT"))
                conn.commit()

        # ActivationRequest table: created automatically by SQLModel.metadata.create_all
        # when the table does not yet exist. No manual column migrations needed here.


def get_session():
    """FastAPI dependency: yields a DB session."""
    with Session(engine) as session:
        yield session
