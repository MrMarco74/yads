
from sqlmodel import create_engine, text
from yads.config import settings

def migrate():
    engine = create_engine(settings.DATABASE_URL)
    with engine.connect() as conn:
        try:
            # Postgres syntax
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS session_timeout_minutes INTEGER DEFAULT 60;"))
            conn.commit()
            print("Successfully added session_timeout_minutes column to Tenant table.")
        except Exception as e:
            print(f"Error migrating: {e}")

if __name__ == "__main__":
    migrate()
