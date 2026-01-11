from sqlmodel import text
from yads.database import engine, get_session

def migrate():
    with engine.connect() as conn:
        print("Adding force_password_change column...")
        try:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS force_password_change BOOLEAN DEFAULT FALSE;'))
            conn.commit()
            print("Migration successful.")
        except Exception as e:
            print(f"Migration error (might already exist): {e}")

if __name__ == "__main__":
    migrate()
