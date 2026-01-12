from sqlmodel import text
from yads.database import engine, get_session

def migrate():
    with engine.connect() as conn:
        print("Migrating Database...")
        
        # 1. Update User Table
        print(">> Adding last_seen_changelog_id to user table...")
        try:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS last_seen_changelog_id INTEGER DEFAULT 0;'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Note: {e}")

        # 2. Create ChangelogEntry Table
        print(">> Creating changelogentry table...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS changelogentry (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR NOT NULL,
                    content VARCHAR NOT NULL,
                    version VARCHAR NOT NULL,
                    published_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                );
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating table: {e}")
            
if __name__ == "__main__":
    migrate()
