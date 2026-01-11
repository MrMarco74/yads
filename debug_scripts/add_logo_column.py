from sqlmodel import Session, create_engine, text
from yads.config import settings
import sys

# Configure stdout encoding to utf-8
sys.stdout.reconfigure(encoding='utf-8')

engine = create_engine(settings.DATABASE_URL)

def add_column():
    with Session(engine) as session:
        try:
            print("Attempting to add 'brand_logo_url' column to 'target' table...")
            session.exec(text("ALTER TABLE target ADD COLUMN brand_logo_url TEXT;"))
            session.commit()
            print("Column added successfully.")
        except Exception as e:
            print(f"Error (might already exist): {e}")
            session.rollback()

if __name__ == "__main__":
    add_column()
