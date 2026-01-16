import sys
import os

# Add parent directory to path so we can import yads modules
# /app/yads/scripts/restore_admin.py -> /app
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlmodel import Session, select
from yads.database import engine
from yads.models import User
from yads.auth.security import get_password_hash

def restore_admin():
    with Session(engine) as session:
        # Check if admin exists
        statement = select(User).where(User.username == "admin")
        results = session.exec(statement)
        admin = results.first()

        if admin:
            print("Admin user already exists.")
            return

        print("Restoring admin user...")
        # create admin user
        admin = User(
            username="admin",
            password_hash=get_password_hash("admin"), # Default password, user should change this
            role="admin",
            is_active=True
        )
        session.add(admin)
        session.commit()
        print("Admin user restored successfully with default password 'admin'.")

if __name__ == "__main__":
    restore_admin()
