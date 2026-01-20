
import sys
import os

# Add project root to sys.path to allow importing 'yads'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from sqlmodel import select
from yads.database import get_session
from yads.models import User
from yads.auth.security import get_password_hash

def reset_password(username, new_password):
    print(f"Attempting to reset password for user: {username}")
    session_gen = get_session()
    session = next(session_gen)
    try:
        user = session.exec(select(User).where(User.username == username)).first()
        if not user:
            print(f"User '{username}' not found! Creating new user...")
            # from yads.auth.security import get_password_hash
            user = User(username=username, password_hash=get_password_hash(new_password), role="admin")
            session.add(user)
            session.commit()
            print(f"User '{username}' created with role 'admin'.")
            return

        print(f"User found (ID: {user.id}). Updating password...")
        user.password_hash = get_password_hash(new_password)
        session.add(user)
        session.commit()
        session.refresh(user)
        print(f"Password for '{username}' has been reset to '{new_password}'.")
    except Exception as e:
        print(f"Error resetting password: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        username = sys.argv[1]
        password = sys.argv[2]
        reset_password(username, password)
    else:
        reset_password("admin", "admin")
