from sqlmodel import Session, select
from yads.database import engine
from yads.models import User

def reset_user_changelog(username: str):
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        user = session.exec(statement).first()
        
        if not user:
            print(f"User '{username}' not found.")
            return
            
        print(f"User '{username}' found. Current last_seen_changelog_id: {user.last_seen_changelog_id}")
        user.last_seen_changelog_id = 0 # Reset to 0 to see all updates again
        session.add(user)
        session.commit()
        session.refresh(user)
        print(f"Updated last_seen_changelog_id to: {user.last_seen_changelog_id}")

if __name__ == "__main__":
    reset_user_changelog("viewertest")
