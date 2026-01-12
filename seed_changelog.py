from sqlmodel import Session
from yads.database import engine
from yads.models import ChangelogEntry

def seed_changelog():
    with Session(engine) as session:
        # Check if any exist
        existing = session.query(ChangelogEntry).first()
        if existing:
            print("Changelog entries already exist. Skipping seed.")
            return

        entry = ChangelogEntry(
            title="Welcome to YADS 1.2.6",
            version="1.2.6",
            content="""
            <p>We've updated the system with new features!</p>
            <ul>
                <li><strong>Recent Changes Modal:</strong> You are seeing this right now!</li>
                <li><strong>Improved Reporting:</strong> CVEs are now better organized.</li>
                <li><strong>Bug Fixes:</strong> Checkov pipeline issues resolved.</li>
            </ul>
            <p>Enjoy the new updates!</p>
            """
        )
        session.add(entry)
        session.commit()
        print(f"Created Changelog Entry ID: {entry.id}")

if __name__ == "__main__":
    seed_changelog()
