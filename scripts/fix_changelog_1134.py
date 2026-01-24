from sqlmodel import Session, select
from yads.database import engine
from yads.models import ChangelogEntry

def fix_changelog():
    with Session(engine) as session:
        # Find the specific entry
        entry = session.exec(select(ChangelogEntry).where(ChangelogEntry.version == "1.13.4")).first()
        
        if entry:
            print(f"Found existing entry for 1.13.4 with title: {entry.title}")
            # Update content
            entry.title = "YADS v1.13.4: Release Tools & UI Polish"
            entry.content = """
                <h3>🚀 Release Management</h3>
                <ul>
                    <li><strong>Robust Translator:</strong> Fixed crashes when Gemini API key is missing by automatically falling back to manual translation mode.</li>
                    <li><strong>Non-Interactive Fixes:</strong> Resolved "EOF when reading a line" errors for fully automated release builds.</li>
                    <li><strong>Strict Process Control:</strong> Release process now aborts immediately on any step failure to prevent partial/corrupt releases.</li>
                </ul>
                <h3>💅 UI UX Improvements</h3>
                <ul>
                    <li><strong>Settings Layout:</strong> Refactored Settings page to use a responsive grid that scales to full width (up to 4 columns) on large screens.</li>
                    <li><strong>Graph Visualization:</strong> Disabled domain name truncation in "Generate Full Graph Image" to ensure complete visibility of all targets.</li>
                    <li><strong>Toggle Component:</strong> Fixed rendering issues with "Auto-Queue" toggles by implementing a standard DOM-based switch.</li>
                </ul>
                """
            session.add(entry)
            session.commit()
            print("Successfully updated Changelog 1.13.4")
        else:
            print("Entry 1.13.4 not found. Creating it...")
            entry = ChangelogEntry(
                title="YADS v1.13.4: Release Tools & UI Polish",
                version="1.13.4",
                content="""
                <h3>🚀 Release Management</h3>
                <ul>
                    <li><strong>Robust Translator:</strong> Fixed crashes when Gemini API key is missing by automatically falling back to manual translation mode.</li>
                    <li><strong>Non-Interactive Fixes:</strong> Resolved "EOF when reading a line" errors for fully automated release builds.</li>
                    <li><strong>Strict Process Control:</strong> Release process now aborts immediately on any step failure to prevent partial/corrupt releases.</li>
                </ul>
                <h3>💅 UI UX Improvements</h3>
                <ul>
                    <li><strong>Settings Layout:</strong> Refactored Settings page to use a responsive grid that scales to full width (up to 4 columns) on large screens.</li>
                    <li><strong>Graph Visualization:</strong> Disabled domain name truncation in "Generate Full Graph Image" to ensure complete visibility of all targets.</li>
                    <li><strong>Toggle Component:</strong> Fixed rendering issues with "Auto-Queue" toggles by implementing a standard DOM-based switch.</li>
                </ul>
                """
            )
            session.add(entry)
            session.commit()
            print("Created Changelog 1.13.4")

if __name__ == "__main__":
    fix_changelog()
