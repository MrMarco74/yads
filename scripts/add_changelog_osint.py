import sys
import os
sys.path.append(os.getcwd())

from sqlmodel import Session
from datetime import datetime
from yads.database import engine
from yads.models import ChangelogEntry

def add_changelog():
    with Session(engine) as session:
        entry = ChangelogEntry(
            title="Update 1.3.2: OSINT Brand Monitoring & License Management",
            version="1.3.2",
            published_at=datetime.utcnow(),
            content="""
## 🕵️ OSINT Brand Monitoring
We are excited to introduce the **OSINT Search** feature!

*   **Reverse Image Search**: Upload your brand logo to find potential phishing sites or unauthorized usage across the web.
*   **Target Discovery**: Automatically identify unknown domains and import them directly into your monitoring list.
*   **Simulation Mode**: Currently running in a simulated environment for testing purposes.

## 🔐 License Management
Administrators now have granular control over tenant features:
*   **Feature Toggles**: Enable or disable OSINT capabilities per tenant.
*   **Quotas**: Set monthly search limits to control costs.
*   **Usage Tracking**: Monitor search volume and estimated costs directly from the Tenant Overview.

## 🛠️ Other Improvements
*   **Sidebar**: New navigation item for OSINT with "Locked" status indicators.
*   **UI/UX**: Improved drag-and-drop file handling and license management modals.
            """
        )
        session.add(entry)
        session.commit()
        print("Changelog entry added successfully.")

if __name__ == "__main__":
    add_changelog()
