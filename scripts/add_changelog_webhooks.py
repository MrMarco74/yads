from sqlmodel import Session, select
from yads.database import engine
from yads.models import ChangelogEntry

def add_changelog():
    with Session(engine) as session:
        # Check if already exists to avoid dupes on multiple runs
        existing = session.exec(select(ChangelogEntry).where(ChangelogEntry.title == "Webhooks & API Discovery")).first()
        if existing:
            print("Changelog entry already exists.")
            return

        entry = ChangelogEntry(
            title="Webhooks & API Discovery",
            version="1.4.0",
            category="feature",
            content="""
### 🚀 New Features

**Webhook Notifications**
- Real-time event triggers for **Scan Finished** and **New Asset Discovery**.
- Configure multiple webhook URLs per tenant.
- Test webhooks directly from the **Tenant Settings** page.
- Receive JSON payloads compatible with Slack, Discord, or custom endpoints.

**API Discovery**
- **Automated API Detection**: The Web Analyzer now identifies API documentation and endpoints.
- Supports **Swagger/OpenAPI**, **GraphQL**, **WSDL**, and versioned REST APIs.
- Findings are displayed in the **Target Details** view under the Web Analysis section.

### 🛠 Improvements
- **Security**: Added validation for webhook URLs.
- **UI**: New "Webhooks" card in Tenant Settings with status indicators.
- **Worker**: Enhanced scan completion logging and event dispatching.
            """
        )
        session.add(entry)
        session.commit()
        print("Added changelog entry: Webhooks & API Discovery")

if __name__ == "__main__":
    add_changelog()
