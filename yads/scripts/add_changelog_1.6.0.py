from sqlmodel import Session
from yads.database import engine
from yads.utils.announcements import publish_changelog_entry

def add_changelog():
    with Session(engine) as session:
        publish_changelog_entry(
            session=session,
            version="1.6.0",
            title="Comprehensive Reporting Suite",
            content="""
                ## New Reports Dashboard
                We have added 5 new specialized reports to give you better insights into your attack surface:
                
                *   **Sensitive Data Dashboard (`/secrets`)**: Centralized view of all exposed API keys, tokens, and config files found by scanners.
                *   **Email Security (`/email-security`)**: SPF/DMARC analysis to prevent spoofing.
                *   **Port Exposure (`/ports`)**: Track open ports and identify risky services.
                *   **Technology Drift (`/tech-drift`)**: A timeline view of when technologies are added or removed from your assets.
                *   **Attack Surface Reduction (`/asr`)**: A cleanup list of dead endpoints, default pages, and expired certs.
                
                ## Improvements
                *   **Navigation**: Updated sidebar with new "Reports" section.
                *   **Visualizations**: Enhanced charts and timelines across all new dashboards.
            """
        )

if __name__ == "__main__":
    add_changelog()
