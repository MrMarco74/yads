from sqlmodel import Session
from yads.database import engine
from yads.models import ChangelogEntry

def seed_changelog():
    with Session(engine) as session:
        if not session.query(ChangelogEntry).where(ChangelogEntry.version == "1.2.6").first():
            entry1 = ChangelogEntry(
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
            session.add(entry1)

        if not session.query(ChangelogEntry).where(ChangelogEntry.version == "1.2.8").first():
            entry2 = ChangelogEntry(
                title="YADS v1.2.8: UI Refinements & Core Improvements",
                version="1.2.8",
                content="""
                <h3>🚀 New Features</h3>
                <ul>
                    <li><strong>Tenant Renaming:</strong> Admins can now rename tenants directly from the Tenants overview page via a new "Rename" button and modal.</li>
                    <li><strong>Expanded Excel Export:</strong> The target export now includes all visible UI columns, including SSL details, CVE counts, Secrets, and Infrastructure info.</li>
                    <li><strong>Plot Graph Button:</strong> The Network Graph now features an explicit "Plot Graph" button in the sidebar for better control.</li>
                </ul>
                <h3>🔧 Improvements & Fixes</h3>
                <ul>
                    <li><strong>Zero-Tenant State:</strong> System Reset now results in a clean "Zero-Tenant" state for better data isolation protocols.</li>
                    <li><strong>Graph UI Restoration:</strong> Fixed missing loading overlays and status indicators on the Network Graph page.</li>
                    <li><strong>Worker Autoscaling:</strong> Celery workers now use autoscaling for better resource management.</li>
                </ul>
                """
            )
            session.add(entry2)
        
        if not session.query(ChangelogEntry).where(ChangelogEntry.version == "1.2.7").first():
            entry_127 = ChangelogEntry(
                title="Tenant-Aware Backup & Restore",
                version="1.2.7",
                content="""
                <h3>🔐 Tenant-Aware Backup</h3>
                <p>We've upgraded the backup system to support multi-tenancy!</p>
                <ul class="list-disc list-inside mt-2 mb-2">
                    <li><strong>Tenant Selection:</strong> You can now choose specific tenants to backup.</li>
                    <li><strong>Safe Restore:</strong> The restore process now analyzes the backup file and warns you before purging any data.</li>
                    <li><strong>Isolation:</strong> Restoring a partial backup only affects the selected tenants, keeping others safe.</li>
                </ul>
                <p class="text-xs text-gray-500">Check the Settings page to try it out.</p>
                """
            )
            session.add(entry_127)

        if not session.query(ChangelogEntry).where(ChangelogEntry.version == "1.2.9").first():
            entry3 = ChangelogEntry(
                title="YADS v1.2.9: Multi-Tenancy & RBAC Extensions",
                version="1.2.9",
                content="""
                <h3>🛡️ Security & Access Control</h3>
                <ul>
                    <li><strong>Tenant Admin Role:</strong> Introduced a new 'Tenant Admin' role capable of managing users within their own tenant.</li>
                    <li><strong>Auditor Role:</strong> Renamed 'Viewer' to 'Auditor' to better reflect the role's purpose.</li>
                    <li><strong>Scoped User Management:</strong> Platform Admins can now manage all users, while Tenant Admins are restricted to their specific tenant scope.</li>
                    <li><strong>Password Resets:</strong> Improved password reset workflows for tenant-specific users.</li>
                </ul>
                <h3>💅 UI Improvements</h3>
                <ul>
                    <li><strong>Role Badges:</strong> Updated visual indicators for different user roles in the management table.</li>
                    <li><strong>Navigation:</strong> Context-aware navigation links for Tenant Admins.</li>
                </ul>
                """
            )
            session.add(entry3)
        
        if not session.query(ChangelogEntry).where(ChangelogEntry.version == "1.3.1").first():
            entry4 = ChangelogEntry(
                title="YADS v1.3.1: Scheduling & Logging Enhancements",
                version="1.3.1",
                content="""
                <h3>📅 Scheduling System</h3>
                <ul>
                    <li><strong>New Scheduling UI:</strong> Users can now configure daily or weekly scan schedules directly from the Target Details page.</li>
                    <li><strong>Automated Scanning:</strong> The backend scheduler now automatically queues scans based on defined schedules.</li>
                </ul>
                <h3>📊 Logging & Analysis</h3>
                <ul>
                    <li><strong>Tenant-Aware Logging:</strong> Logs are now tagged with tenant IDs for better isolation and troubleshooting.</li>
                    <li><strong>Restricted Log Access:</strong> Log viewing is now secured via RBAC, ensuring tenants only see their own logs.</li>
                </ul>
                <h3>🛡️ System Stability</h3>
                <ul>
                    <li><strong>Safe Migrations:</strong> Database migration scripts have been verified to ensure zero data loss during updates.</li>
                </ul>
                """
            )
            session.add(entry4)
        

        session.commit()
        print("Changelog seeded successfully.")

if __name__ == "__main__":
    seed_changelog()
