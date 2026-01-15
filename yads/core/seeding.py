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
        
        if not session.query(ChangelogEntry).where(ChangelogEntry.version == "1.3.4").first():
            entry5 = ChangelogEntry(
                title="YADS v1.3.4: External Links Analysis & Reports",
                version="1.3.4",
                content="""
                <h3>🌍 External Links Analysis</h3>
                <p>New analytics view to identify third-party dependencies!</p>
                <ul>
                    <li><strong>Detection:</strong> Automatically lists all external domains (not in your targets) found via Crawler links or DNS records.</li>
                    <li><strong>Tenant-Aware:</strong> Respects your tenant scope, showing only links from your targets.</li>
                    <li><strong>PDF Export:</strong> You can now export the External Links report to a professional PDF format for sharing.</li>
                </ul>
                """
            )
            session.add(entry5)

        # 1.4.0
        if not session.query(ChangelogEntry).where(ChangelogEntry.version == "1.4.0").first():
            entry_140 = ChangelogEntry(
                title="YADS v1.4.0: Critical Analytics & Performance Update",
                version="1.4.0",
                content="""
                <h3>🛡️ Critical Analytics HUD</h3>
                <ul>
                    <li><strong>Functional "Critical Attention" Block:</strong> The dashboard now highlights <i>real</i> Urgent threats (Expired SSL, Critical CVEs, Public Buckets) in the top widget.</li>
                    <li><strong>System Secure State:</strong> If no critical issues are found, the dashboard clearly indicates a secure status.</li>
                </ul>
                <h3>📊 SOC2 Compliance Engine</h3>
                <p>The Compliance widget is now fully operational!</p>
                <ul>
                    <li><strong>Real-Time Scoring:</strong> Calculates a readiness score (0-100%) based on active scan findings.</li>
                    <li><strong>Penalties:</strong> Deducts points for security lapses like Expired SSL (-20), Critical CVEs (-15), and Risky Ports (-10).</li>
                </ul>
                <h3>⚡ Performance Optimizations</h3>
                <ul>
                    <li><strong>External Links Page:</strong> Refactored to load instantly. Data is now calculated asynchronously in the background.</li>
                </ul>
                <h3>🕸️ Network Analysis</h3>
                <ul>
                    <li><strong>Dead Links Analysis:</strong> New dashboard to identify unreachable targets and orphaned domains.</li>
                    <li><strong>Graph Filters:</strong> Added filters to the Network Graph to toggle "Web Links" visibility.</li>
                </ul>
                """
            )
            session.add(entry_140)

        # 1.5.0 - DEEP SECURITY UPDATE
        if not session.query(ChangelogEntry).where(ChangelogEntry.version == "1.5.0").first():
            entry_150 = ChangelogEntry(
                title="YADS v1.5.0: Deep Security & Compliance Update",
                version="1.5.0",
                content="""
                <h3>🚀 Deep Security Features</h3>
                <ul>
                    <li><strong>Nuclei Vulnerability Integration:</strong> Active scanning for 5000+ known vulnerabilities using ProjectDiscovery's Nuclei. Findings are categorized instantly (Critical, High, Medium).</li>
                    <li><strong>Stealth Nmap Scan:</strong> New "Stealth" option using evasion flags (<i>-sS, -T2, -D RND:5</i>) for undetectable port scanning.</li>
                    <li><strong>JS SAST Analysis:</strong> Static Analysis of client-side JavaScript to detect DOM XSS sinks (<i>innerHTML, eval</i>) and hidden API routes.</li>
                </ul>
                <h3>📊 Reporting & Compliance</h3>
                <ul>
                    <li><strong>Security Grade Mapping:</strong> Aggregates all scan data into an <strong>A-F Grade</strong> with clear risk factor deductions.</li>
                    <li><strong>Compliance Dashboard:</strong> Automatically maps findings to standards like <strong>OWASP Top 10</strong> and <strong>GDPR/ISO27001</strong>.</li>
                    <li><strong>Swagger/OpenAPI Parser:</strong> Automatically detects and displays API endpoints from <i>swagger.json</i> files.</li>
                </ul>
                """
            )
            session.add(entry_150)


        # 1.5.1 - STABILITY UPDATE
        if not session.query(ChangelogEntry).where(ChangelogEntry.version == "1.5.1").first():
            entry_151 = ChangelogEntry(
                title="YADS v1.5.1: Critical Stability & Queue Reliability",
                version="1.5.1",
                content="""
                <h3>🛠️ Critical Stability Fixes</h3>
                <ul>
                    <li><strong>Queue Reliability:</strong> Fixed a race condition where the background worker could become unresponsive to "Resume" commands. It now self-heals automatically.</li>
                    <li><strong>Zombie Status Fix:</strong> The "Clear Queue" button now correctly resets the status of all stuck jobs in the database, removing "Zombie" badges from the UI.</li>
                    <li><strong>Connection Limits:</strong> Optimised database connection pooling to prevent Server Errors (500) during heavy loads.</li>
                </ul>
                """
            )
            session.add(entry_151)

        session.commit()
        print("Changelog seeded successfully.")

if __name__ == "__main__":
    seed_changelog()
