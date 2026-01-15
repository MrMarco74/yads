# YADS - Comprehensive User Guide
**Version:** 1.5.1
**Last Updated:** 2026-01-15

Welcome to the **YADS (Yet Another Domain Scanner)** manual. This guide covers all aspects of the application, from running your first scan to advanced configuration and multi-tenancy.

---

## Table of Contents

1.  [Introduction](#1-introduction)
2.  [Getting Started](#2-getting-started)
3.  [Dashboard Overview](#3-dashboard-overview)
4.  [Target Management](#4-target-management)
5.  [Running Scans](#5-running-scans)
6.  [Analysis Modules](#6-analysis-modules)
6.  [Analysis Modules](#6-analysis-modules)
7.  [OSINT Brand Monitoring](#7-osint-brand-monitoring)
8.  [Visualizations](#8-visualizations)
9.  [Data Management & Reports](#9-data-management--reports)
10. [User Management & Security](#10-user-management--security)
11. [Multi-Tenancy](#11-multi-tenancy)
12. [System Settings & Queue](#12-system-settings--queue)

---

## 1. Introduction

**YADS** is an automated security reconnaissance platform designed to map, analyze, and monitor internet-facing assets. It combines multiple scanning techniques—DNS enumeration, port scanning, web analysis, and vulnerability detection—into a single, easy-to-use interface.

### Key Features
*   **Asset Discovery**: Find subdomains and forgotten infrastructure.
*   **Vulnerability Scanning**: Detect outdated software (CVEs) and misconfigurations.
*   **Visual Intelligence**: Capture screenshots and visualize network relationships.
*   **Continuous Monitoring**: Track changes over time with change detection.
*   **Multi-User & Multi-Tenant**: Securely manage multiple teams or clients within one instance.

---

## 2. Getting Started

### Accessing the System
Navigate to your YADS instance (e.g., `https://yads.your-domain.com`).
*   **Login**: Enter your username and password.
*   **MFA**: If enabled, enter your Time-based One-Time Password (TOTP) from your authenticator app.

### First Steps
1.  **Dashboard**: You will land on the main dashboard showing an overview of your targets.
2.  **Add Target**: Use the input box at the top (or "Add Target" button) to enter a domain (e.g., `example.com`).
3.  **Run Scan**: Once added, click the "Scan" button to start gathering data.

---

## 3. Dashboard Overview

The Dashboard is your command center.

*   **Critical Attention HUD**: A prominent alert block at the top highlighting immediate threats (e.g. Expired SSL, Critical Vulnerabilities). If the system is secure, this block will confirm it.
*   **Stats Cards**: Fast view of Total Targets, Active Scans, and Queue status.
*   **Target List**: A paginated table of all your monitored domains.
    *   **Status Indicators**: Shows if a scan is `Idle`, `Queued`, `Running`, or `Failed`.
    *   **Health Checks**: Quick indicators for SSL status, Online status, and Risk Score.
*   **Live Activity**: The "Active Scans" panel on the right shows real-time progress of running jobs.

---

## 4. Target Management

### Adding Targets
*   **Single**: Enter a domain in the dashboard input.
*   **Bulk Import**: Click the "Import" button to upload a text file (one domain per line) or paste a list.
    *   *Option*: "Verify DNS" checks if domains are resolvable before adding them.

### Bulk Actions
Select multiple targets using the checkboxes in the table to perform batch operations:
*   **Bulk Scan**: Trigger specific scan modules for all selected targets.
*   **Bulk Delete**: Remove targets and their data.

### Filtering
Use the column filters in the **Table View** to find specific targets:
*   **Filter by Name**: Search for partial domain matches.
*   **Filter by Status**: Show only `Failed` or `Running` scans.
*   **Filter by Tags**: Organize targets using custom tags.

---

## 5. Running Scans

You can run scans in two modes:

### Quick Scan
Clicking the "Play" button on a target runs the **Default Scan Profile**, which includes:
*   DNS Enumeration
*   Web Analysis
*   SSL Check

### Custom Scan
On the **Target Details** page, click **"New Scan"** to open the advanced selector. You can toggle individual modules:
*   **Subdomain Recon**: Finds `sub.example.com`.
*   **DNS Records**: A/AAAA/MX/TXT records.
*   **Web Analyzer**: Screenshots, tech stack, and headers.
*   **Typosquatting**: Checks for phishing domains (e.g., `exampel.com`).
*   **CVE Scanner**: Checks detected software against vulnerability databases.
*   **Port Scan**: Probes common ports (80, 443, 8080, etc.).
*   **Wayback Machine**: Looks for historical files and endpoints.
*   **FULL SCAN**: Runs all available modules.

### Scheduled Scans
You can automate your reconnaissance by setting up a recurring schedule for any target.
1.  Navigate to the **Target Details** page of the desired domain.
2.  Locate the **Scheduling** card in the left sidebar.
3.  Select **Daily** or **Weekly**.
    *   **Daily**: Runs every 24 hours.
    *   **Weekly**: Runs every 7 days.
    *   **Disable**: Stops any future automated scans.

*Note: Scheduled scans automatically execute the **FULL SCAN** profile to ensure comprehensive coverage.*

---

## 6. Analysis Modules

### Web Analyzer & OSINT
Visits the page as a real user.
*   **Visuals**: Full-page screenshot and favicon.
*   **Technologies**: Identifies CMS (WordPress), Server (Nginx), and Frameworks.
*   **OSINT**: Extracts emails, phone numbers, and social media links found on the page.

### Vulnerability Report (CVEs)
*   Matches version numbers (e.g., "Apache 2.4.49") against known CVEs.
*   Displays severity (CVSS) and descriptions.
*   *Note*: This logic relies on accurate version detection.

### Infrastructure Scanner
*   **Geo-Location**: Maps the server IP to a physical location.
*   **ASN Info**: Identifies the hosting provider (e.g., AWS, DigitalOcean).
*   **Cloud Check**: Detects if the asset is on a major cloud provider.
*   **Reputation**: Checks IP against spam/malware blacklists.

### DNS & Subdomain
*   **Passive Recon**: Uses public logs (CT) to find subdomains without touching the target.
    *   **Active Brute-force**: Tries common subdomain names.
    *   **Dangling CNAMEs**: Warns if a subdomain points to a non-existent cloud resource (hijacking risk).

### Vulnerability Scanning (Active)

**(New in v1.5.0)**
YADS now integrates **Nuclei** for active vulnerability detection.
*   **Capabilities**: Scans for 5000+ known vulnerabilities (CVEs), misconfigurations, and exposed panels.
*   **Severity**: Findings are categorized as Critical, High, Medium, Low, or Info.
*   **Usage**: Select "Nuclei Vulnerability Scan" in the *New Scan* modal.

### Stealth Port Scanning

**(New in v1.5.0)**
*   **Stealth Mode**: Uses Nmap with evasion flags (`-sS`, `-T2`, `-D RND:5`) to probe ports without triggering IDS/IPS.
*   **Slow & Safe**: Designed for stealth, this scan takes longer but reduces detection risk.

### JavaScript SAST

**(New in v1.5.0)**
*   **Static Analysis**: Automatically downloads and analyzes client-side JavaScript files.
*   **Sink Detection**: Identifies potential DOM XSS sinks (e.g. `innerHTML`, `document.write`).
*   **Route Discovery**: Extracts hidden API routes from JS code.


### API Discovery
**(New in v1.4.0)**
Part of the Web Analyzer, this module automatically detects:
*   **Documentation**: Finds `swagger.json`, `openapi.yaml`, and WSDL files.
*   **Endpoints**: Identifies GraphQL endpoints (`/graphql`) and versioned REST paths (`/api/v1/`).
*   **Results**: displayed in the **Web Analysis** card on the Target Details page.

### SOC2 Compliance Engine
**(New in v1.3.5)**
Real-time scoring of your infrastructure's compliance readiness.
*   **Score**: Calculated dynamically (0-100%) based on active scan results.
*   **Penalties**:
    *   **Expired SSL**: -20 pts
    *   **Critical CVEs**: -15 pts
    *   **Risky Ports**: -10 pts (e.g. 21, 23, 3389 open to internet)
    *   **Public Buckets**: -25 pts
*   **Insights**: Hover over the score widget on the Dashboard to see specific failings.

---

## 7. OSINT Brand Monitoring

**(New in v1.3.2)**

The OSINT module helps you discover unmonitored assets by finding where your brand assets (logos) appear on the web.

### Google Cloud Setup (Prerequisite)
To use this feature, your Tenant Admin must configure the **Google Cloud Vision API**:
1.  **Enable API**: In your Google Cloud Console, enable the **"Cloud Vision API"**.
2.  **API Key**: Create an API Key in "Credentials".
    *   *Important*: If you restrict your API Key (recommended), ensure **Cloud Vision API** is checked in the list of allowed APIs.
3.  **Billing**: The Cloud Vision API requires an active Billing Account linked to the project (even for the free tier).

### Reverse Image Search
1.  **Preparation**: Ensure your Tenant Admin has configured the **Google Cloud Vision API** keys in the Tenant Settings.
2.  **Upload**: Drag and drop your official logo (PNG/JPG) into the search zone.
3.  **Analysis**: The system uses Google's **Vision API (Web Detection)** to find exact copies or visually similar images across the entire web.
4.  **Result Filtering**:
    *   **Unknown**: Domains not currently in your target list. You can import these with one click.
    *   **Monitored**: Domains you are already tracking.

### License & Quotas
This feature is licensed separately per tenant.
*   **Locked State**: If you see a "Locked" icon in the sidebar, your tenant has not purchased this add-on.
*   **Usage Limits**: Your admin sets a monthly search quota. If exceeded, searches will be blocked until the next cycle.

---

## 8. Visualizations

### Network Graph
An interactive node-graph showing relationships between Domains, IPs, and ASNs.
*   **Plot Graph**: Click the "Plot Graph" button in the sidebar to fetch and display data.
*   **Context Messaging**: If no data is available for the selected filters, the system will provide specific feedback (e.g., "Has this target been scanned?").
*   **Filters**:
    *   **Show Web Links**: Toggle visibility of HTTP-based edges.
    *   **Gray out DNS**: Fades DNS connections to gray to highlight the web structure.
*   **Clusters**: See which domains share the same hosting infrastructure.
*   **Zoom/Pan**: Navigate large infrastructures easily.

### Analytics Dashboard
High-level metrics for management.
*   **World Map**: Physical location of all assets.
    *   **Tech Distribution**: charts showing most common technologies (e.g., "80% Nginx").
    *   **Risk Overview**: Summary of critical vulnerabilities across the portfolio.

### Compliance & Grading
**(New in v1.5.0)**
Found at the top of every **Target Detail** page:
*   **Security Grade (A-F)**: A composite score based on SSL, Headers, Vulnerabilities, and Open Ports.
*   **Risk Factors**: Explicitly lists the reasons for score deductions (e.g. "Missing HSTS -10").
*   **Compliance Gaps**: Maps technical findings to industry standards:
    *   **OWASP Top 10**: e.g. A05 (Misconfiguration), A02 (Crypto Failures).
    *   **GDPR / ISO 27001**: Detects PII exposure and secrets.


### Spiderweb (Redirect Graph)
Visualizes redirect chains.
*   **Entry Points**: See where users land after typing a domain.


### External Links Analysis
The **External Links** view helps you identify third-party dependencies and potential shadow IT.
- **Access**: Go to `Analytics > External Links` in the sidebar.
- **Purpose**: Lists all domains found during scans (via Crawler or DNS) that are **not** part of your defined Targets.
- **Features**:
    - **Scope Awareness**: Automatically excludes your own targets/subdomains.
    - **Sources**: Shows which of your targets link to the external domain.
    - **Type**: Indicates if the link was found via a webpage link (`link`), Mail Exchange record (`MX`), Nameserver (`NS`), etc.
    - **Export**: Click "Export PDF" to download a summary report.

### Dead Links Analysis
**(New in v1.4.0)**
Identify health issues within your own inventory.
- **Access**: Go to `Analytics > Dead Links`.
- **Unreachable Targets**: Lists targets that failed recent scans (Offline or Server Error).
- **Orphaned Targets**: Lists targets in your inventory that are **not linked to** by any other target in your scope. Useful for finding forgotten assets.

---

## 9. Data Management & Reports

### Exporting Data
*   **PDF Report**: On the Target Details page, download a professionally formatted PDF summary.
*   **Excel Export**: The Target Overview page features an expanded Excel export including all UI columns: SSL details, CVE counts, Secrets, ASN/ISP info, and more.
*   **Backup**: Admin users can export the entire database and assets as a ZIP file from the Settings page.

### System Logs
*   **View Logs**: Admins can inspect real-time application and worker logs for troubleshooting.
*   **Stream**: The log viewer updates live as scans progress.

---

## 10. User Management & Security

*(Admin Only)*

### Managing Users
Go to **Users** in the navbar.
*   **Create User**: Define username, password, and initial role.
*   **Roles**:
    *   **Viewer**: Read-only access to dashboards.
    *   **Scanner**: Can add targets and run scans.
    *   **Admin**: Full system access, including settings and user management.

### Multi-Factor Authentication (MFA)
*   Users can enable 2FA in their profile.
*   Admins can see who has MFA enabled but cannot disable it for them (users must reset if lost, or Admin deletes user).

### Tenant Assignment
*   Assign users to specific **Tenants** to isolate their view. A user assigned to "Client A" will only see targets belonging to "Client A".

---

## 11. Multi-Tenancy

YADS supports multiple isolated environments (Tenants).
*   **Isolation**: Targets, Results, and Users are scoped to a Tenant.
*   **Switching**: Users with access to multiple tenants can switch context via the dropdown in the top navigation bar.
*   **Management**: Admins can rename tenants and manage memberships via the **Tenants** page.
*   **Management**: Admins can rename tenants and manage memberships via the **Tenants** page.
*   **Platform Admin**: An Admin without a specific tenant sees *everything* and can manage the tenants themselves.

### Webhook Notifications
**(New in v1.4.0)**
Tenants can configure real-time webhooks to integrate with external systems (Slack, Discord, Tines, etc.).
1.  Go to **Tenant Settings**.
2.  Scroll to the **Webhook Notifications** card.
3.  Add a URL and select events (e.g., `scan_finished`, `new_asset`).
4.  Use the **Test** button to verify connectivity.

---

## 12. System Settings & Queue

*(Admin Only)*

### Queue Control
*   **Pause/Resume**: Stop the background worker from processing new scans. The worker will check for the Resume signal every 60 seconds.
*   **Clear Queue**: PANIC BUTTON. Cancels all pending and running scans and resets their status to "Idle" in the database. Use this if the system gets stuck.
*   **System Reset**: Reverts the system to a "Clean State". This removes all scan data and tenants, but preserves user accounts and system configurations.

### Configuration
*   **Web Timeout**: Set global timeout for HTTP requests (default: 10s).
*   **Concurrent Limits**: Define how many headers scanners run in parallel.

---

## 13. Best Practices

To get the most out of YADS, consider these tips:
> **💡 Pro Tip**: Schedule regular scans during off-peak hours to minimize network impact.

1.  **Tagging**: Use tags creatively (e.g., `prod`, `dev`, `critical`) to organize targets.
2.  **Regular Reviews**: Check the **Analytics** page weekly to spot trends in vulnerability counts.
3.  **Scope Definition**: Be careful when adding root domains (e.g., `company.com`) as the **Subdomain Recon** module might find hundreds of assets.

---

## 14. Troubleshooting

### Common Issues

#### 🛑 Scan stuck in "Pending"
*   **Cause**: The background worker might be paused or overloaded.
*   **Fix**: Check **Settings > Queue Control** and ensure the queue is active. Check **active workers** count. The worker auto-heals every 60 seconds if it was paused.

#### ⚠️ "Web Analyzer" failed
*   **Cause**: Target might be offline or blocking the scanner.
*   **Fix**: Try visiting the URL manually. Adjust **Web Request Timeout** in settings if the site is slow.

#### 🚫 MFA Code Rejected
*   **Cause**: Time drift on the server or client.
*   **Fix**: Ensure your server time is synced via NTP.

---

## 15. Support

For technical support or to report bugs:
*   **Internal Wiki**: [Link to internal wiki]
*   **Email**: `security-team@example.com`

---

*Verified for YADS v1.4.0*
