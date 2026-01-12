# YADS - Comprehensive User Guide

Welcome to the **YADS (Yet Another Domain Scanner)** manual. This guide covers all aspects of the application, from running your first scan to advanced configuration and multi-tenancy.

---

## Table of Contents

1.  [Introduction](#1-introduction)
2.  [Getting Started](#2-getting-started)
3.  [Dashboard Overview](#3-dashboard-overview)
4.  [Target Management](#4-target-management)
5.  [Running Scans](#5-running-scans)
6.  [Analysis Modules](#6-analysis-modules)
7.  [Visualizations](#7-visualizations)
8.  [Data Management & Reports](#8-data-management--reports)
9.  [User Management & Security](#9-user-management--security)
10. [Multi-Tenancy](#10-multi-tenancy)
11. [System Settings & Queue](#11-system-settings--queue)

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

---

## 7. Visualizations

### Network Graph
An interactive node-graph showing relationships between Domains, IPs, and ASNs.
*   **Plot Graph**: Click the "Plot Graph" button in the sidebar to fetch and display data.
*   **Context Messaging**: If no data is available for the selected filters, the system will provide specific feedback (e.g., "Has this target been scanned?").
*   **Clusters**: See which domains share the same hosting infrastructure.
*   **Zoom/Pan**: Navigate large infrastructures easily.

### Analytics Dashboard
High-level metrics for management.
*   **World Map**: Physical location of all assets.
*   **Tech Distribution**: charts showing most common technologies (e.g., "80% Nginx").
*   **Risk Overview**: Summary of critical vulnerabilities across the portfolio.

### Spiderweb (Redirect Graph)
Visualizes redirect chains.
*   **Entry Points**: See where users land after typing a domain.
*   **Loops**: Identify configuration errors causing infinite redirects.

---

## 8. Data Management & Reports

### Exporting Data
*   **PDF Report**: On the Target Details page, download a professionally formatted PDF summary.
*   **Excel Export**: The Target Overview page features an expanded Excel export including all UI columns: SSL details, CVE counts, Secrets, ASN/ISP info, and more.
*   **Backup**: Admin users can export the entire database and assets as a ZIP file from the Settings page.

### System Logs
*   **View Logs**: Admins can inspect real-time application and worker logs for troubleshooting.
*   **Stream**: The log viewer updates live as scans progress.

---

## 9. User Management & Security

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

## 10. Multi-Tenancy

YADS supports multiple isolated environments (Tenants).
*   **Isolation**: Targets, Results, and Users are scoped to a Tenant.
*   **Switching**: Users with access to multiple tenants can switch context via the dropdown in the top navigation bar.
*   **Management**: Admins can rename tenants and manage memberships via the **Tenants** page.
*   **Platform Admin**: An Admin without a specific tenant sees *everything* and can manage the tenants themselves.

---

## 11. System Settings & Queue

*(Admin Only)*

### Queue Control
*   **Pause/Resume**: Stop the background worker from processing new scans. Useful for maintenance.
*   **Clear Queue**: Remove all pending jobs.
*   **System Reset**: Reverts the system to a "Clean State". This removes all scan data and tenants, but preserves user accounts and system configurations.

### Configuration
*   **Web Timeout**: Set global timeout for HTTP requests (default: 10s).
*   **Concurrent Limits**: Define how many headers scanners run in parallel.

---

## 12. Best Practices

To get the most out of YADS, consider these tips:
> **💡 Pro Tip**: Schedule regular scans during off-peak hours to minimize network impact.

1.  **Tagging**: Use tags creatively (e.g., `prod`, `dev`, `critical`) to organize targets.
2.  **Regular Reviews**: Check the **Analytics** page weekly to spot trends in vulnerability counts.
3.  **Scope Definition**: Be careful when adding root domains (e.g., `company.com`) as the **Subdomain Recon** module might find hundreds of assets.

---

## 13. Troubleshooting

### Common Issues

#### 🛑 Scan stuck in "Pending"
*   **Cause**: The background worker might be paused or overloaded.
*   **Fix**: Check **Settings > Queue Control** and ensure the queue is active. Check **active workers** count.

#### ⚠️ "Web Analyzer" failed
*   **Cause**: Target might be offline or blocking the scanner.
*   **Fix**: Try visiting the URL manually. Adjust **Web Request Timeout** in settings if the site is slow.

#### 🚫 MFA Code Rejected
*   **Cause**: Time drift on the server or client.
*   **Fix**: Ensure your server time is synced via NTP.

---

## 14. Support

For technical support or to report bugs:
*   **Internal Wiki**: [Link to internal wiki]
*   **Email**: `security-team@example.com`

---

*Verified for YADS v1.2.8*
