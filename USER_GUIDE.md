# YADS - User Guide

**YADS** (Yet Another Domain Scanner) is a comprehensive automated scanner for analyzing domain security, infrastructure, and OSINT data.

## 🚀 Getting Started

1.  **Add a Target**: Go to the Dashboard and enter a domain name (e.g., `example.com`) in the "Add New Target" box.
2.  **Start Scanning**:
    *   Click "Scan Now" on the dashboard for a quick default scan.
    *   Or go to the **Target Details** page and click **"New Scan"** to select specific modules.

---

## 🛠 Scanner Modules

YADS includes several specialized scanners that run in parallel:

### 1. Web Analyzer & OSINT
*   **What it does**: Visits the website using a headless browser (Playwright) to capture what a real user sees.
*   **Features**:
    *   📸 **Screenshots**: Captures a full-page screenshot.
    *   🧬 **Tech Stack**: Identifies CMS (WordPress, Drupal), Frameworks (React, Vue), and Server tech.
    *   🕵️ **OSINT Extraction**:
        *   **Contacts**: Extracts proper email addresses and phone numbers.
        *   **Socials**: Finds links to LinkedIn, Twitter/X, GitHub, etc.
        *   **Documents**: Lists public files (`.pdf`, `.docx`, `.xlsx`) linked on the page.
    *   ⚠️ **Risk Hints**: Checks for exposed sensitive keywords or debug modes.

### 2. DNS & Subdomain Scanner
*   **DNS Records**: Fetches A, AAAA, MX, TXT, SPF, DMARC records. Checks for **Dangling CNAMEs** (hijacking risk).
*   **Subdomain Enumeration**:
    *   Uses **Certificate Transparency** logs (`crt.sh`) to find subdomains.
    *   Performs active DNS brute-forcing with a wordlist.
    *   Verifies which subdomains are actually alive.

### 3. Infrastructure Scanner
*   **Network Intelligence**: Resolves IPs to **ASN** (Autonomous System Number) and Location (Country/City).
*   **Cloud Detection**: Identifies if the target is hosted on AWS, Google Cloud, Azure, etc.
*   **Storage Buckets**: Checks for common S3 bucket names associated with the domain and tests if they are public.
*   **Reputation**: Checks the IP against blacklist/spam databases (e.g., Spamhaus).

### 4. Typosquat Scanner
*   **Brand Protection**: Generates hundreds of "look-alike" domain variations (e.g., `exampel.com`).
*   **Detection**: Checks if these domains are registered and resolving, indicating potential phishing traps targeting your brand.

### 5. SSL Scanner
*   **Certificate Audit**: detailed analysis of the SSL/TLS certificate (Issuer, Valid Dates, SANs).
*   **Configuration**: Checks for weak Cipher Suites or outdated protocols.

---

## 📊 Reports & Data Management

### Target Details & PDF Export
*   View all scan results on a single, comprehensive page.
*   **Export PDF**: Click the "Export PDF" button to download a summary report suitable for sharing with stakeholders.

### Backup & Recovery
*   Located in **Settings** > **Data Backup & Recovery**.
*   **Export**: Download a complete `.zip` archive of your database and screenshots.
*   **Restore**: Upload a backup zip to restore the system to a previous state.
    *   *Warning*: Restore is a destructive action that replaces current data.

---

## ⚙️ Settings

Customize the scanner behavior:
*   **Concurrent Scans**: Limit how many domains are scanned at once.
*   **Timeouts**: Adjust long/short timeouts for network requests.
*   **Auto-Queueing**: Automatically re-scan targets periodically (configurable interval).
