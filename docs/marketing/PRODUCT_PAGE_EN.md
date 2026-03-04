# YADS: Yet Another Domain Scanner
## Next-Gen Attack Surface Management Platform

> **Secure your digital infrastructure with automated reconnaissance, deep vulnerability analysis, and visual intelligence.**

![YADS Dashboard Overview](/home/mrmarco/Documents/gitlab/yads/product_screenshots/dashboard_hero.png)

---

### 🚀 Why YADS?

YADS is an all-in-one security platform designed for modern DevSecOps teams, Penetration Testers, and MSSPs. It automates the tedious process of reconnaissance and delivers actionable insights in real-time.

| **Comprehensive** | **Automated** | **Multi-Tenant** |
| :--- | :--- | :--- |
| From DNS enumeration to Web App Vulns – everything in one tool. | Schedule scans daily or weekly. "Set and Forget". | Manage multiple clients or teams in isolated environments. |

---

### ✨ Key Features

#### 1. Asset Discovery & Inventory
Never lose track of your external attack surface again.
*   **Subdomain Enumeration**: Finds hidden and forgotten subdomains (e.g., `dev.company.com`).
*   **Technology Fingerprinting**: Automatically detects CMS, Webservers, and Frameworks (Tech Radar).
*   **Cloud Infrastructure**: Identifies hosting providers and geo-locations.

![Asset Inventory](/home/mrmarco/Documents/gitlab/yads/product_screenshots/assets_list.png)

#### 2. Deep Vulnerability Scanning
Integrates industry-leading scanners for maximum coverage.
*   **Nuclei Integration**: Scans for over 5000+ known CVEs and misconfigurations.
*   **Stealth Port Scanning**: Detects open ports without triggering IDS/IPS.
*   **JavaScript SAST**: Analyzes client-side JS for DOM XSS and sensitive API keys.

#### 3. Visual Intelligence & Network Graph
Data is useless if you don't understand it. YADS makes connections visible.
*   **Interactive Network Graph**: Visualizes connections between Domains, IPs, and ASNs.
*   **Attack Path Visualization**: Highlights risky paths and compromise chains.
*   **OSINT Brand Monitoring**: Finds unauthorized use of your logos across the web (Phishing detection).

![Network Graph Visualization](/home/mrmarco/Documents/gitlab/yads/product_screenshots/network_graph.png)

#### 4. Compliance & Reporting
Turn technical data into management-ready reports.
*   **SOC2 Readiness Score**: Real-time assessment of your compliance (0-100%).
*   **Security Grading**: Automatic grading (A-F) for every asset.
*   **PDF Exports**: Generate professional Executive Reports with one click.

![Compliance Dashboard](/home/mrmarco/Documents/gitlab/yads/product_screenshots/compliance_report.png)

#### 5. Automation & Integration
*   **Scan Scheduler**: Automate recurring audits.
*   **Webhook Notifications**: Send alerts directly to Slack, Teams, or Tines.
*   **API-First Design**: Integrate YADS seamlessly into your CI/CD pipelines.

---

### 🛡️ Technical Highlights

*   **Docker-Native**: Easy deployment with `docker-compose`.
*   **Role-Based Access Control (RBAC)**: Granular permissions for Admins, Scanners, and Viewers.
*   **High Performance**: Parallel processing with Celery and Redis.

> **"YADS reduced our recon time from days to minutes."**

---

### 💻 Get Started Now

Ready to secure your attack surface?

[View Documentation](./USER_GUIDE.md) | [Contact Us](mailto:sales@yads-security.com)

---

### 🆕 What's New in v1.18.5 — Security Hardening Release

> *Released: March 2026*

This release focuses on **code quality and security hardening** across the entire codebase.

#### 🔐 Security Fixes
*   **Deception Detection Module** — New scanner module for detecting Honeypots, DNS Sinkholes, and Tarpits with confidence scoring (0–100)
*   **XSS Protection** — Jinja2 template engine configuration in `markdown_report_generator.py` documented and secured
*   **SSL Certificate Handling** — All `verify=False` calls across scanner modules annotated with security comments (intentional behavior for security scanners)
*   **Subprocess Hardening** — All external tool calls (nmap, nuclei, docker) annotated with explicit `# nosec` comments

#### 🧹 Code Quality
*   **Deprecated API** — `datetime.utcnow()` replaced with timezone-aware `datetime.now(timezone.utc)` throughout
*   **Duplicate Literals** — `'+00:00'` centralized as `_UTC_SUFFIX` constant
*   **Bare Except** — `except:` replaced with `except Exception:` where applicable
*   **SQL False Positives** — Documented that `safe_table_name` in `backup.py` is a compile-time constant, not user input

#### 🕵️ New Module: Deception Detection
*   Detects **Honeypots** (Web, SSH, FTP, Telnet, SMTP) using known signature databases
*   Detects **DNS Sinkholes** (Spamhaus, Microsoft DCU, FBI, Shadowserver)
*   Detects **Tarpits** with timing analysis (HTTP, SMTP, TCP)
*   **Confidence Scoring**: Every detection rated 0–100% confidence with risk level (low/medium/high/critical)
*   **Frontend Integration**: Full display in Target Detail View

---

### 🗺️ Roadmap

| Version | Status | Highlights |
|---------|--------|------------|
| **v1.18.5** | ✅ Current | Deception Detection, Security Hardening, Code Quality |
| **v1.19.x** | 🔄 In Development | Wayback Machine Integration, Visual Regression Monitor |
| **v1.20.x** | 📋 Planned | AI-Powered Executive Reporting (Ollama/OpenAI), Cloud Asset Enumeration (S3/GCS/Azure) |
| **v2.0** | 💡 Vision | Credential & Leak Monitoring (HIBP), Attack Path Visualization, JIRA/Ticket Integration |

*Copyright © 2026 YADS Security Project — v1.18.5*
