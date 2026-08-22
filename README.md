# YADS (Yet Another Domain Scanner) — v1.27.0

YADS is a powerful, automated domain intelligence and security scanner. It aggregates data from multiple sources to provide a comprehensive view of a target domain's attack surface, with AI-powered analysis, attack path visualization, and full vulnerability lifecycle management.

## 📚 Documentation
> **[📖 Read the User Guide](docs/USER_GUIDE.md)** for detailed usage instructions and feature explanations.

## ✨ Key Features

*   **AI Intelligence Suite**: AI-powered finding prioritization, remediation assistant, and natural language search (OpenAI/Anthropic BYOK, with rule-based fallbacks). Full EN/DE language support.
*   **Attack Path Visualizer**: Interactive D3.js force-directed graph showing exploitation chains from open ports through services to critical findings.
*   **Executive C-Level Report**: Security grade (A–F), risk trend, KPI cards, top vulnerabilities, and recommended actions — printable to PDF.
*   **Finding Management**: Track every finding through Open → Acknowledged → Fixed with analyst notes, status filtering, and CSV export.
*   **Asset Tagging**: Organize targets with custom tags, interactive tag cloud, bulk operations, and inline editing.
*   **Multi-Domain Portfolio View**: Platform-admin cross-tenant overview with per-tenant security scores, finding counts, and top vulnerable domains.
*   **Web Analysis**: Headless browser scans with screenshot capture, tech stack detection, and OSINT extraction (Emails, Socials, Documents).
*   **Extended Cloud Scanner**: AWS S3, GCS, Azure Blob, DigitalOcean Spaces, Cloudflare R2, plus Shadow IT detection (Netlify, Vercel, Heroku, Firebase, Render, Railway, Fly.io, GitHub Pages).
*   **DNS & Subdomains**: Deep DNS analysis (Dangling CNAMEs) and subdomain enumeration via Certificate Transparency.
*   **SSL Security**: Certificate validity and cipher strength auditing incl. Post-Quantum Cryptography (PQC) readiness assessment.
*   **Multilanguage Reports**: PDF and Excel exports with `?lang=en|de` parameter — all column headers, section titles, and fixed strings translated.
*   **Parallel Scan Execution**: Independent scanner modules run concurrently (up to 6 threads) for faster scan completion.
*   **Deception Detection**: Identifies Honeypots (Web/SSH/FTP/SMTP), DNS Sinkholes, and Tarpits with confidence scoring.
*   **Reporting**: Export full audit reports as PDF with cover page, chapter intros, and AI executive summary.
*   **Disaster Recovery**: Built-in Backup & Restore functionality (encrypted, password-protected).

## 🆕 What's New in v1.27.0

*   **Recon Correlation** — Third-party domain risk aggregation, attack-surface delta views (newly opened/closed ports), WAF-bypass verification against real findings, Whois × DNS ownership-change detection, and baseline diffing for API/mobile-app discovery.
*   **Compliance Suite** — Real Finding → MITRE ATT&CK mapping with an interactive Navigator heatmap, a NIS2 Article 21 measures dashboard, NIS2 24h/72h incident-reporting timers, and a DORA ICT third-party register with resilience-testing evidence export.
*   **Notifications, Triage & UX** — Finding triage workflow (acknowledge/snooze/assign/ticket), an undo window for destructive actions, global search, command palette, saved filter views, bulk actions, and an onboarding tour.
*   **Reporting & Platform Ops** — CSV/JSON/SARIF export, recurring report delivery, MSSP white-labeling, Mean-Time-To-Remediate (MTTR) tracking, and a detailed `/health` endpoint for external monitoring.
*   **Security Hardening** — Closed an IDOR on finding-status endpoints, an SSRF gap in integration health checks, and a reflected XSS vector in search; replaced a regex-based HTML sanitizer with a proper HTML parser in the report generator.

See the [full release notes](https://github.com/MrMarco74/yads/releases/tag/v1.27.0) for the complete list of ~90 changes.

## 🚀 Quick Start & Installation

1.  **Deployment**:
    The infrastructure configuration lives in the **[yads-infra](https://github.com/MrMarco74/yads-infra)** repository, which builds against a sibling `yads` checkout (no prebuilt images or registry needed).

    YADS is split across several repos that need to move together — clone the matching
    [release tag](https://github.com/MrMarco74/yads/releases) rather than `main` for a
    known-working combination (see a release's notes for the full compatible tag list):

    ```bash
    git clone --branch v1.27.0 https://github.com/MrMarco74/yads.git
    git clone --branch v1.27.0 https://github.com/MrMarco74/yads-infra.git
    cd yads-infra
    docker compose up -d
    ```

2.  **Initial Setup Wizard**:
    Open `http://<your-server-ip>:8000`. You will be automatically redirected to the **Setup Wizard**.
    Follow the steps:

    *   **Database**: Set a secure password for the database.
    *   **Initialization**: Choose "Upgrade" (keep data) or "Factory Reset" (purge data).
    *   **Admin**: Create your first System Admin account.

3.  **Manual Development Setup**:
    YADS is split into multiple repositories. For development, ensure they are checked out as peer directories:

    ```bash
    # Core API & Models
    git clone https://github.com/MrMarco74/yads.git

    # Common Utilities (Required by many)
    git clone https://github.com/MrMarco74/yads-common.git

    # Setup for Core:
    cd yads
    pip install -r requirements.txt
    pip install -e ../yads-common
    uvicorn yads.api.main:app --reload
    ```

## 📂 Project Structure

- `yads`: Core API, Workers, and Models.
- `yads-common`: Shared GUI components, cryptography, and utilities.
- `yads-addons`: Optional scanner modules loaded via the Extension Hub.
- `yads-shadowtwin`: Monte Carlo breach-simulation engine.
- `yads-templates`: Jinja2 report templates.
- `yads-infra`: Docker Compose and infrastructure configurations.
- `yads-kubernetes`: Helm charts, Terraform, and Ansible for large-scale deployment.
- `yads-documentation`: Architecture blueprints and contributor guides.

## 🗺️ Roadmap

| Version | Status | Highlights |
|---------|--------|------------|
| **v1.20.0** | ✅ Shipped | AI Intelligence Suite, Attack Path Visualizer, Finding Management, Portfolio View, Asset Tagging, Parallel Scans |
| **v1.21.x – v1.26.x** | ✅ Shipped | Splunk/SIEM integration suite, distributed workers, custom module system, module signing, NIS2/DORA compliance groundwork |
| **v1.27.0** | ✅ Current | Recon correlation, MITRE ATT&CK mapping, NIS2/DORA compliance suite, finding triage, MTTR tracking, security hardening pass |
| **v2.0** | 💡 Vision | Mobile App, Advanced SOAR Playbooks, ML-based Anomaly Detection |

## License

MIT License. See [LICENSE](LICENSE) for details.
