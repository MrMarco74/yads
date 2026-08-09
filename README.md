# YADS (Yet Another Domain Scanner) — v1.20.0

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

## 🆕 What's New in v1.20.0

*   **AI Assistant** — Finding prioritization, remediation steps, and NL search via OpenAI/Anthropic (BYOK). Rule-based fallbacks for all three features. Full DE/EN multilanguage output.
*   **Attack Path Visualizer** — D3.js force-directed graph mapping exploitation chains per target.
*   **Executive Report (C-Level)** — Non-technical security dashboard with grade, trend, KPIs, and recommended actions.
*   **Finding Management** — Lifecycle tracking (Open/Acknowledged/False Positive/Fixed), analyst notes, CSV export.
*   **Asset Tagging UI** — Tag cloud, bulk operations, inline editing, central tag management.
*   **Portfolio View** — Cross-tenant security overview for platform administrators.
*   **Extended Cloud Scanner** — DigitalOcean Spaces (NYC3/AMS3), Cloudflare R2, Shadow IT detection across 8 PaaS platforms.
*   **Multilanguage Exports** — PDF and Excel with `?lang=de` support for full German output.
*   **Parallel Scan Execution** — ThreadPoolExecutor with up to 6 concurrent modules per scan.

## 🚀 Quick Start & Installation

1.  **Deployment**:
    The infrastructure configuration lives in the **[yads-infra](https://github.com/MrMarco74/yads-infra)** repository, which builds against a sibling `yads` checkout (no prebuilt images or registry needed).

    YADS is split across several repos that need to move together — clone the matching
    [release tag](https://github.com/MrMarco74/yads/releases) rather than `main` for a
    known-working combination (see a release's notes for the full compatible tag list):

    ```bash
    git clone --branch v1.20.0 https://github.com/MrMarco74/yads.git
    git clone --branch v1.20.0 https://github.com/MrMarco74/yads-infra.git
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
| **v1.19.x** | ✅ Shipped | AI Risk Analysis, ZIP Export, Executive PDF with Cover Page |
| **v1.20.0** | ✅ Current | AI Intelligence Suite, Attack Path Visualizer, Finding Management, Portfolio View, Asset Tagging, Parallel Scans |
| **v1.21.x** | 🔄 Planned | ServiceNow Integration, Cortex XSOAR, Proxy Support (Zscaler) |
| **v2.0** | 💡 Vision | Mobile App, Advanced SOAR Playbooks, ML-based Anomaly Detection |

## License

MIT License. See [LICENSE](LICENSE) for details.
