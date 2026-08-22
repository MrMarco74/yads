# YADS (Yet Another Domain Scanner) — v1.28.1

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

## 🆕 What's New in v1.28.x

*   **Dormant Domain Detector** — New recon module flagging domains that are still registered/monitored but effectively abandoned: 8 weighted signals (no recent activity, no live web service, expiring/expired cert, stale DNS, missing Impressum, never archived by Wayback, no analytics infrastructure, and an optional SearXNG "not indexed" check). New `/dormant-domains` report with WHOIS context and Excel/PDF export.
*   **Catch-All Page Detector** — New recon module identifying parked-domain sales pages, default web-server splash pages, and wildcard vhosts serving generic content — signature match → vhost/content comparison → optional LLM classification fallback for the inconclusive minority.
*   **Bulk Scan by Criteria** — New `/targets/bulk-scan` page: pick scan types once and a target-selection criterion (all / root-domains-only / online-only / last-scanned-before-date, combinable) — resolved server-side to a target list, so scanning thousands of domains no longer means rendering a giant table first.
*   **SearXNG Integration** — Optional self-hosted metasearch integration (`/integrations`) used by recon modules for search-engine-indexing signals; degrades gracefully when not configured.
*   **LLM Settings UX** — Test Connection button and a real model-picker (fetches the live model list from Ollama or any OpenAI-compatible endpoint) in Tenant Settings, instead of typing a model name blind.
*   **Impressum Detection** — Split out of the combined GDPR privacy-policy check into its own signal (German TMG/DDG legal-notice requirement is a separate legal basis from the GDPR privacy notice).
*   **Performance** — Batched the N+1 `ScanResult` query and cached `tldextract` lookups on `/targets/table`, cutting load time dramatically for tenants with thousands of targets.
*   **Security Hardening** — Closed a gap where a category "select all" or Full Scan could sweep in the subdomain wordlist brute-force or the catch-all detector's LLM cost without an explicit, individual opt-in (both `/targets/table` and the per-target scan dialog); hardened the new LLM/SearXNG test endpoints against SSRF and against leaking exception detail or credentials in URLs.
*   **Bug Fixes** — Fixed the worker container silently missing its encryption key (BYOK secrets were decrypting to garbage in scan-time code, not just failing loudly); fixed a startup-migration split-brain that could crash-loop a deploy on a new column; fixed a session-expiry redirect that could loop; fixed a `NameError` crash in the screenshot module's Playwright-unavailable path; suppressed log-flooding TLS warnings globally.
*   **v1.28.1 patch** — Fixed target deletion (single, bulk, and tenant delete) 500ing with a `ForeignKeyViolation` whenever a target had a `baseline_snapshot` row; the three cascade-delete code paths had drifted out of sync on which child tables to clean up first.

See the [full release notes](https://github.com/MrMarco74/yads/releases/tag/v1.28.1) for the complete list of changes.

## 🚀 Quick Start & Installation

1.  **Deployment**:
    The infrastructure configuration lives in the **[yads-infra](https://github.com/MrMarco74/yads-infra)** repository, which builds against a sibling `yads` checkout (no prebuilt images or registry needed).

    YADS is split across several repos that need to move together — clone the matching
    [release tag](https://github.com/MrMarco74/yads/releases) rather than `main` for a
    known-working combination (see a release's notes for the full compatible tag list):

    ```bash
    git clone --branch v1.28.1 https://github.com/MrMarco74/yads.git
    git clone --branch v1.28.1 https://github.com/MrMarco74/yads-infra.git
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
| **v1.27.0 – v1.27.1** | ✅ Shipped | Recon correlation, MITRE ATT&CK mapping, NIS2/DORA compliance suite, finding triage, MTTR tracking, security hardening pass, Extension Hub fixes |
| **v1.28.0** | ✅ Shipped | Dormant Domain Detector, Catch-All Page Detector, Bulk Scan by Criteria, SearXNG integration, LLM settings UX, performance and security hardening |
| **v1.28.1** | ✅ Current | Patch release: fixed target-deletion 500 (missing `baseline_snapshot` in cascade-delete) |
| **v2.0** | 💡 Vision | Mobile App, Advanced SOAR Playbooks, ML-based Anomaly Detection |

## License

MIT License. See [LICENSE](LICENSE) for details.
