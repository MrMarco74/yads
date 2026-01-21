# YADS (Yet Another Domain Scanner)

YADS is a powerful, automated domain intelligence and security scanner. It aggregates data from multiple sources to provide a comprehensive view of a target domain's attack surface.

## 📚 Documentation
> **[📖 Read the User Guide](USER_GUIDE.md)** for detailed usage instructions and feature explanations.

## ✨ Key Features

*   **Web Analysis**: Headless browser scans with screenshot capture, tech stack detection, and OSINT extraction (Emails, Socials, Documents).
*   **Infrastructure Scanning**: Cloud provider detection, S3 bucket enumeration, and IP reputation checks.
*   **DNS & Subdomains**: Deep DNS analysis (Dangling CNAMEs) and subdomain enumeration via Certificate Transparency.
*   **Typosquatting**: Detection of malicious look-alike domains targeting your brand.
*   **SSL Security**: Certificate validity and cipher strength auditing.
*   **Reporting**: Export full audit reports as PDF.
*   **Disaster Recovery**: Built-in Backup & Restore functionality.

## 🚀 Quick Start & Installation

1.  **Deployment**:
    Use the provided `docker-compose.yml` to start the stack.

    ```bash
    docker-compose up -d
    ```

2.  **Initial Setup Wizard**:
    Open `http://<your-server-ip>:8000`. You will be automatically redirected to the **Setup Wizard**.
    Follow the 4-step process:

    *   **License**: Enter your YADS license key.
    *   **Database**: Set a secure password for the database.
    *   **Initialization**: Choose "Upgrade" (keep data) or "Factory Reset" (purge data).
    *   **Admin**: Create your first System Admin account.

3.  **Manual Development Setup**:
    If running from source without Docker:

    ```bash
    pip install -r requirements.txt
    playwright install chromium
    uvicorn yads.api.main:app --reload
    # Note: You may need to manually trigger setup flows or set SETUP_COMPLETE=true in .env
    ```

## License

Proprietary / Internal Tool.
