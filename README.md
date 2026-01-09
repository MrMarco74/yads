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

## 🚀 Quick Start
1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    playwright install chromium
    ```
2.  **Run the Server**:
    ```bash
    uvicorn yads.api.main:app --reload
    ```
3.  **Start the Worker (Celery)**:
    ```bash
    celery -A yads.worker worker --loglevel=info
    ```
4.  **Access Dashboard**: Open `http://localhost:8000`.

## License
Proprietary / Internal Tool.
