# YADS: Yet Another Domain Scanner
## Next-Gen Attack Surface Management Platform

> **Sichern Sie Ihre digitale Infrastruktur mit automatisiere Aufklärung, tiefgehender Vulnerability-Analyse und visueller Intelligenz.**

![YADS Dashboard Übersicht](/home/mrmarco/Documents/gitlab/yads/product_screenshots/dashboard_hero.png)

---

### 🚀 Warum YADS?

YADS ist eine All-in-One-Sicherheitsplattform für moderne DevSecOps-Teams, Penetrationstester und MSSPs. Es automatisiert den mühsamen Prozess der Aufklärung (Reconnaissance) und liefert handlungsrelevante Erkenntnisse in Echtzeit.

| **Umfassend** | **Automatisiert** | **Mandantenfähig** |
| :--- | :--- | :--- |
| Von DNS-Enumeration bis zu Web-App-Vulns – alles in einem Tool. | Planen Sie Scans täglich oder wöchentlich. "Set and Forget". | Verwalten Sie mehrere Kunden oder Teams in isolierten Umgebungen. |

---

### ✨ Hauptfunktionen

#### 1. Asset Discovery & Inventory
Verlieren Sie nie wieder den Überblick über Ihre externe Angriffsfläche.
*   **Subdomain Enumeration**: Findet versteckte und vergessene Subdomains (z.B. `dev.company.com`).
*   **Technology Fingerprinting**: Erkennt automatisch CMS, Webserver und Frameworks (Tech Radar).
*   **Cloud Infrastructure**: Identifiziert Hosting-Provider und Geo-Locations.

![Asset Inventory](/home/mrmarco/Documents/gitlab/yads/product_screenshots/assets_list.png)

#### 2. Deep Vulnerability Scanning
Integriert branchenführende Scanner für maximale Abdeckung.
*   **Nuclei Integration**: Scannt nach über 5000+ bekannten CVEs und Fehlkonfigurationen.
*   **Stealth Port Scanning**: Erkennt offene Ports, ohne IDS/IPS auszulösen.
*   **JavaScript SAST**: Analysiert Client-Side JS auf DOM XSS und sensitive API-Keys.

#### 3. Visuelle Intelligenz & Network Graph
Daten sind nutzlos, wenn man sie nicht versteht. YADS macht Zusammenhänge sichtbar.
*   **Interaktiver Netzwerk-Graph**: Visualisiert Verbindungen zwischen Domains, IPs und ASNs.
*   **Attack Path Visualization**: Hebt riskante Pfade und Kompromittierungsketten hervor.
*   **OSINT Brand Monitoring**: Findet unautorisierte Nutzung Ihrer Logos im Web (Phishing-Erkennung).

![Network Graph Visualization](/home/mrmarco/Documents/gitlab/yads/product_screenshots/network_graph.png)

#### 4. Compliance & Reporting
Verwandeln Sie technische Daten in Management-taugliche Berichte.
*   **SOC2 Readiness Score**: Echtzeit-Bewertung Ihrer Compliance (0-100%).
*   **Security Grading**: Automatische Benotung (A-F) für jedes Asset.
*   **PDF Exports**: Erstellen Sie professionelle Executive Reports auf Knopfdruck.

![Compliance Dashboard](/home/mrmarco/Documents/gitlab/yads/product_screenshots/compliance_report.png)

#### 5. Automatisierung & Integration
*   **Scan Scheduler**: Automatisieren Sie wiederkehrende Audits.
*   **Webhook Benachrichtigungen**: Senden Sie Alerts direkt an Slack, Teams oder Tines.
*   **API-First Design**: Integrieren Sie YADS nahtlos in Ihre CI/CD-Pipelines.

---

### 🛡️ Technische Highlights

*   **Docker-Native**: Einfaches Deployment mit `docker-compose`.
*   **Rollenspezifischer Zugriff (RBAC)**: Granulare Rechtevergabe für Admins, Scanner und Viewer.
*   **High Performance**: Parallele Verarbeitung mit Celery und Redis.

> **"YADS hat unsere Recon-Zeit von Tagen auf Minuten reduziert."**

---

### 💻 Starten Sie jetzt

Bereit, Ihre Angriffsfläche zu sichern?

[Dokumentation ansehen](./USER_GUIDE.md) | [Kontakt aufnehmen](mailto:sales@yads-security.com)

---

### 🆕 Neu in v1.18.5 — Security Hardening Release

> *Veröffentlicht: März 2026*

Diese Version konzentriert sich auf **Code-Qualität und Sicherheitshärtung** der gesamten Codebase.

#### 🔐 Sicherheitsfixes
*   **Deception Detection Modul** — Neues Scanner-Modul zur Erkennung von Honeypots, DNS-Sinkholes und Tarpits mit Konfidenz-Scoring (0–100)
*   **XSS-Schutz** — Jinja2 Template-Engine-Konfiguration in `markdown_report_generator.py` dokumentiert und abgesichert
*   **SSL-Zertifikat-Behandlung** — `verify=False`-Aufrufe in allen Scanner-Modulen mit Security-Kommentaren dokumentiert (intentionelles Verhalten für Security-Scanner)
*   **Subprocess-Härtung** — Alle externen Tool-Aufrufe (nmap, nuclei, docker) mit expliziten `# nosec`-Annotationen versehen

#### 🧹 Code Quality
*   **Deprecated API** — `datetime.utcnow()` wurde durch timezone-aware `datetime.now(timezone.utc)` ersetzt
*   **Duplicate Literals** — `'+00:00'` als `_UTC_SUFFIX`-Konstante zentralisiert
*   **Bare Except** — `except:` durch `except Exception:` ersetzt
*   **SQL False Positives** — Dokumentiert, dass `safe_table_name` in `backup.py` ein compile-time Constant ist

#### 🕵️ Neues Modul: Deception Detection
*   Erkennt **Honeypots** (Web, SSH, FTP, Telnet, SMTP) mit bekannten Signatur-Datenbanken
*   Erkennt **DNS Sinkholes** (Spamhaus, Microsoft DCU, FBI, Shadowserver)
*   Erkennt **Tarpits** mit Timing-Analyse (HTTP, SMTP, TCP)
*   **Confidence Scoring**: Jede Detektion mit 0–100% Konfidenz und Risk Level (low/medium/high/critical)
*   **Frontend-Integration**: Vollständige Darstellung im Target-Detail-View

---

### 🗺️ Roadmap

| Version | Status | Highlights |
|---------|--------|------------|
| **v1.18.5** | ✅ Aktuell | Deception Detection, Security Hardening, Code Quality |
| **v1.19.x** | 🔄 In Entwicklung | Wayback Machine Integration, Visual Regression Monitor |
| **v1.20.x** | 📋 Geplant | AI-Powered Executive Reporting (Ollama/OpenAI), Cloud Asset Enumeration (S3/GCS/Azure) |
| **v2.0** | 💡 Vision | Credential & Leak Monitoring (HIBP), Attack Path Visualization, JIRA/Ticket Integration |

*Copyright © 2026 YADS Security Project — v1.18.5*
