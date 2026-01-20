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

*Copyright © 2026 YADS Security Project*
