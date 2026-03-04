# YADS — Vibe-Coding Backlog

## 🚀 New Features (Proposals)

### 1. AI-Powered Executive Reporting 🧠
- Integrate Local LLM (Ollama) oder OpenAI API
- "Generate Management Report" → One-click PDF-Summary: Lagebild, kritische Findings, Empfehlungen
- "Explain this Vulnerability" → Button neben CVE für Human-Readable Erklärung + Remediation Steps

### 2. Visual Regression / Defacement Monitor 👁️
- Store "Baseline" Screenshots pro Target
- Nach jedem Scan: Pixel-Diff gegen Baseline
- Alert bei > X% visueller Abweichung
- Nützlich für: Defacement, Broken Deployments

### 3. Cloud Asset Enumeration ☁️
- Domain-Permutationen testen gegen AWS S3, Google Cloud Storage, Azure Blobs
  - `company-backup`, `company-dev`, `company-assets`, etc.
- Offene Buckets automatisch auflisten

### 4. Credential & Leak Monitoring 🕵️
- **HIBP Integration**: Alle gefundenen E-Mails (via OSINT) gegen "Have I Been Pwned" checken
- **GitLeaks**: Public GitHub Repos auf `domain + password/api_key/secret` scannen

### 5. Attack Path Visualization 🕸️
- Im bestehenden Network Graph: Risiko-Ketten highlighten
- Beispiel: `Subdomain A (Low Security)` → `Shared IP` → `Main DB (High Security)`
- "Wenn ich A kompromittiere — bin ich auf demselben Server wie B?"

### 6. JIRA / Ticket Integration 🎫
- "Create Ticket" Button direkt auf einem Finding
- Bi-direktionaler Sync: JIRA Ticket "Closed" → YADS triggert automatisch Rescan zur Verifikation

---

## 🧹 Tech Debt / Polishing

### Code Cleanup
- `web_analyzer.py` — `_detect_technologies()` weiter modularisieren (Complexity: 34, noch nicht vollständig aufgebrochen)
- Duplicate Literals zentralisieren:
  - `"Index of /"` (4x in `web_analyzer.py`)
  - `"yads.modules.dns"` (6x in `dns_scanner.py`)

### Security
- `B501` — 13x `requests` mit `verify=False` → dokumentieren oder in konfigurierbarer Option kapseln
- `B701` — Jinja2 mit `autoescape=False` prüfen (potenzieller XSS-Vektor)
- `B108` — 3x unsichere Temp-Files → auf `tempfile.NamedTemporaryFile` umstellen

---

## 💡 Empfehlung für den nächsten Start

**Einfachster Einstieg:** Wayback Machine Integration (Low Effort, interessante OSINT-Daten)
**Meiste visuelle Impact:** Visual Regression / Defacement Monitor
**Meiste Security-Relevanz:** AI Executive Reporting oder Cloud Asset Enumeration
