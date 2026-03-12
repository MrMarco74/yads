# YADS Scanner Module — Technische Dokumentation

> Letzte Aktualisierung: 2026-03-12
> Basis: YADS v1.14.x

---

## Übersicht

YADS verfügt über 24 Scanner-Module. Sie sind in **passive** (kein aktives Probing, kein Blocking-Risiko) und **aktive** (direkte Interaktion mit dem Ziel, IDS/WAF-Risiko) unterteilt.

| Eigenschaft | Passiv | Aktiv |
|---|---|---|
| Anzahl | 16 | 8 |
| Blocking-Risiko | Niedrig | Mittel–Hoch |
| Typische Quellen | DNS, öffentliche APIs, HTTP-Header lesen | Port-Scans, Fuzzing, Browser-Automation |

Alle Module erben von `BaseScannerModule` (`yads/core/base.py`) und nutzen:
- **Change Detection** via SHA256-Hash des Ergebnis-JSON — nur bei Änderungen wird ein neuer `ScanResult` gespeichert
- **Null-Byte-Sanitization** vor PostgreSQL JSONB-Writes
- **Rate Limiter** (`yads/core/rate_limiter.py`) — globaler Bandbreitenbegrenzer pro Target

---

## Schnellübersicht

| # | Modul | Label | Passiv | Risiko | Externe APIs |
|---|---|---|---|---|---|
| 1 | `dns_scanner` | DNS Records | ✅ | Mittel | crt.sh, Hackertarget |
| 2 | `subdomain_scanner` | Subdomain Discovery | ✅ | Mittel | crt.sh, Hackertarget |
| 3 | `web_analyzer` | Web Analyzer | ✅* | Mittel–Hoch | — |
| 4 | `ssl_scanner` | SSL/TLS Analysis | ✅ | Niedrig | — |
| 5 | `nuclei_scanner` | Nuclei Vulnerability Scan | ❌ | Hoch | Nuclei Pro (optional) |
| 6 | `visual_osint` | Visual OSINT | ✅* | Mittel | Google, Clearbit |
| 7 | `typosquat_scanner` | Typosquat Detection | ✅ | Mittel | — |
| 8 | `cloud_scanner` | Cloud Asset Discovery | ✅ | Mittel | — |
| 9 | `crawler` | Web Crawler | ❌ | Mittel–Hoch | — |
| 10 | `port_scanner` | Port Scanner | ❌ | Hoch | — |
| 11 | `nmap_scanner` | Nmap Stealth Scan | ❌ | Hoch | — |
| 12 | `threat_intel` | Threat Intelligence | ✅ | Niedrig | AbuseIPDB, OTX, VirusTotal |
| 13 | `subdomain_takeover` | Subdomain Takeover | ❌ | Mittel | — |
| 14 | `http_headers` | HTTP Security Headers | ✅ | Niedrig | — |
| 15 | `email_security` | Email Security (SPF/DKIM/DMARC) | ✅ | Niedrig | — |
| 16 | `content_discovery` | Content Discovery | ❌ | Mittel–Hoch | — |
| 17 | `axfr_scanner` | DNS Zone Transfer | ✅ | Niedrig | — |
| 18 | `tld_scanner` | TLD Variation Scan | ✅ | Mittel | — |
| 19 | `rpki_scanner` | RPKI/BGP Validation | ✅ | Niedrig | RIPE Stat, ipinfo.io |
| 20 | `cookie_scanner` | Cookie Security | ✅ | Niedrig | — |
| 21 | `csp_scanner` | CSP Analysis | ✅ | Niedrig | — |
| 22 | `security_txt` | security.txt (RFC 9116) | ✅ | Niedrig | — |
| 23 | `cert_mismatch` | Certificate Validation | ✅ | Niedrig | — |
| 24 | `cors_scanner` | CORS Misconfiguration | ❌ | Mittel–Hoch | — |
| 25 | `banner_grabber` | Service Banner Grabber | ❌ | Hoch | — |

> \* Startet headless Chromium — sichtbarer User-Agent, aber kein aktives Probing

---

## Modul-Referenz

---

### 1. `dns_scanner` — DNS Records

**Datei:** `yads/modules/dns_scanner.py`
**Passiv:** ✅ | **Risiko:** Mittel

**Zweck**
Liest alle relevanten DNS-Record-Typen aus, erkennt Wildcard-Konfigurationen, findet dangling CNAMEs und identifiziert Takeover-Risiken.

**Technische Methoden**
- DNS-Abfragen für A, AAAA, MX, TXT, SPF, DMARC, NS, CNAME, SRV, SOA (via `dnspython`)
- Wildcard-Erkennung durch Auflösung eines zufälligen Subdomains
- Dangling-CNAME-Erkennung + Takeover-Risikobewertung gegen bekannte Provider-Fingerprints
- Reverse-DNS PTR-Lookups

**Rückgabe**
```json
{
  "records": { "A": [...], "MX": [...], "TXT": [...] },
  "dangling_cnames": [...],
  "nameservers": [...],
  "wildcard_detected": false,
  "email_security": { "spf": {...}, "dmarc": {...} },
  "takeover_risks": [{ "provider": "...", "cname": "...", "status": "..." }]
}
```

**Besonderheiten**
- Unterstützt benutzerdefinierte DNS-Server via `SystemConfig.CUSTOM_DNS_SERVERS`
- Timeout: 3s pro Lookup

**Konfiguration**
| Einstellung | Ort | Default |
|---|---|---|
| `CUSTOM_DNS_SERVERS` | SystemConfig | System-DNS |

---

### 2. `subdomain_scanner` — Subdomain Discovery

**Datei:** `yads/modules/dns_scanner.py` (gleiche Datei wie dns_scanner)
**Passiv:** ✅ | **Risiko:** Mittel

**Zweck**
Enumeriert Subdomains über Certificate Transparency Logs, Hackertarget, CT-Org-Cross-Queries und parallele DNS-Verifikation.

**Technische Methoden**
- crt.sh: PostgreSQL-API direkt oder HTTP-Fallback
- Hackertarget-API als sekundäre Quelle
- CT-Org-Cross-Query: Findet verwandte Apex-Domains über die Org-Angabe im Zertifikat
- Parallele Subdomain-Verifikation (10 Worker, A-Record-Auflösung)

**Rückgabe**
```json
{
  "subdomains": [{ "subdomain": "...", "ips": [...], "alive": true }],
  "ct_related_domains": [...],
  "reverse_dns": {}
}
```

**Besonderheiten**
- Wenn `SystemConfig.AUTO_QUEUE_SUBDOMAINS = true`: neu entdeckte Subdomains werden automatisch als Targets angelegt und mit `dns_scanner` gescannt
- Fallback crt.sh → Hackertarget bei Rate-Limit oder Timeout

---

### 3. `web_analyzer` — Web Analyzer

**Datei:** `yads/modules/web_analyzer.py`
**Passiv:** ✅* | **Risiko:** Mittel–Hoch

**Zweck**
Zweistufige Web-Analyse: Schnelle Header-Erkennung + tiefe Playwright-basierte Analyse für Tech-Stack, Secrets, APIs und visuelle Identität.

**Technische Methoden**
- Stage 1: HTTP/HTTPS Connectivity-Check via `requests`
- Stage 2: Playwright Headless Chromium (Chromium, 1280×800)
- Tech-Stack-Fingerprinting: 140+ Signaturen (CMS, JS-Frameworks, Server, Analytics)
- Secret-Scanning: AWS Keys, Stripe, Google API, Slack Tokens, Private Keys via Regex
- API-Endpoint-Erkennung: Swagger/OpenAPI, GraphQL, REST-Versionen
- JS-Dateianalyse: Dangerous Sinks, Routes
- Login-Page-Erkennung (Password-Inputs, Title-Keywords)
- CVE-Lookup wenn Versionen erkannt

**Rückgabe**
```json
{
  "status_code": 200,
  "redirect_chain": [...],
  "tech_stack": [...],
  "title": "...",
  "emails": [...],
  "phones": [...],
  "socials": {...},
  "secrets": [...],
  "api_endpoints": [...],
  "cves": [...],
  "is_login_page": false,
  "screenshot_path": "..."
}
```

**Besonderheiten**
- HTTPS → HTTP Fallback bei Verbindungsfehler
- Load-Timeout: 30s (Playwright)
- Null-Byte-Sanitization vor DB-Write
- User-Agent ist Standard-Chromium — sichtbar in Access-Logs des Ziels

---

### 4. `ssl_scanner` — SSL/TLS Certificate Analysis

**Datei:** `yads/modules/ssl_scanner.py`
**Passiv:** ✅ | **Risiko:** Niedrig

**Zweck**
Extrahiert TLS-Zertifikatsdetails, enumeriert Cipher Suites via Nmap und bewertet Post-Quantum-Kryptographie-Readiness.

**Technische Methoden**
- SSL-Context-Verbindung (Python `ssl`-Modul, Port 443)
- Zertifikats-Extraktion: Subject, Issuer, SANs, Ablauf, Serial
- Nmap-basierte Cipher-Enumeration (`ssl-enum-ciphers` Script, XML-Parsing)
- Python-Fallback bei fehlendem Nmap
- PQC-Erkennung: ML-KEM, Kyber-Varianten, Hybrid-Groups
- HSTS-, TLS-Version-, Forbidden-Cipher-Checks

**Rückgabe**
```json
{
  "subject": {...},
  "issuer": {...},
  "notAfter": "...",
  "subjectAltName": [...],
  "ciphers": [{ "name": "...", "version": "...", "bits": 256, "kex_group": "..." }],
  "pqc_readiness": { "status": "...", "score": 65, "hybrid_groups_detected": [...] }
}
```

**Besonderheiten**
- PQC-Score: 100 (PQC aktiv), 65 (TLS 1.3 fähig), 15 (nur TLS 1.2)
- Org/Email aus Zertifikat wird für CT-Cross-Query extrahiert
- Fallback: `CERT_OPTIONAL` → `CERT_NONE` bei Chain-Validierungsfehler

**Abhängigkeiten**
- `nmap` (optional, für Cipher-Enumeration)

---

### 5. `nuclei_scanner` — Nuclei Vulnerability Scan

**Datei:** `yads/modules/nuclei_scanner.py`
**Passiv:** ❌ | **Risiko:** Hoch

**Zweck**
Führt template-basiertes aktives Vulnerability-Scanning via ProjectDiscovery Nuclei durch.

**Technische Methoden**
- Subprocess: `nuclei -u <url> -json -silent`
- JSON-Output-Parsing (ein Objekt pro Zeile)
- Schweregrad-Kategorisierung: critical, high, medium, low, info
- Finding-Deduplizierung nach Template-ID

**Rückgabe**
```json
{
  "findings": [{
    "template_id": "...",
    "name": "...",
    "severity": "high",
    "type": "...",
    "matched_at": "...",
    "curl_command": "..."
  }],
  "stats": { "critical": 0, "high": 2, "medium": 5, "low": 3, "info": 10 },
  "version": "3.3.4"
}
```

**Besonderheiten**
- ⚠️ Timeout: 20 Minuten pro Scan
- ⚠️ Aktives Probing — kann IDS/WAF auslösen und Rate-Limiting beim Ziel provozieren
- Nuclei-Binary muss im PATH vorhanden sein
- Tenant-spezifischer Nuclei Pro API-Key (`tenant.nuclei_api_key`)

**Konfiguration**
| Einstellung | Ort | Default |
|---|---|---|
| `nuclei_api_key` | Tenant-Settings | — |

---

### 6. `visual_osint` — Visual OSINT

**Datei:** `yads/modules/visual_osint.py`
**Passiv:** ✅* | **Risiko:** Mittel

**Zweck**
Screenshot-Erfassung, visuelle Änderungserkennung via dHash-Vergleich, Favicon-Hash-Berechnung für Shodan-Pivots.

**Technische Methoden**
- Playwright Headless Chromium (1280×800 Viewport)
- Full-Page-Screenshot
- dHash (Difference Hash) Bildvergleich für Defacement-Erkennung
- Favicon MurmurHash3 (Shodan-Algorithmus: base64 + mmh3)
- Logo/Favicon-Lookup via Google und Clearbit

**Rückgabe**
```json
{
  "screenshot_path": "...",
  "baseline_path": "...",
  "diff_score": 3,
  "is_defaced": false,
  "favicon_hash": "-12345678",
  "logos": {...},
  "status": "captured"
}
```

**Besonderheiten**
- Defacement-Schwellwert: dHash > 15 = defaced
- Favicon-Hash kompatibel mit Shodan `http.favicon.hash:`
- HTTP-Fallback bei HTTPS-Fehler
- Screenshots werden auf Disk gespeichert (`settings.STATIC_DIR/screenshots/`)

**Abhängigkeiten**
- Playwright + Chromium, Pillow, imagehash, mmh3

---

### 7. `typosquat_scanner` — Typosquatting Detection

**Datei:** `yads/modules/typosquat_scanner.py`
**Passiv:** ✅ | **Risiko:** Mittel

**Zweck**
Generiert und prüft Typosquatting-Variationen der Domain auf DNS-Aktivität.

**Technische Methoden**
- 5 Variation-Strategien: Omission (Zeichen weglassen), Repetition (Zeichen doppeln), Transposition (Zeichen tauschen), Replacement (ähnliche Zeichen), TLD-Swap
- Parallele A-Record-Auflösung (10 Worker, 1s Timeout)
- Shared Resolver für Effizienz

**Rückgabe**
```json
{
  "scanned_count": 484,
  "total_variations": 484,
  "found": [{ "domain": "exmaple.com", "ips": ["1.2.3.4"], "type": "transposition" }]
}
```

**Besonderheiten**
- Generiert ~484 Variationen pro typischer Domain
- Geprüfte TLDs: com, net, org, info, io, co, de
- ~50ms pro Lookup, Gesamt ca. 5–30s je nach Registrierungsgrad

---

### 8. `cloud_scanner` — Cloud Asset Discovery

**Datei:** `yads/modules/cloud_scanner.py`
**Passiv:** ✅ | **Risiko:** Mittel

**Zweck**
Enumeriert Cloud-Storage-Buckets (AWS S3, GCS, Azure, DigitalOcean, Cloudflare R2) und PaaS-Dienste (GitHub Pages, Netlify, Vercel, Heroku, Firebase etc.).

**Technische Methoden**
- HTTP HEAD/GET zu provider-spezifischen Bucket-URLs
- Status-Code-Klassifikation: 200=public, 403=vorhanden/geschützt, 404=nicht vorhanden
- 80 keyword-basierte Bucket-Name-Kandidaten
- PaaS-Provider-Template-Matching (9 Provider)
- Soft-404-Filterung (Default-Page-Erkennung)

**Rückgabe**
```json
{
  "assets": [{ "provider": "aws-s3", "bucket_name": "...", "url": "...", "status": "open", "severity": "high" }],
  "summary": { "total_assets_found": 2, "open_buckets": 1, "shadow_it_detected": true }
}
```

**Besonderheiten**
- Offene Buckets: Schweregrad `high`
- Vorhandene aber geschützte Buckets: `info`
- Shadow-IT: aktive Netlify/Heroku-Sites = `low`
- Timeout: 3s pro Request

---

### 9. `crawler` — Web Crawler

**Datei:** `yads/modules/crawler.py`
**Passiv:** ❌ | **Risiko:** Mittel–Hoch

**Zweck**
Crawlt die Website-Struktur, kartiert Links, identifiziert externe Abhängigkeiten und Dead-Ends.

**Technische Methoden**
- BFS-Queue-basiertes Crawling (Deque)
- Playwright für Screenshots (bis zu 10 Seiten)
- HTTP-Traffic-Logging
- URL-Normalisierung und Deduplizierung
- Redis-basiertes globales Visit-Tracking (24h TTL)
- Link-Extraktion via Regex

**Rückgabe**
```json
{
  "stats": { "pages_crawled": 47, "depth_reached": 3, "total_links": 312 },
  "dead_ends": [...],
  "collectors": [{ "domain": "cdn.example.com", "count": 12 }],
  "nodes": [{ "id": "...", "status": 200, "screenshot": "..." }],
  "http_traffic": [...]
}
```

**Besonderheiten**
- Max. Tiefe: 3
- Max. Seiten: 100
- Crawl-Delay: 0.5s (konfigurierbar)
- ⚠️ Generiert messbar erhöhten Traffic beim Ziel

**Konfiguration**
| Einstellung | Ort | Default |
|---|---|---|
| `WEB_RATE_LIMIT_DELAY` | SystemConfig | 0.5s |
| `WEB_REQUEST_TIMEOUT` | SystemConfig | 10s |

---

### 10. `port_scanner` — Port Scanner

**Datei:** `yads/modules/port_scanner.py`
**Passiv:** ❌ | **Risiko:** Hoch

**Zweck**
Socket-basierter TCP-Connect-Scan der 17 häufigsten Ports mit HTTP-Probe und Banner-Grabbing.

**Technische Methoden**
- TCP Socket Connect (17 Ports: 21, 22, 23, 25, 53, 80, 443, 3306, 5432, 6379, 8000, 8008, 8080, 8443, 8888, 9200, 27017)
- 1.5s Timeout pro Port
- HTTP/HTTPS Server-Header-Extraktion
- FTP/SSH/SMTP Banner-Grab (1024 Bytes)

**Rückgabe**
```json
{
  "open_ports": [{ "port": 443, "service": "https", "banner": "nginx/1.24", "http_status": 200 }],
  "is_active": true,
  "scanned_ports": 17
}
```

**Besonderheiten**
- ⚠️ Port-Scanning kann IDS/WAF-Alerts auslösen
- Quick-Mode (`quick_web_probe`): Nur Ports 80/443, HEAD-Request

---

### 11. `nmap_scanner` — Nmap Stealth Scan

**Datei:** `yads/modules/nmap_scanner.py`
**Passiv:** ❌ | **Risiko:** Hoch

**Zweck**
Nmap-basierter Scan der Top 1000 Ports mit optionalem SYN-Stealth-Modus bei Root-Rechten.

**Technische Methoden**
- Subprocess: `nmap -sS -T2 -D RND:5 --top-ports 1000 -oX -` (bei Root)
- Fallback auf TCP Connect (`-sT`) ohne Root
- XML-Output-Parsing (defusedxml)
- Timing T2 (Polite), 200ms Scan-Delay
- Automatische Privilege-Erkennung (`os.geteuid()`)

**Rückgabe**
```json
{
  "open_ports": [{ "port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH 8.9" }],
  "method": "syn_stealth",
  "is_active": true
}
```

**Besonderheiten**
- ⚠️ SYN-Scan: niedrig auffällig aber trotzdem erkennbar
- Decoys (`-D RND:5`): erschwert Quellerkennung
- Timeout: 5 Minuten
- Locale-Erzwingung: `LC_ALL=C`

**Abhängigkeiten**
- `nmap` Binary

---

### 12. `threat_intel` — Threat Intelligence

**Datei:** `yads/modules/threat_intel_scanner.py`
**Passiv:** ✅ | **Risiko:** Niedrig

**Zweck**
Multi-Source-Reputationsabfrage bei AbuseIPDB, OTX AlienVault und VirusTotal.

**Technische Methoden**
- IP-Auflösung via `socket`
- AbuseIPDB `/api/v2/check`: Confidence-Score, Report-Anzahl, Kategorien
- OTX AlienVault `/indicators/domain|IPv4/general`: Pulses, Malware-Familien
- VirusTotal `/domains/{domain}`: Detection-Stats, Reputation, Kategorien
- Rate-Limiting-Enforcement (10s Timeout)

**Rückgabe**
```json
{
  "abuseipdb": { "abuse_confidence_score": 0, "total_reports": 0 },
  "otx": { "pulse_count": 0, "pulses": [] },
  "virustotal": { "malicious": 0, "suspicious": 0, "reputation": 0 },
  "findings": [...],
  "summary": { "score": 100, "threat_level": "none", "sources_checked": 3 }
}
```

**Besonderheiten**
- Graceful Degradation bei fehlendem API-Key
- Threat-Level-Schwellwerte: AbuseIPDB > 75%, VirusTotal > 5 malicious, OTX > 10 Pulses = `critical`
- Scoring: 100 = clean, 0 = hochriskant

**Konfiguration**
| Einstellung | Ort |
|---|---|
| `ABUSEIPDB_API_KEY` | Umgebungsvariable |
| `OTX_API_KEY` | Umgebungsvariable |
| `virustotal_api_key` | Tenant-Settings |

---

### 13. `subdomain_takeover` — Subdomain Takeover Detection

**Datei:** `yads/modules/subdomain_takeover_scanner.py`
**Passiv:** ❌ | **Risiko:** Mittel

**Zweck**
Erkennt dangling CNAME/NS-Records auf nicht beanspruchte Drittanbieter-Dienste (GitHub Pages, Heroku, Azure, Shopify u.a.).

**Technische Methoden**
- CNAME-Lookup via DNS
- Pattern-Matching gegen 35 bekannte verwundbare Dienste
- HTTP Response Fingerprinting (Body-Keyword-Matching)
- Prüfung ob CNAME-Ziel auflösbar ist
- Common-Subdomain-Kandidaten (www, mail, api, admin, dev, staging ...)
- DB-Lookup bekannter Subdomains wenn `target_id` vorhanden

**Rückgabe**
```json
{
  "subdomains_checked": 42,
  "vulnerable": [{ "subdomain": "...", "cname": "...", "service": "heroku", "severity": "high" }],
  "potentially_vulnerable": [...],
  "summary": { "vulnerable_count": 1, "score": 70 }
}
```

**Besonderheiten**
- 30+ Takeover-Signaturen
- Doppelte Prüfung: HTTP-Fingerprint + CNAME-Auflösbarkeit
- Scoring: -30 (critical), -20 (high), -10 (medium)
- Timeout: 8s pro HTTP-Request

---

### 14. `http_headers` — HTTP Security Headers

**Datei:** `yads/modules/http_headers_scanner.py`
**Passiv:** ✅ | **Risiko:** Niedrig

**Zweck**
Analysiert HTTP-Response-Header auf OWASP-Security-Best-Practices.

**Technische Methoden**
- HTTP/HTTPS GET-Request
- 8 Security-Header-Checks: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP`, `CORP`
- Leaky-Header-Erkennung: `Server`, `X-Powered-By`, `X-AspNet-Version` etc.
- HSTS-Validierung: Min. 6 Monate (15.552.000s), `includeSubDomains`

**Rückgabe**
```json
{
  "headers": { "strict-transport-security": "max-age=31536000" },
  "findings": [{ "header": "X-Frame-Options", "severity": "medium", "issue": "Missing" }],
  "leaky_headers": { "server": "nginx/1.24.0" },
  "score": 75
}
```

**Besonderheiten**
- Score: 80% Basis (vorhandene Header / 8), -10 pro High-Severity-Finding
- HTTPS → HTTP Fallback

---

### 15. `email_security` — Email Security (SPF/DKIM/DMARC)

**Datei:** `yads/modules/email_security_scanner.py`
**Passiv:** ✅ | **Risiko:** Niedrig

**Zweck**
Validiert E-Mail-Authentifizierungs-Records (SPF, DMARC, DKIM, MX, BIMI).

**Technische Methoden**
- DNS TXT/MX-Abfragen
- SPF: Policy-Qualifier (-all, ~all, +all), DNS-Lookup-Count (max. 8)
- DMARC: `_dmarc.{domain}`, Policy (p=), pct, rua
- DKIM: 13 gängige Selektoren (default, google, mail, k1–k2, selector1–2, mimecast, sendgrid ...)
- MX-Enumeration
- BIMI: `default._bimi.{domain}`

**Rückgabe**
```json
{
  "spf": { "present": true, "policy": "-all", "issues": [] },
  "dmarc": { "present": true, "policy": "reject", "pct": 100 },
  "dkim": { "selectors_found": ["google", "mail"], "count": 2 },
  "mx": { "present": true, "records": [...] },
  "score": 95
}
```

**Besonderheiten**
- Scoring: SPF 30 Punkte, DMARC 40 Punkte, DKIM 30 Punkte
- DMARC `p=none` gilt als unzureichend (Finding)
- SPF `+all` = kritisch (erlaubt alle Server)

---

### 16. `content_discovery` — Content Discovery

**Datei:** `yads/modules/content_discovery.py`
**Passiv:** ❌ | **Risiko:** Mittel–Hoch

**Zweck**
Fuzzt HTTP-Endpunkte auf bekannte sensitive Pfade und Verzeichnisse.

**Technische Methoden**
- Kuratierte Wordlist (50+ Pfade: `.env`, `.git/`, `admin/`, `swagger.json`, `robots.txt`, `backup.sql`, `phpinfo.php` ...)
- Parallele GET/HEAD-Requests (5 Worker)
- Status-Code-Filterung: 404 ignoriert, 200/403/401/30x gemeldet
- Rate Limiter per Target

**Rückgabe**
```json
{
  "found_assets": [{ "path": "/.git/HEAD", "url": "...", "status": 200, "length": 23 }]
}
```

**Besonderheiten**
- ⚠️ 50+ HTTP-Requests — kann WAF auslösen
- Kein Soft-404-Handling (minimale False-Positive-Filterung)
- Stream=True verhindert große Downloads

---

### 17. `axfr_scanner` — DNS Zone Transfer

**Datei:** `yads/modules/axfr_scanner.py`
**Passiv:** ✅ | **Risiko:** Niedrig

**Zweck**
Versucht DNS Zone Transfer (AXFR) gegen autoritative Nameserver — kritischer Fund wenn erfolgreich.

**Technische Methoden**
- NS-Record-Auflösung
- AXFR via `dns.query.xfr()`
- Zone-Parsing mit `dns.zone.from_xfr()`
- Bis zu 6 Nameserver, 5s Timeout

**Rückgabe**
```json
{
  "nameservers_checked": 2,
  "vulnerable": false,
  "transfer_results": [{ "nameserver": "ns1.example.com", "success": false, "reason": "REFUSED" }]
}
```

**Besonderheiten**
- Wird von korrekt konfigurierten Servern verweigert (REFUSED/FormError)
- Erfolgreicher AXFR = kritischer Fund mit vollständiger Zonenliste

---

### 18. `tld_scanner` — TLD Variation Scan

**Datei:** `yads/modules/tld_scanner.py`
**Passiv:** ✅ | **Risiko:** Mittel

**Zweck**
Prüft denselben SLD unter 24 verschiedenen TLDs auf Registrierungsstatus und potenzielle Phishing-Domains.

**Technische Methoden**
- tldextract für SLD/TLD-Parsing
- Parallele A-Record-Auflösung (30 Worker) über 24 TLDs
- HTTP HEAD für Server-Header
- IP-Vergleich mit Referenz-Domain (Same-Owner-Heuristik)

**Rückgabe**
```json
{
  "sld": "example",
  "scanned_count": 24,
  "registered_count_diff_owner": 3,
  "details": [{ "tld": "net", "domain": "example.net", "status": "registered", "same_owner": false }]
}
```

**Besonderheiten**
- 24 TLDs (nicht alle ~1500 IANA-TLDs — zu langsam)
- Timeout: 2s pro Lookup

---

### 19. `rpki_scanner` — RPKI/BGP Validation

**Datei:** `yads/modules/rpki_scanner.py`
**Passiv:** ✅ | **Risiko:** Niedrig

**Zweck**
Validiert Route Origin Authorizations (ROAs) für Domain-IPs — erkennt BGP-Hijacking-Risiken.

**Technische Methoden**
- IP-Auflösung via `socket.getaddrinfo`
- RIPE Stat API: network-info, as-overview, rpki-validation
- ipinfo.io Fallback für ASN/Org-Lookup
- ROA-State-Klassifikation: valid / invalid / not_found

**Rückgabe**
```json
{
  "routes": [{ "ip": "1.2.3.4", "asn": "AS1234", "rpki_state": "valid", "roas": [...] }],
  "summary": { "score": 100, "valid": 2, "invalid": 0, "not_found": 0 }
}
```

**Besonderheiten**
- Max. 3 IPs pro Domain
- Scoring: -25 (high/invalid), -8 (medium/not_found)
- `not_found` = ungeschützte Route (kein ROA vorhanden)

---

### 20. `cookie_scanner` — Cookie Security

**Datei:** `yads/modules/cookie_scanner.py`
**Passiv:** ✅ | **Risiko:** Niedrig

**Zweck**
Analysiert Set-Cookie-Header auf Security-Attribute (Secure, HttpOnly, SameSite, Prefixes).

**Technische Methoden**
- Set-Cookie Raw-Header-Parsing
- Session-Cookie-Heuristik: Regex auf Name (session, token, auth, jwt, csrf ...)
- Prefix-Validierung: `__Secure-` und `__Host-`
- SameSite-Wert-Check

**Rückgabe**
```json
{
  "cookies": [{ "name": "sessionid", "secure": true, "httponly": false, "samesite": "Lax", "is_session_cookie": true }],
  "summary": { "total": 3, "insecure": 1 },
  "score": 60
}
```

**Besonderheiten**
- `__Host-` erfordert: Secure + kein Domain-Attribut + `Path=/`
- `SameSite=None` erfordert Secure-Flag
- Session-Cookies bekommen höhere Schweregrade bei fehlenden Flags
- Scoring: -30 (kein Secure), -25 (kein HttpOnly), -20 (kein SameSite)

---

### 21. `csp_scanner` — CSP Analysis

**Datei:** `yads/modules/csp_scanner.py`
**Passiv:** ✅ | **Risiko:** Niedrig

**Zweck**
Extrahiert und analysiert Content-Security-Policy-Header — findet externe Domains, potenzielle Assets und Fehlkonfigurationen.

**Technische Methoden**
- HTTP/HTTPS Header-Fetch
- CSP-Parsing per Semikolon/Space (25 Source-Direktiven)
- Domain-Extraktion aus CSP
- Kategorisierung: CDN, Analytics, Social, Ads, Fonts, Payment, Support, Cloud, Monitoring
- Potenzielle-Asset-Heuristik (Domain-Namensüberschneidung, Corporate-Pattern)
- Security-Analyse: `unsafe-inline`, `unsafe-eval`, Wildcards, fehlende Direktiven

**Rückgabe**
```json
{
  "csp_header": "default-src 'self'...",
  "external_domains": ["cdn.example.com", "analytics.google.com"],
  "potential_assets": [{ "domain": "cdn.mycompany.com", "reason": "naming_pattern", "priority": "high" }],
  "third_party_services": { "analytics": ["google-analytics.com"] },
  "security_findings": [{ "issue": "unsafe-inline in script-src", "severity": "high" }]
}
```

---

### 22. `security_txt` — security.txt (RFC 9116)

**Datei:** `yads/modules/security_txt_scanner.py`
**Passiv:** ✅ | **Risiko:** Niedrig

**Zweck**
Validiert Vorhandensein und Korrektheit von `/.well-known/security.txt` gemäß RFC 9116.

**Technische Methoden**
- Prüft 2 Pfade: `/.well-known/security.txt` und `/security.txt`
- Pflichtfeld-Check: `Contact`
- Empfohlene Felder: `Expires`, `Encryption`, `Preferred-Languages`, `Policy`, `Acknowledgments`
- `Expires`-Validierung: ISO 8601, Freshness-Check (< 30 Tage = Warning)
- Contact-Format: `mailto:`, `https://`, `tel:`

**Rückgabe**
```json
{
  "found": true,
  "url": "/.well-known/security.txt",
  "fields": { "Contact": "mailto:security@example.com", "Expires": "2026-12-31T00:00:00Z" },
  "issues": [],
  "score": 90
}
```

**Besonderheiten**
- Basis-Score: 50, +8 pro empfohlenem Feld, -10 pro Issue
- Expires < 30 Tage = Warning (nicht Error)

---

### 23. `cert_mismatch` — Certificate Validation

**Datei:** `yads/modules/cert_mismatch_scanner.py`
**Passiv:** ✅ | **Risiko:** Niedrig

**Zweck**
Prüft TLS-Zertifikat auf Domain-Match (CN/SAN), Ablauf und Self-Signed-Status.

**Technische Methoden**
- SSL-Context-Verbindung (`CERT_REQUIRED`, Fallback `CERT_NONE`)
- `getpeercert()` Extraktion
- CN und SAN-Parsing
- Wildcard-SAN-Matching (`*.example.com`)
- Self-Signed-Erkennung: Issuer == Subject.Org

**Rückgabe**
```json
{
  "valid": true,
  "cert_info": { "subject_cn": "example.com", "expires": "2026-06-01", "days_until_expiry": 81 },
  "findings": []
}
```

**Besonderheiten**
- Ablauf-Schwellwerte: < 0 Tage = critical, < 14 = high, < 30 = medium
- Wildcard nur ein Level tief: `sub.example.com` ✅, `a.b.example.com` ❌

---

### 24. `cors_scanner` — CORS Misconfiguration

**Datei:** `yads/modules/cors_scanner.py`
**Passiv:** ❌ | **Risiko:** Mittel–Hoch

**Zweck**
Testet CORS-Policy durch gesendete Origin-Header und Inspektion der `Access-Control-Allow-Origin`-Antworten.

**Technische Methoden**
- OPTIONS-Requests mit manipuliertem `Origin`-Header
- Test-Cases: Beliebige Origin, Subdomain-Wildcard, Null-Origin, Suffix-Bypass
- ACAO-Reflection-Check
- `Access-Control-Allow-Credentials: true` Inspektion

**Rückgabe**
```json
{
  "tested_endpoints": [{ "origin_tested": "https://evil.com", "acao": "https://evil.com", "vulnerable": true }],
  "findings": [{ "severity": "high", "detail": "Arbitrary origin reflected with credentials" }],
  "score": 40
}
```

**Besonderheiten**
- ⚠️ Kann WAF/IDS auslösen
- Critical: `ACAO=*` + `Allow-Credentials=true` (technisch ungültig, trotzdem gemeldet)
- High: Null-Origin reflektiert + Credentials

---

### 25. `banner_grabber` — Service Banner Grabber

**Datei:** `yads/modules/banner_grabber.py`
**Passiv:** ❌ | **Risiko:** Hoch

**Zweck**
Greift Service-Banner von offenen Ports, identifiziert Software-Versionen, erkennt gefährliche/veraltete Dienste.

**Technische Methoden**
- Paralleles Banner-Grabbing (10 Worker, 3s Timeout) über 17 Default-Ports
- Port-spezifische Probes (HEAD für HTTP, PING für Redis etc.)
- SSL-Wrapping für Ports 443, 8443
- Versions-Pattern-Matching (20+ Regex: OpenSSH, FTP, MySQL, Nginx, Apache ...)
- Outdated-Version-Check: OpenSSH < 8.0, MySQL < 8.0
- Gefährliche Dienste: Telnet, VNC, RDP, unauthentifiziertes Redis/Elasticsearch/MongoDB

**Rückgabe**
```json
{
  "services": [{ "port": 22, "banner": "SSH-2.0-OpenSSH_7.9", "service": "ssh", "version": "7.9", "findings": [...] }],
  "summary": { "open_services": 3, "score": 65 }
}
```

**Besonderheiten**
- ⚠️ 10 parallele Verbindungen — sichtbar in Server-Logs
- Score-Abzüge: Telnet -20, VNC -15, RDP -10, Redis unauthentifiziert -30
- Version-Disclosure als `info`-Schweregrad
- Integriert Nmap-Ergebnisse wenn `target_id` vorhanden

---

## Systemkonfiguration

### SystemConfig-Keys (Datenbank)

| Key | Betrifft Module | Default |
|---|---|---|
| `CUSTOM_DNS_SERVERS` | dns_scanner, subdomain_scanner | System-DNS |
| `AUTO_QUEUE_SUBDOMAINS` | subdomain_scanner | `false` |
| `QUEUE_ACTIVE` | Alle (Worker-Level) | `true` |
| `GLOBAL_MAX_CONCURRENT_SCANS` | Scheduler | `5` |
| `WORKER_CONCURRENCY` | Worker | `4` |
| `WEB_REQUEST_TIMEOUT` | web_analyzer, crawler | 10s |
| `WEB_RATE_LIMIT_DELAY` | crawler | 0.5s |

### Tenant-Settings (API-Keys)

| Feld | Betrifft Module |
|---|---|
| `google_api_key` + `google_cse_cx` | brand_intelligence, email_intelligence |
| `nuclei_api_key` | nuclei_scanner |
| `hibp_api_key` | leaked_credentials |
| `shodan_api_key` | shodan_censys |
| `censys_api_key` | shodan_censys |
| `virustotal_api_key` | threat_intel |
| `hunter_api_key` | email_harvester |
| `github_token` | js_secrets |

### Umgebungsvariablen (Worker)

| Variable | Betrifft Module |
|---|---|
| `ABUSEIPDB_API_KEY` | threat_intel |
| `OTX_API_KEY` | threat_intel |
| `CHROME_BIN` | web_analyzer, visual_osint, crawler |

---

## Technische Besonderheiten (übergreifend)

### Change Detection
Alle Module nutzen SHA256-basierte Änderungserkennung via `BaseScannerModule.compute_hash()`. Ein neuer `ScanResult` wird nur gespeichert wenn sich der Hash des Ergebnis-JSON ändert. `ModuleState.last_result_hash` speichert den letzten Hash pro Target/Modul.

### Null-Byte-Sanitization
PostgreSQL JSONB unterstützt `\u0000` nicht. Module die HTTP-Inhalte verarbeiten (`web_analyzer`, `crawler`) rufen `sanitize_null_bytes()` (`yads/utils/sanitize.py`) vor dem DB-Write auf.

### Parallele Ausführung
Module werden im Worker in Gruppen ausgeführt:
- **Gruppe A** (Background): `dns_scanner`, `ssl_scanner`
- **Sequentiell**: `subdomain_scanner`, `web_analyzer`, `typosquat_scanner`, `visual_osint`
- **Parallele Gruppe**: alle übrigen passiven Module gleichzeitig

### Auto-Queue Subdomains
`subdomain_scanner` kann neu entdeckte Subdomains automatisch als Targets anlegen wenn `SystemConfig.AUTO_QUEUE_SUBDOMAINS = true`. Neu erstellte Targets erben die `tenant_id` des Eltern-Targets und werden mit `dns_scanner`-Only gescannt (kein Schneeballeffekt durch volle Scans).

> ⚠️ **Achtung:** Dieser Mechanismus kann bei großen Domains unkontrolliert viele Targets erzeugen. Für die Produktion empfohlen: `AUTO_QUEUE_SUBDOMAINS = false` und manuelle Steuerung.
