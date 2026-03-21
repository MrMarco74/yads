# YADS – Datenpunkte vs. DSGVO, DORA & NIS2

*Erstellt: 2026-03-21 | Aktualisiert: 2026-03-21 | Basis: yads-datenpunkte.md*

---

## 1. DSGVO-Abgleich

### 1.1 Rechtsgrundlagen (Art. 6 DSGVO)

| Datenkategorie | Rechtsgrundlage | Bewertung |
|---|---|---|
| Accountdaten (Name, E-Mail, Passwort-Hash) | Art. 6 Abs. 1 lit. b (Vertragserfüllung) | ✅ klar gedeckt |
| MFA / TOTP-Secret | Art. 6 Abs. 1 lit. b + lit. f (berechtigtes Interesse: Sicherheit) | ✅ gedeckt |
| Session-JWT | Art. 6 Abs. 1 lit. b | ✅ gedeckt |
| OIDC-Subject-ID | Art. 6 Abs. 1 lit. b | ✅ gedeckt |
| Audit-Events (Login, Passwort, Rollen) | Art. 6 Abs. 1 lit. c (rechtliche Verpflichtung) + lit. f | ✅ gedeckt — Logging ist Compliance-Pflicht |
| Scan-Ergebnisse (Domains, IPs, SSL, …) | Art. 6 Abs. 1 lit. b — betrifft primär technische Daten des Targets | ✅ kein Personenbezug wenn Target eine Firma ist |
| OSINT (E-Mails, Social-Handles, Credentials) | **Art. 6 Abs. 1 lit. f (berechtigtes Interesse)** — aber OSINT zu natürlichen Personen ist heikel | ⚠️ Abhängig von Tenant-Zweck; Auftragsverarbeiter-Regelung nötig |
| HTTP-Traffic-Logs (inkl. Auth-Header) | Art. 6 Abs. 1 lit. f | ⚠️ Können personenbezogene Daten enthalten (z. B. Auth-Token, Cookies) |
| API-Keys (BYOK: OpenAI, Shodan etc.) | Art. 6 Abs. 1 lit. b | ⚠️ Klartext-Speicherung kritisch (Sicherheitsrisiko, kein DSGVO-Problem per se) |
| Client-IP (Support-Portal, Kontaktformular) | Art. 6 Abs. 1 lit. f | ⚠️ IP = personenbezogenes Datum; Hinweis in Datenschutzerklärung erforderlich |
| Bug-Reports (Systeminfo der Installation) | Art. 6 Abs. 1 lit. b | ⚠️ Können Hostnamen, Benutzernamen, Pfade enthalten |
| Support-Nachrichten (Kundenkommunikation) | Art. 6 Abs. 1 lit. b | ✅ gedeckt |
| Aktivierungsanfragen (Instance-UUID) | Art. 6 Abs. 1 lit. b | ✅ kein Personenbezug |

### 1.2 Datensparsamkeit (Art. 5 Abs. 1 lit. c DSGVO)

| Punkt | Status | Lücke |
|---|---|---|
| HTTP-Traffic-Logs speichern vollständige Request-/Response-Header inkl. Auth-Header | ⚠️ Risiko | Keine automatische Bereinigung personenbezogener Header; unbegrenzte Speicherung |
| Scan-Ergebnisse (Screenshots, E-Mails, Credentials) akkumulieren unbegrenzt | ❌ Lücke | Keine Retention-Policy; widerspricht Datensparsamkeit |
| Client-IP bei Kontaktformular | ⚠️ Risiko | Notwendigkeit der IP-Speicherung nicht dokumentiert |
| Bug-Reports im Klartext mit vollständigen Systeminfos | ⚠️ Risiko | Können Hostnamen, User-IDs enthalten; TTL fehlt |
| OSINT-Daten zu Personen (E-Mails, Social-Handles) | ⚠️ Risiko | Zweckbindung und Löschfristen unklar |

### 1.3 Speicherbegrenzung / Löschfristen (Art. 5 Abs. 1 lit. e DSGVO)

| Daten | Aktuelle Speicherdauer | DSGVO-Anforderung | Status |
|---|---|---|---|
| Scan-Ergebnisse | Unbegrenzt (DATA_RETENTION_DAYS ist konfigurierbar, aber kein Default) | Zweckgebunden, nach Ende löschen | ❌ Default fehlt |
| HTTP-Traffic-Logs | Unbegrenzt | Kurze Frist sinnvoll (z. B. 30 Tage) | ❌ Kein TTL |
| Audit-Events (SecurityAuditLog) | Unbegrenzt | DORA: mind. 5 Jahre; DSGVO: so kurz wie nötig | ⚠️ Konflikt DSGVO ↔ DORA (s. u.) |
| Bug-Reports im Support-Portal | Unbegrenzt | Nach Abschluss löschen oder anonymisieren | ❌ Kein Lifecycle |
| Session-JWTs | Konfigurierbar (Tenant-spezifisch) | ✅ korrekt |
| Client-IPs im Support-Portal | Unbegrenzt (zusammen mit Kontaktanfrage) | Max. 7 Tage (gängige Praxis) | ❌ TTL fehlt |

### 1.4 Technisch-organisatorische Maßnahmen (Art. 32 DSGVO)

| Maßnahme | Implementiert | Anmerkung |
|---|---|---|
| Passwort-Hashing (Bcrypt) | ✅ | |
| MFA (TOTP) | ✅ | Optional per Tenant |
| HTTPS / TLS in Transit | ✅ | Reverse Proxy |
| JWT in HttpOnly Cookies | ✅ | |
| CSRF-Schutz | ✅ | Double-Submit-Cookie-Pattern |
| RBAC (admin, tenant_admin, scanner, auditor) | ✅ | |
| Audit-Logging mit Hash-Chain (DORA EU) | ✅ | SecurityAuditLog mit SHA256-Chain |
| Verschlüsselung von Bug-Reports in Transit | ✅ | X25519 ECDH |
| **Verschlüsselung Bug-Reports at rest** | ❌ | Werden serverseitig entschlüsselt, Plaintext in DB |
| **Verschlüsselung API-Keys at rest** | ❌ | BYOK-Keys im Klartext in der DB |
| Datenbankbackup verschlüsselt | ✅ | Encrypted ZIP |
| Netzwerkisolation (Docker Swarm) | ✅ | |
| Security-Headers (HSTS, CSP, X-Frame) | ✅ | |
| Input-Validierung / SQL-Injection-Schutz | ✅ | SQLModel ORM (parameterisiert) |
| SSRF-Schutz für interne Netze | ⚠️ | Domain-Regex-Filter, aber kein explizites RFC-1918-Blocklist |

### 1.5 Auftragsverarbeitung (Art. 28 DSGVO)

| Externe Übertragung | Datenkategorie | AVV-Pflicht | Status |
|---|---|---|---|
| crt.sh, Wayback Machine | Domainnamen | ❌ (öffentliche Dienste, keine Personendaten) | ✅ kein AVV nötig |
| Google Custom Search | Domainnamen + OSINT-Queries | ⚠️ Könnte Personenbezug haben | ⚠️ AVV prüfen |
| HIBP (Have I Been Pwned) | E-Mails (OSINT) | ✅ HIBP hat AVV / API-Nutzungsbedingungen | ✅ prüfen ob ausreichend |
| Shodan / Censys | IPs, Domainnamen | ⚠️ IPs können personenbezogen sein | ⚠️ AVV prüfen |
| VirusTotal | Domains, IPs, Hashes | ⚠️ | ⚠️ AVV prüfen |
| OpenAI / Anthropic (KI-Analyse) | Finding-Texte (können Personendaten enthalten) | ✅ Pflicht | ❌ AVV mit OpenAI/Anthropic erforderlich; nur auf User-Trigger |
| Splunk HEC | Security-Events | ✅ Pflicht wenn on-premise Kundendaten | ⚠️ Tenant muss eigenen AVV haben |
| Slack / Teams / Jira (Webhooks) | Finding-Texte | ⚠️ | ⚠️ Tenant-Verantwortung; Hinweis in Doku nötig |

---

## 2. DORA-Abgleich

*Digital Operational Resilience Act (EU) 2022/2554 — gilt für Finanzunternehmen und deren IKT-Dienstleister.*

**Hinweis:** YADS ist ein Security-Tool, kein Finanzdienstleister. DORA ist relevant, wenn YADS von DORA-pflichtigen Unternehmen eingesetzt wird oder wenn YADS als kritischer IKT-Drittdienstleister eingestuft wird.

### 2.1 IKT-Risikomanagement (Art. 5–16 DORA)

| Anforderung | YADS-Implementierung | Status |
|---|---|---|
| IKT-Risikoidentifikation und -bewertung | Security-Scanning (19 Module), Nuclei, Nuclei-Suggestions | ✅ Kernfunktion |
| Kontinuierliches Monitoring | Cron-basierte Scan-Schedules, SecurityTrend-Zeitreihen | ✅ |
| Patch-Management / Schwachstellen-Tracking | Nuclei-CVE-Erkennung, ChangeEvents für Deltas | ✅ |
| Netzwerk-Segmentierung | Docker Swarm Overlay-Network, Worker-Isolation | ✅ |
| Zugangskontrollen | RBAC, MFA, OIDC, HttpOnly JWT | ✅ |
| Kryptografie und Verschlüsselung | TLS, Bcrypt, Ed25519, X25519 ECDH | ✅ (Lücke: at-rest für API-Keys + Bug-Reports) |
| IKT-Betriebssicherheit | Celery-Worker-Isolation, Queue-Pause-Mechanismus | ✅ |
| Backup und Wiederherstellung | Encrypted ZIP Backup/Restore per UI | ✅ |
| Logging und Monitoring | Redis-Streaming, Prometheus, Grafana, SecurityAuditLog | ✅ |

### 2.2 IKT-Vorfallsmanagement (Art. 17–23 DORA)

| Anforderung | YADS-Implementierung | Status |
|---|---|---|
| Erkennung von IKT-Vorfällen | SecurityAuditLog, Grafana Alert Rules (5 vordefiniert) | ✅ |
| Klassifizierung von Vorfällen | SecurityAuditLog mit MITRE ATT&CK-Mapping | ✅ |
| Meldung schwerwiegender Vorfälle | Webhook-Notifications (Slack, Teams, Jira) | ✅ Mechanismus vorhanden |
| **Meldung an Aufsichtsbehörden** | Nicht implementiert | ❌ DORA Art. 19: Meldung an BaFin/EZB bei Major Incident; YADS hat keinen Reporting-Workflow |
| Dokumentation und Nachverfolgung | ChangeEvents, Audit-Hash-Chain | ✅ |
| Lessons Learned / Root Cause Analysis | Nicht implementiert | ⚠️ Kein strukturiertes Post-Incident-Formular |

### 2.3 Resilienztests (Art. 24–27 DORA)

| Anforderung | YADS-Implementierung | Status |
|---|---|---|
| Threat-Led Penetration Testing (TLPT) | Nuclei aktiver Scanner, Attack Path Analysis | ✅ Tool-Unterstützung vorhanden |
| Regelmäßige Resilienztests | Scan-Schedules, DNS-Health-Checks | ✅ |
| Swarm-Stress-Test | `scripts/verification/swarm_stress_test.py` | ✅ |
| **TLPT-Dokumentation** | Nicht implementiert | ⚠️ DORA verlangt formelle Testberichte; YADS-PDF-Report ist nah dran |

### 2.4 IKT-Drittparteienrisiko (Art. 28–44 DORA)

| Anforderung | YADS-Implementierung | Status |
|---|---|---|
| Inventar kritischer IKT-Drittparteien | Externe APIs (Google, Shodan, etc.) in Settings konfigurierbar | ⚠️ Kein formelles Drittparteien-Register |
| Vertragsanforderungen an Drittparteien | Nicht implementiert | ❌ DORA Art. 30 verlangt vertragliche Mindestanforderungen |
| Ausstiegsstrategien | BYOK-Modell ermöglicht Anbieterwechsel | ✅ (technisch) |
| Konzentrationsrisiko | Mehrere API-Provider konfigurierbar (kein Single-Vendor-Lock) | ✅ |

### 2.5 Informationsaustausch (Art. 45 DORA)

| Anforderung | Status |
|---|---|
| Teilen von Threat-Intelligence | Nuclei-Templates (öffentlich), VirusTotal-Feeds | ✅ |
| Strukturierter Austausch (STIX/TAXII) | Nicht implementiert | ⚠️ |

### 2.6 Aufbewahrungsfristen (DORA Art. 12 Abs. 7)

> DORA verlangt Aufbewahrung von IKT-bezogenen Protokollen für **mindestens 5 Jahre**.

| Log-Typ | Aktuelle Retention | DORA-Anforderung | Status |
|---|---|---|---|
| SecurityAuditLog (Hash-Chain) | Unbegrenzt | Min. 5 Jahre | ✅ (unbegrenzt = ≥ 5 Jahre) |
| Scan-Ergebnisse (ScanResult) | Konfigurierbar (DATA_RETENTION_DAYS) | IKT-Ereignisse: 5 Jahre | ⚠️ Default zu kurz wenn < 1825 Tage |
| HTTP-Traffic-Logs | Unbegrenzt | 5 Jahre (wenn IKT-Ereignis) | ⚠️ Inhaltlich unklar ob DORA-pflichtig |
| Grafana/Loki (Observability) | Loki: MinIO 5-Jahr-Retention | ✅ (wenn aktiviert) | ✅ |
| Prometheus Metriken | Standard: 15 Tage | Nicht DORA-relevant (Metriken ≠ Protokolle) | ✅ |

---

## 3. NIS2-Abgleich

*Network and Information Security Directive 2 (EU) 2022/2555 — gilt für wesentliche und wichtige Einrichtungen in kritischen Sektoren sowie deren IKT-Dienstleister.*

**Hinweis zur Anwendbarkeit:** YADS selbst ist ein Security-Tool. NIS2 ist relevant in zwei Szenarien:
1. **YADS wird von NIS2-pflichtigen Kunden eingesetzt** → YADS muss als IKT-Drittpartei NIS2-kompatibel sein (Art. 21 Abs. 2 lit. d: Lieferkettenrisiko)
2. **YADS-Betreiber ist selbst NIS2-pflichtig** (z. B. als Managed Security Service Provider) → Direkte Pflichten

---

### 3.1 Sicherheitsmaßnahmen (Art. 21 NIS2)

| Anforderung | YADS-Implementierung | Status |
|---|---|---|
| **Risikoanalyse und Sicherheitskonzepte** | SecurityAuditLog, Scan-basiertes Risiko-Scoring (A–F), MITRE ATT&CK-Mapping | ✅ |
| **Incident Response** | Webhook-Notifications (Scan-Events, Findings), Grafana Alert Rules | ⚠️ Technischer Mechanismus vorhanden, kein formeller IR-Plan |
| **Business Continuity / Backup** | Encrypted ZIP Backup/Restore per UI, automatisch bei API-Start | ✅ |
| **Lieferkettensicherheit** | BYOK-Modell (keine Zwangsbindung an Cloud-Provider), externe APIs konfigurierbar | ⚠️ Kein formelles Drittparteien-Sicherheitsregister |
| **Sicherheit in Netz und Informationssystemen** | Docker Swarm Overlay-Network, Worker-Isolation, RBAC | ✅ |
| **Schwachstellenmanagement** | Nuclei CVE-Erkennung, ChangeEvents, SecurityTrend-Zeitreihen | ✅ Kernfunktion |
| **Verschlüsselung** | TLS in Transit, Bcrypt, Ed25519, X25519 ECDH, Encrypted Backups | ⚠️ Lücke: API-Keys + Bug-Reports at rest unverschlüsselt |
| **Multi-Faktor-Authentifizierung** | TOTP-basiertes MFA, OIDC | ✅ (optional, nicht erzwungen per Default) |
| **Zugangskontrolle** | RBAC (admin, tenant_admin, scanner, auditor), Session-Timeouts, Rate Limiting | ✅ |
| **Sicherheit bei der Entwicklung** | GitLab CI/CD, SBOM/CBOM-Generierung (Syft), Docker Multi-Stage Builds | ✅ |
| **Grundlegende Cyber-Hygiene** | Security-Headers (HSTS, CSP, X-Frame), Input-Validierung via SQLModel ORM | ✅ |

### 3.2 Meldepflichten (Art. 23 NIS2)

> NIS2 verlangt eine **Frühwarnung innerhalb 24 Stunden**, eine **vollständige Meldung innerhalb 72 Stunden** und einen **Abschlussbericht nach 1 Monat** bei erheblichen Vorfällen.

| Anforderung | YADS-Implementierung | Status |
|---|---|---|
| Erkennung erheblicher Vorfälle | SecurityAuditLog, Grafana Alerts, Scan-basierte Anomalie-Erkennung | ✅ Erkennung vorhanden |
| **Frühwarnung 24h** | Nicht implementiert | ❌ Kein automatisierter Melde-Workflow an Behörden |
| **Vollständige Meldung 72h** | Nicht implementiert | ❌ Kein strukturiertes Meldeformular / Behörden-Reporting |
| **Abschlussbericht 1 Monat** | Nicht implementiert | ❌ |
| Interne Dokumentation des Vorfalls | ChangeEvents, Audit-Hash-Chain, Redis-Logs | ✅ Basis-Dokumentation vorhanden |
| Benachrichtigung betroffener Nutzer | Nicht implementiert | ❌ Kein Notification-Workflow für Betroffene |

**Zusammenfassung:** YADS hat die technische Grundlage zur Erkennung, aber keinen strukturierten Prozess für die behördliche Meldung. Das ist das größte NIS2-Gap.

### 3.3 Governance (Art. 20 NIS2)

> NIS2 verlangt, dass **Leitungsorgane** Cybersicherheitsmaßnahmen billigen, überwachen und für Verstöße haften. Sie müssen regelmäßig geschult werden.

| Anforderung | Status |
|---|---|
| Management-Verantwortung für Cybersicherheit dokumentiert | ⚠️ Nicht in YADS selbst abgebildet — organisatorische Aufgabe des Betreibers |
| Regelmäßige Schulungen des Leitungsorgans | ⚠️ Nicht in YADS abgebildet |
| Cybersicherheitskonzept genehmigt durch Leitungsorgan | ⚠️ Nicht dokumentiert |

### 3.4 Lieferkettenrisiko (Art. 21 Abs. 2 lit. d NIS2)

> NIS2 verlangt Sicherheit in der Lieferkette einschließlich sicherheitsbezogener Aspekte der Beziehungen zwischen Einrichtungen und ihren unmittelbaren Anbietern oder Dienstanbietern.

| Drittpartei | Sicherheitsbewertung | NIS2-Risiko | Status |
|---|---|---|---|
| crt.sh, Wayback Machine | Öffentliche APIs, keine Auth | Niedrig | ✅ |
| Google Custom Search | Datenverarbeitung in USA | Mittel | ⚠️ Kein Sicherheitsnachweis (SOC2 o. ä.) verlangt |
| Shodan / Censys | Datenverarbeitung in USA | Mittel | ⚠️ |
| VirusTotal (Google) | Datenverarbeitung in USA | Mittel | ⚠️ |
| OpenAI / Anthropic | Datenverarbeitung in USA, Finding-Texte werden übertragen | Hoch | ❌ Kein Sicherheitsnachweis in YADS-Doku; BYOK schützt vor Vendor-Lock-in, nicht vor Datentransfer |
| Nuclei (ProjectDiscovery) | OSS-Tool, lokale Ausführung | Niedrig | ✅ |
| Playwright / Chromium | Lokale Ausführung | Niedrig | ✅ |
| Splunk HEC (optional) | Konfigurierbar (on-premise möglich) | Mittel | ⚠️ Tenant-Verantwortung |

### 3.5 Aufbewahrungsfristen im NIS2-Kontext

NIS2 schreibt keine expliziten Aufbewahrungsfristen vor, verweist aber auf nationale Umsetzungsgesetze (in Deutschland: NIS2UmsuCG). Als Richtwert gelten **mindestens 3 Jahre** für sicherheitsrelevante Protokolle.

| Log-Typ | Aktuelle Retention | NIS2-Empfehlung | Status |
|---|---|---|---|
| SecurityAuditLog (Hash-Chain) | Unbegrenzt | Mind. 3 Jahre | ✅ |
| Scan-Ergebnisse | Konfigurierbar | Mind. 3 Jahre bei NIS2-Kunden | ⚠️ Kein verpflichtender Default |
| Incident-Dokumentation | Nicht strukturiert | Für Behördenmeldungen aufbewahren | ❌ Fehlt |
| Grafana/Loki | 5 Jahre (wenn aktiviert) | ✅ | ✅ |

### 3.6 NIS2 vs. DORA — Abgrenzung

| Aspekt | NIS2 | DORA |
|---|---|---|
| **Scope** | Alle wesentlichen/wichtigen Einrichtungen (Energie, Gesundheit, Wasser, Digital, etc.) | Nur Finanzsektor |
| **Fokus** | Netz- und Informationssicherheit, Meldepflichten | Operationale Resilienz, IKT-Drittparteien-Risiko |
| **Meldepflicht** | 24h Frühwarnung, 72h Vollmeldung | Major Incident an BaFin/EZB |
| **Sanktionen** | Bis 10 Mio. EUR / 2% Umsatz (wesentlich) | Bis 1% Tagesumsatz |
| **Überschneidung in YADS** | Beide verlangen Audit-Logs, Incident Response, Verschlüsselung, MFA | DORA zusätzlich: TLPT-Dokumentation, formelles Drittparteien-Register |

---

## 4. Kritische Lücken — Priorisierte Handlungsempfehlungen

### Prio 1 — Sofort (technische Sicherheitslücken mit Datenschutzbezug)

| # | Lücke | Rechtsgrundlage | Empfehlung |
|---|---|---|---|
| L1 | API-Keys (BYOK) im Klartext in DB | Art. 32 DSGVO, NIS2 Art. 21 | Verschlüsselung at rest (AES-256, Schlüssel aus Secret oder HSM) |
| L2 | Bug-Reports nach Entschlüsselung als Plaintext in DB | Art. 32 DSGVO, NIS2 Art. 21 | Re-Verschlüsselung in DB oder Anonymisierung nach Bearbeitung |
| L3 | HTTP-Traffic-Logs ohne TTL (können Auth-Header enthalten) | Art. 5 Abs. 1 lit. e DSGVO | Default TTL 30 Tage; kritische Header (Authorization, Cookie) vor Speicherung redaktieren |
| L4 | MFA nicht standardmäßig erzwungen | NIS2 Art. 21 Abs. 2 lit. j | MFA als Default-Pflicht für alle Tenant-Admins aktivieren |

### Prio 2 — Kurzfristig (fehlende Policies)

| # | Lücke | Rechtsgrundlage | Empfehlung |
|---|---|---|---|
| L5 | Kein Default für DATA_RETENTION_DAYS | Art. 5 lit. e DSGVO + DORA Art. 12 | Default 1825 Tage (5 Jahre) für Scan-Ergebnisse; HTTP-Logs default 30 Tage |
| L6 | Client-IP im Support-Portal ohne TTL | Art. 5 lit. e DSGVO | Automatische Löschung nach 7 Tagen |
| L7 | Kein AVV mit OpenAI/Anthropic dokumentiert | Art. 28 DSGVO | AVV abschließen; in Doku festhalten dass KI nur auf User-Trigger |
| L8 | Kein DORA/NIS2-Vorfallsmeldungs-Workflow | DORA Art. 19, NIS2 Art. 23 | Melde-Template + 24h/72h-Checkliste in Doku; Webhook-Notification als technische Basis |
| L9 | Kein strukturierter Incident-Response-Plan | NIS2 Art. 21 Abs. 2 lit. b | IR-Plan dokumentieren; SecurityAuditLog als Basis für Post-Mortem nutzen |

### Prio 3 — Mittelfristig (Dokumentation & Compliance)

| # | Lücke | Rechtsgrundlage | Empfehlung |
|---|---|---|---|
| L10 | Kein formelles Drittparteien-Register | DORA Art. 28, NIS2 Art. 21 Abs. 2 lit. d | Verzeichnis der externen APIs mit Sicherheitsklassifizierung + SOC2/ISO27001-Nachweis-Anforderung in Doku |
| L11 | OSINT-Zweckbindung für personenbezogene Daten (E-Mails, Social) unklar | Art. 5 lit. b DSGVO | Tenant-AGB / Nutzungsrichtlinie formulieren |
| L12 | Kein AVV-Template für Slack/Teams/Jira-Webhook-Empfänger | Art. 28 DSGVO | Hinweis in Onboarding-Wizard + Doku |
| L13 | SSRF-Schutz ohne explizites RFC-1918-Blocklist | Art. 32 DSGVO, NIS2 Art. 21 | `ipaddress.ip_address(ip).is_private` Check in Scanner-Eingang |
| L14 | Keine dokumentierte Governance-Struktur für Cybersicherheit | NIS2 Art. 20 | Sicherheitsverantwortliche benennen; Management-Sign-off dokumentieren |
| L15 | Kein STIX/TAXII-Austausch für Threat Intelligence | NIS2 Art. 45 | Optionaler Export-Endpoint für strukturierten Austausch (mittelfristig) |

---

## 5. Konflikt DSGVO ↔ DORA ↔ NIS2

| Datenpunkt | DSGVO | DORA | NIS2 | Lösung |
|---|---|---|---|---|
| SecurityAuditLog | Datensparsamkeit → so kurz wie nötig | Mind. 5 Jahre | Mind. 3 Jahre | **DORA geht vor** bei Finanzsektor-Kunden (5 Jahre); sonst NIS2 (3 Jahre); Default: 5 Jahre |
| HTTP-Traffic-Logs | Kurze TTL (30 Tage) | Können IKT-Vorfalls-Protokolle sein → 5 Jahre | Incident-Logs 3 Jahre | **Differenzierung:** Routine-Crawler-Logs 30 Tage; bei erkanntem Vorfall → Archivierung in Loki (MinIO, 5 Jahre) |
| Scan-Ergebnisse | Zweckgebunden löschen | IKT-Monitoring → Langzeitaufbewahrung | Mind. 3 Jahre | **Konfigurierbar lassen** (DATA_RETENTION_DAYS), Default 1825 Tage, Tenant entscheidet |
| MFA-Pflicht | Keine Pflicht (aber empfohlen) | Empfohlen | Art. 21 Abs. 2 lit. j: **Pflicht** für privilegierte Accounts | MFA-Default für Tenant-Admins + Admins erzwingen; User optional lassen |
| Vorfallsmeldung | 72h bei Datenpannen (Art. 33 DSGVO) | Sofort + Abschlussbericht (Art. 19 DORA) | 24h Frühwarnung + 72h Vollmeldung (Art. 23 NIS2) | Einheitlicher IR-Workflow der alle drei Fristen bedient; 24h NIS2-Frühwarnung ist schärfste Anforderung |

---

*Erstellt: 2026-03-21 | Aktualisiert: 2026-03-21 (NIS2 ergänzt) | Stand: YADS v1.51.5*
