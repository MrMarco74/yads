# YADS – User Data Analyse

## Was gesammelt wird & wofür

### YADS (Core)

| Datenkategorie | Konkrete Felder | Zweck |
|---|---|---|
| **Accountdaten** | Username, E-Mail, Passwort-Hash (Bcrypt), letzter Login, Sprache | Authentifizierung, UX |
| **MFA** | TOTP-Secret, Pending-Secret | 2FA |
| **Session** | JWT (HS256, HttpOnly Cookie), Ablaufzeit pro Tenant | Session-Management |
| **OIDC** | Subject-ID (Keycloak), Tenant-Name | SSO-Login |
| **Audit-Events** | Login-Versuche, Passwort-Änderungen, Rollenänderungen, API-Key-Lifecycle, Backup-Events | Compliance, MITRE ATT&CK Mapping |
| **HTTP-Traffic-Logs** | Methode, URL, alle Request-/Response-Header, Body-Snippet, Timing | Crawler-Logs beim Scan |
| **Scan-Ergebnisse** | 19 Scanner-Module (DNS, SSL, Screenshots, E-Mails, Telefonnummern, Social-Handles, Credentials, …) | Angriffsflächen-Analyse |
| **OSINT-Daten** | Domains, IPs, E-Mails, Social-Accounts von Scan-Targets | Security-Scanning |
| **Tenant-Einstellungen** | OSINT-Quotas, LLM-Provider + Keys, Report-Branding | Mandantenkonfiguration |
| **API-Keys (BYOK)** | Google, HIBP, Hunter.io, GitHub, Twitter, Shodan, Censys, VirusTotal, OpenAI, Anthropic | Werden an die jeweiligen externen APIs geschickt |

#### Externe Übertragungen vom Core

- Domainnamen → crt.sh, Google, HIBP, Hunter.io, GitHub, Shodan, Censys, VirusTotal
- Security-Events → Splunk HEC (optional)
- Findings → Jira / GitHub Issues / Slack/Teams Webhooks
- Finding-Texte → OpenAI / Anthropic / Ollama (für KI-Analyse)

---

### YADS-Support-Portal

| Datenkategorie | Konkrete Felder | Zweck |
|---|---|---|
| **Kundendaten** | customer_id, Name, E-Mail, Firma | Kundenverwaltung |
| **Bug-Reports** | Instance-UUID, YADS-Version, Beschreibung, vollständiger verschlüsselter JSON-Report | Support-Bearbeitung |
| **Support-Nachrichten** | Sender, Text, Timestamps, Gelesen-Status | Ticketsystem |
| **Aktivierungsanfragen** | Instance-UUID, Ed25519 Request-Code, Status, Response-Code | Lizenzaktivierung |
| **Kontaktanfragen** | Name, E-Mail, Firma, Topic, Nachricht, **Client-IP** | Lead-Management / Support |
| **Ed25519 Public Keys** | Customer-ID, Public Key, EOS-Status | Signatur-Verifikation |

---

### Datenbankschema (Core) – Übersicht

| Tabelle | Inhalt |
|---|---|
| `user` | Accountdaten, MFA, OIDC, Auth-Mode |
| `tenant` | Mandant, OSINT-Quotas, LLM-Config, Branding |
| `target` | Domains/Assets, Tags (JSONB), Discovery-Metadaten |
| `scanresult` | Scanner-Outputs (JSONB), 19 Module |
| `modulestate` | SHA256-Hashes für Change Detection |
| `changeevent` | Diffs zwischen Scans |
| `httptraffic` | Vollständige Crawler-Requests/Responses |
| `userrtenantlink` | M:N User↔Tenant Cross-Access |
| `securitytrend` | Historische Security-Scores |
| `scanschedule` | Cron-basierte Scan-Planung |
| `webhook` | Event-Integrationen |
| `discoverysession` | Subdomain-Discovery-Sessions |
| `discoverycandidate` | Entdeckte Domains pending Approval |
| `discoveryblocklist` | Tenant-weite Domain-Blocklisten |
| `workernode` | Registrierte Worker (Hostname, IP, Load) |
| `workertask` | Task-Tracking mit Progress |
| `resourcequota` | Per-Tenant Limits |

---

### Projektübersicht

| Projekt | Rolle | User-Daten? |
|---|---|---|
| **yads** | Core-API + Worker | Ja, umfangreich |
| **yads-support-portal** | Ticketsystem | Ja (Kundendaten, IPs) |
| **yads-infra** | Docker Compose Deployment | Nur Konfiguration |
| **yads-kubernetes** | K8s Manifeste | Nur Konfiguration |
| **yads-common** | Shared Library | Nein |
| **yads-tools** | Release-Automation | Nein (API-Keys in Configs) |
| **yads-testing** | Testlabor | Nein |
| **yads-website** | Marketingseite | Nein |

---

## Kritische Punkte

1. **API-Keys im Klartext in der DB** — alle BYOK-Keys (OpenAI, Shodan, etc.) werden unverschlüsselt gespeichert

2. **HTTP-Traffic-Logs ohne TTL** — alle Request/Response-Header der Crawler werden unbegrenzt gespeichert; wenn ein Target Auth-Header hat, landen die in der DB

3. **Keine Daten-Retention-Policy** — Scan-Ergebnisse, Audit-Logs, HTTP-Logs laufen unbegrenzt auf

4. **Client-IP im Support-Portal** — wird bei Kontaktanfragen mitgeloggt

5. **Bug-Reports** — werden serverseitig entschlüsselt und als Plaintext in der DB gespeichert (enthält vollständige Systeminfos der Installation)

---

## NIS2-Relevanz (Kurzübersicht)

*Vollständige Analyse in `datenpunkte_vs_vorgaben.md` Abschnitt 3.*

NIS2 (EU 2022/2555) ist für YADS in zwei Kontexten relevant:
- **Als IKT-Drittpartei** von NIS2-pflichtigen Kunden (Lieferkettenrisiko Art. 21 Abs. 2 lit. d)
- **Als potenzieller MSSP** wenn der Betreiber selbst unter NIS2 fällt

| Bereich | NIS2-Anforderung | YADS-Status |
|---|---|---|
| Verschlüsselung at rest | Art. 21 — Pflicht | ❌ API-Keys + Bug-Reports unverschlüsselt |
| MFA | Art. 21 Abs. 2 lit. j — Pflicht für privilegierte Accounts | ⚠️ Vorhanden, aber kein erzwungener Default |
| Incident Response | Art. 21 Abs. 2 lit. b — Formeller IR-Plan | ❌ Kein dokumentierter Plan |
| Meldepflicht 24h/72h | Art. 23 — Behördenmeldung | ❌ Kein Melde-Workflow implementiert |
| Lieferkettenrisiko | Art. 21 Abs. 2 lit. d — Drittparteien-Sicherheit | ⚠️ Kein formelles Register |
| Kontinuierliches Monitoring | Art. 21 — Schwachstellen-Tracking | ✅ Kernfunktion von YADS |
| Backup & Wiederherstellung | Art. 21 — Business Continuity | ✅ Encrypted ZIP Backup |
| Governance-Dokumentation | Art. 20 — Management-Verantwortung | ⚠️ Organisatorische Aufgabe des Betreibers |

---

*Erstellt: 2026-03-21 | Aktualisiert: 2026-03-21 (NIS2 ergänzt)*
