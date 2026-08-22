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

## 🔍 Recon Engine — Erweiterungen (2026-08-21)

### 7. Passive-Hunter-Phase erweitern 🕸️ ✅ implementiert (Welle 1, 2026-08-22)
- `discovery_passive_hunters.py`: aktuell SPF-Traversal, Wayback-CDX, VirusTotal-Passive-DNS, SRV, CORS/CSP, Robots/Sitemap, Favicon/Shodan
- Ergänzen: Certificate-Transparency-Log-Streaming (live statt on-demand crt.sh-Abfrage), DNS-Zone-Transfer-Versuche
- Umgesetzt: `axfr_zone_transfer()` (Zone-Transfer-Versuch gegen alle NS, read-only) + `ct_log_sans()` (crt.sh SAN-Extraktion inkl. Cross-Domain-Cohosting). "Live" statt on-demand: `run_discovery_scan` diffed CT-SAN-Ergebnisse jetzt gegen `BaselineSnapshot` (Welle 0) — wiederholte/geplante Discovery-Läufe melden nur noch neu hinzugekommene Zertifikate statt der vollen Liste jedes Mal. Verifiziert gegen test-tenant.example (Dev): AXFR korrekt verweigert (0 Kandidaten), CT-SAN-Hunter fehlerfrei durchgelaufen.

### 8. Discovery-Session parallelisieren ⚡ ✅ analysiert + gefixt (Welle 1, 2026-08-22)
- `run_discovery_scan` läuft aktuell sequenziell durch die Kandidatenliste (ein Target nach dem anderen, siehe `remaining=N` Logs)
- Mehrere Kandidaten gleichzeitig verarbeiten → deutlich schnellere Discovery-Sessions bei großen Zielen (z.B. examplecorp.* mit hunderten Subdomains)
- Befund: `DiscoveryOrchestrator._dispatch_depth` dispatcht bereits alle Kandidaten einer Tiefe async über `celery_app.send_task` (keine echte Sequenzialität im Code) — der `remaining=N`-Eindruck kam vom tatsächlichen Flaschenhals: `run_discovery_scan` brute-forcte pro dispatchtem Kandidat die **volle** Subdomain-Wordlist (50001 Einträge im Test) über `SubdomainScanner`. Fix: neuer `wordlist_limit`-Parameter auf `SubdomainScanner` + `light_subdomain_scan`-Flag auf `run_all_scans`, von `run_discovery_scan` gesetzt → Wordlist auf 100 Einträge gekappt (CT-Logs laufen unverändert vollständig). Verifiziert: 50001 → 103 Kandidaten pro Discovery-Scan, Laufzeit von ~274s auf <1s für den Wordlist-Teil.

### 9. Scoring/Dedup vor Auto-Queue 🎯 ✅ implementiert (Welle 1, 2026-08-22)
- Aktuell wird jeder neu gefundene Subdomain-Kandidat sofort real gescannt (siehe `worker_tasks.py` Auto-Queue-Block)
- Vor-Scoring einführen: nur Kandidaten mit ≥2 unabhängigen Signalen automatisch queuen, Rest nur zur manuellen Review vorschlagen
- Würde die Queue-Explosion eindämmen, die uns am 2026-08-21 ins Stop/Purge-Debugging gebracht hat
- Umgesetzt: `SubdomainScanner` trackt jetzt pro Kandidat die Herkunft (`sources`: `ct_log`/`wordlist`) statt sie vor der DNS-Verifikation in einem flachen Set zu verschmelzen. Der Auto-Queue-Block in `worker_tasks.py` queued nur noch bei `len(sources) >= 2`; Single-Signal-Kandidaten werden weiterhin als Target angelegt, aber nur per `new_asset`-Webhook (mit `needs_review: true`) zur manuellen Review vorgeschlagen, kein automatischer Scan. Verifiziert: `sources`-Feld erscheint korrekt in `scanresult.data` (z.B. `["ct_log"]`).

### 9a. Auto-Refresh auf `/discovery/` fehlt 🔄 ✅ implementiert (Welle 0, 2026-08-22)
- Seite unter `/discovery/` (discovery_sessions.html) aktualisiert sich nicht automatisch, während eine Session läuft (`remaining=N` zählt im Log runter, UI zeigt das nicht live)
- HTMX-Polling (`hx-trigger="every Ns"`) o.ä. ergänzen, damit Fortschritt sichtbar ist ohne manuelles Reload
- Umgesetzt: `#session-list` pollt alle 5s (`hx-get="/discovery" hx-select hx-swap`), nur solange mindestens eine Session `status == running` ist — stoppt sich selbst, sobald abgeschlossen. Verifiziert gegen Tenant FRISCHKORN/test-tenant.example (Dev).

---

## 🌐 Plattformweite Erweiterungen (2026-08-21)

### 10. EPSS-Priorisierung statt nur CVSS 📊
- `cve_lookup.py`/`nuclei_scanner.py` liefern CVEs, Priorisierung läuft aktuell über CVSS-Schwere
- EPSS-Score (Wahrscheinlichkeit aktiver Ausnutzung) zusätzlich einblenden
- Trennt "kritisch aber theoretisch" von "wird gerade aktiv ausgenutzt" — deutlich actionable-er

### 11. Cross-Tenant-Infrastruktur-Korrelation 🔗 ⏸️ zurückgestellt (Welle 13, 2026-08-22)
- Multi-Tenancy ist sauber über `tenant_id` isoliert, dadurch aber unsichtbar, wenn zwei Tenants dieselbe IP/ASN/Zertifikat/Hosting-Provider teilen
- Plattformweite (Admin-only) Korrelationsansicht über Tenant-Grenzen hinweg (Shared-Hosting-Risiko, Supply-Chain)
- Aus Zeitbudget-Gründen nicht umgesetzt — bewusst als letztes Item behandelt, da sensibelste Cross-Tenant-Datenexposition (siehe Plan).

### 12. Adaptive statt starre Scan-Frequenz ⏱️ ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `ScanSchedule`/`TenantScanConfig` fahren aktuell fest nach daily/weekly
- Targets mit stabilem Change-Detection-Hash seltener scannen, Targets mit häufigen Changes häufiger
- Spart Compute und reduziert Queue-Last (siehe Queue-Explosion vom 2026-08-21)
- Aus Zeitbudget-Gründen nicht umgesetzt — würde eine neue Adaptive-Frequenz-Berechnung im Scheduler-Loop (`yads/core/scheduler.py`) erfordern, die bewusst nicht ohne gründliche Tests angefasst wurde (siehe bekannter Session-Leak-Bug im selben Modul, in Welle 2 dokumentiert). Offen für eine künftige Session.

---

## 🧩 Weitere Erweiterungen (2026-08-21, Batch 2)

### 13. Compliance-Gap-Tracking über Zeit 📈 ✅ implementiert (Welle 6, 2026-08-22)
- `compliance.py`/`custom/compliance_frameworks.py` liefern aktuell vermutlich nur einen Punkt-in-Zeit-Score
- Historie ergänzen: welche Controls (ISO 27001/NIS2/DORA) wurden seit letztem Report geschlossen bzw. neu aufgerissen
- Deutlich wertvoller für Kunden als reiner Snapshot
- Umgesetzt: `ComplianceTrend` speicherte bereits den Aggregat-Score täglich — `calculate_compliance_trends` diffed jetzt zusätzlich die Menge bestandener Controls je Framework via `baseline_diff` (Welle 0); bei neu fehlgeschlagenen Controls wird ein `security_alert`-Webhook gefeuert. Verifiziert: Task manuell ausgeführt, 5 Frameworks × Tenant FRISCHKORN korrekt gescort, Baseline-Snapshots angelegt.

### 14. Adaptives Deception-Deployment 🎭 ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `deception/honeypots.py`, `sinkholes.py`, `tarpits.py` existieren als Module, aktuell vermutlich manuell konfiguriert
- Automatisch vorschlagen, welche Technik zum tatsächlich exponierten Attack Surface passt (z.B. DB-Honeypot nur wenn DB-Port offen)
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 15. Worker-Kapazitäts-Dashboard 📊 ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `WorkerNode`/`ResourceQuota` existieren für Distributed Workers, aber ohne sichtbare Durchsatz-Metriken (Scans/Stunde, Ø Modul-Laufzeit pro Worker)
- Hätte beim WORKER_CONCURRENCY-Tuning/der Queue-Last vom 2026-08-21 direkt geholfen statt aus Logs zu raten
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 16. Alert-Dedup für Webhooks/Digests 🔔 ✅ implementiert (Welle 4, 2026-08-22)
- `webhook_service.py` + `send_daily_digests` schicken vermutlich eine Notification pro Finding/Target
- Bei großen Domain-Estates (z.B. examplecorp.* mit hunderten Subdomains) führt das zu Alert-Fatigue
- Umgesetzt: `WebhookService.trigger_event` zählt (tenant, event_type) über ein Redis-Fenster (600s); bis zu 5 Alerts gehen normal raus, danach wird eine einzelne "[Bundled]"-Sammel-Nachricht gesendet und weitere Einzel-Alerts im Fenster unterdrückt. Kein Delay für die ersten Alerts, kein Eingriff in dringende Einzel-Events bei normalem Volumen.
- Ähnliche Findings über mehrere Targets zu einer Sammel-Notification bündeln

---

## 🧩 Weitere Erweiterungen (2026-08-21, Batch 3)

### 17. PQC-Migrations-Tracking 🔐 ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `analyzers/pqc_scanner.py`/`pqc.py`/`cbom.json` erfassen Post-Quantum-Crypto-Readiness pro Scan
- Trend-Ansicht über Zeit ergänzen: welcher Anteil der Zertifikate/Algorithmen ist PQC-safe, Entwicklung bei Zertifikatserneuerungen
- Macht aus Einzel-Report eine Migrations-Roadmap
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 18. Severity-gewichtetes Tech-Drift-Alerting ⚖️ ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `tech_drift.py` erkennt vermutlich jede Änderung gleich
- TLS-Downgrade sollte anders alarmieren als ein kleiner JS-Lib-Bump
- Konfigurierbare Schweregrad-Schwellen pro Tenant zur Reduktion von Alert-Rauschen
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 19. API-Key-Health-Check für BYOK-Integrationen 🔑 ✅ implementiert (Welle 9, 2026-08-22)
- Tenants hinterlegen eigene Keys (Google CSE, HIBP, Shodan, VirusTotal) über `secrets.py`/`tenant_keys.py`
- Aktuell fällt ein abgelaufener/ungültiger Key vermutlich erst mitten im Scan auf
- Health-Check-Badge in Settings (Key testen, Ablaufdatum, letzter erfolgreicher Call)
- Umgesetzt: nutzt Baustein 2 (`integration_health.py`, Welle 0). "Test"-Button je BYOK-Key in Tenant Settings, echte Live-Validierung gegen Shodan/VirusTotal/HIBP-APIs, generische Presence-Check-Meldung für die übrigen Provider. Verifiziert mit echtem (ungültigem) Test-Key: korrekt als "failed / HTTP 401" erkannt und persistiert.

### 20. Scan-Profile-Vorlagen/Sharing 📋 ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `scan_profiles.py` ist vermutlich rein pro Tenant
- Vordefinierte, exportier-/importierbare Profile ("PCI-DSS Quick Scan", "Fintech Baseline") als JSON
- Admins können sie tenant-übergreifend bereitstellen → schnelleres Onboarding neuer Tenants
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 21. Third-Party-Domains-Seite 🌍 ✅ implementiert (Welle 2, 2026-08-22)
- `yads/modules/external_resources_scanner.py` sammelt pro Target bereits externe Scripts/Styles/iFrames/Bilder inkl. Risiko-Klassifizierung (`TRUSTED_ORIGINS`, `SUSPICIOUS_PATTERNS`, Mixed-Content), aber es gibt keine aggregierte Seite dafür
- Die bestehende "External Links"-Analytics-Seite (`analytics_external_links.html`) liest nur `crawler`- und `dns_scanner`-Daten — `external_resources`-Ergebnisse fließen da nicht ein
- Neue Seite analog zu External-Links bauen, gespeist aus `external_resources`: sortier-/filterbar nach Trust-Level, Ressourcentyp, Anzahl betroffener Targets
- Zusatznutzen: DSGVO-Reporting (welche Drittanbieter laden die Seiten der Tenants)
- Umgesetzt: neuer Router `third_party_domains.py` (+ `third_party_domains.html`), unter "Audit → Core Findings" in die Sidebar verlinkt. Verifiziert gegen test-tenant.example (Dev): Seite lädt, Trust-/Typ-Filter funktionieren, Leerzustand korrekt (Domain lädt keine externen Ressourcen).

---

## 🧩 Weitere Erweiterungen (2026-08-21, Batch 4)

### 22. Proaktive Cert-Expiry-Alerts ⏰ ✅ implementiert (Welle 3, 2026-08-22)
- `cert_timeline.py` zeigt vermutlich nur die Zertifikats-Historie rückblickend an
- Alert X Tage vor Ablauf über alle Targets hinweg ergänzen
- Verhindert den Klassiker "Zertifikat lief unbemerkt ab"
- Umgesetzt: neuer periodischer Task `check_cert_expiry_alerts` (täglich, Celery Beat), läuft über alle Targets, feuert `security_alert`-Webhook einmalig pro Zertifikat via `baseline_diff` sobald <30 Tage bis Ablauf.

### 23. WAF-Bypass-Verifizierung 🛡️ ✅ implementiert (Welle 3, 2026-08-22)
- `waf_analysis.py` erkennt vermutlich nur, *ob* eine WAF vorhanden ist
- `nuclei_scanner.py`-Findings dagegenhalten: wurden Requests tatsächlich geblockt oder kamen sie durch?
- Sagt dem Kunden, ob die WAF-Regeln wirklich greifen, statt nur "WAF vorhanden"
- Befund: `waf_detector.py` prüfte bereits aktiv mit synthetischen Angriffs-Payloads (`_probe_waf_block`) UND Origin-IP-Bypass — ergänzt um echten Abgleich gegen `nuclei_scanner`-Funde: wenn trotz erkannter WAF reale medium+/high/critical-Findings durchkamen, eigenes "WAF bypass confirmed by real scan"-Finding.

### 24. Attack-Surface-Delta-Ansicht 📉📈 ✅ implementiert (Welle 3, 2026-08-22)
- `asr.py` trackt exponierte Ports/Services vermutlich nur als Snapshot
- "seit letztem Scan geschlossen" / "neu exponiert"-Diff-Ansicht ergänzen
- Macht Attack-Surface-Wachstum bzw. -Reduktion über Zeit sichtbar
- Befund: `asr.py` ist tatsächlich das "Cleanup Candidates"-Modul (dead endpoints, expired certs) — Ports/Services werden in `ports.py`/`port_scanner.py`/`nmap_scanner.py` getrackt. Umgesetzt dort: beide Scanner diffen offene Ports via `baseline_diff` (gemeinsamer Snapshot-Key), `ports.py` zeigt neue Spalte "Delta Since Last Scan" (↑ neu exponiert / ↓ geschlossen). Verifiziert gegen test-tenant.example.

### 25. Onboarding mit Recon-Vorschau 🧭 ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `onboarding.py`: beim Anlegen eines neuen Tenants/Targets aktuell vermutlich Blanko-Konfiguration
- Schneller passiver Pre-Scan während Onboarding, der automatisch ein Scan-Profil vorschlägt
- Beispiel: "wir haben diese Subdomains gefunden, sieht nach WordPress + Cloudflare aus, empfohlene Module: X"
- Aus Zeitbudget-Gründen nicht umgesetzt.

---

## 🧩 Weitere Erweiterungen (2026-08-21, Batch 5)

### 26. HTTP-Traffic-Anomalie-Erkennung 📡 ✅ implementiert (Welle 3, 2026-08-22)
- Crawler loggt bereits Request/Response-Daten (`HttpTraffic`-Modell, `reports_traffic.py`), aktuell vermutlich nur als Rohliste einsehbar
- Anomalie-Erkennung ergänzen: plötzliche Status-Code-Häufungen, neu auftauchende unerwartete Endpunkte (Shadow-API-Indikator)
- Umgesetzt: `crawler.py` berechnet nach jedem Crawl eine Fehlerrate (bucketed low/medium/high via `baseline_diff`) und diffed API-artige Pfade (`/api/`, `/admin/`, `/graphql`, `/v\d+/`, `.php`/`.aspx`/`.jsp`) gegen den letzten Crawl. Neue Endpunkte + Fehlerraten-Sprünge werden als Banner auf `/reports/traffic` angezeigt.

### 27. Tag-basierte Scan-Segmentierung 🏷️
- `tags.py` existiert für Targets, vermutlich nur zur Filterung genutzt
- Tag-basierte Scan-Frequenz/Reporting ergänzen (z.B. "critical-prod" täglich + eigener Exec-Report, "staging" nur wöchentlich)

### 28. Redirect-Chain-Health-Check 🔀 ✅ implementiert (Welle 3, 2026-08-22)
- Redirect-Graph (`redirect_graph.html`) existiert bereits zur Visualisierung
- Als eigene Finding-Kategorie ergänzen: kaputte/zirkuläre/zu lange Redirect-Ketten aktiv erkennen (SEO- und Security-relevant)
- Umgesetzt: `web_analyzer.py` fängt `requests.exceptions.TooManyRedirects` jetzt separat (zirkulär/exzessiv) und flaggt zusätzlich Ketten >5 Hops sowie Ketten, die in HTTP 4xx/5xx enden. `web_analyzer` wurde dafür gezielt (nur `redirect_chain_issues`) als `finding_module` aktiviert, damit es in Unified Findings erscheint.

### 29. Triage-Workflow für Notifications ✅ implementiert (Welle 0 + Welle 4, 2026-08-22)
- `notifications.py` ist vermutlich ein reiner Feed
- Ack/Snooze/Zuweisen-an-User ergänzen — leichtgewichtige Ticketing-Schicht direkt in YADS, ergänzt Punkt 6 (JIRA-Integration) statt sie zu ersetzen
- Befund: Ack/Assign/Notiz existierten für `SecurityFinding` (die eigentliche Findings-Ticketing-Schicht, nicht `notifications.py`, das ein reiner Changelog/Announcement-Feed ist) bereits vollständig — nur Snooze fehlte. Welle 0 ergänzte die `snoozed_until`-Spalte, Welle 4 verdrahtet sie: Snooze-Dropdown (1/7/30 Tage) im Status-Modal, snoozte Findings werden aus der Standardansicht ausgeblendet und über den neuen "Snoozed"-Statusfilter separat einsehbar. Verifiziert: Finding snoozen → verschwindet aus Default-View → erscheint unter Snoozed-Filter.

---

## 🧩 Weitere Erweiterungen (2026-08-21, Batch 6)

### 30. Subdomain-Takeover mit Remediation-Guide 🩹 ✅ implementiert (Welle 3, 2026-08-22)
- `subdomain_takeover_scanner.py` erkennt verwundbare CNAMEs, flaggt sie aber vermutlich nur
- Provider-spezifische Remediation-Hinweise ergänzen (z.B. "DNS-Record löschen" bei Heroku/S3/GitHub Pages, mit Link zur Anleitung)
- Umgesetzt: `REMEDIATION_GUIDES`-Mapping für alle gängigen Provider (S3, GitHub Pages, Heroku, Netlify, Azure, Shopify, ...), Anzeige in der Target-Detail-Karte. **Nebenbei gefundener und gefixter Bug:** das Modul nutzte durchgängig `self.db_session`, das in `BaseScannerModule` nie gesetzt wird (nur `self.db` existiert) — die OSINT-Persistierung und die DB-gestützte Subdomain-Kandidatenliste liefen seit jeher als stille Exception ins Leere. Fix verifiziert: kein Fehler mehr im Worker-Log.

### 31. Kontinuierliches Dependency-Confusion-Monitoring 📦 ✅ implementiert (Welle 3, 2026-08-22)
- `dependency_confusion.py` prüft vermutlich einmalig gegen npm/PyPI, ob interne Package-Namen öffentlich registrierbar sind
- Neue interne Package-Namen aus `js_secrets_scanner`/Crawler automatisch als Kandidaten fürs laufende Monitoring nachziehen
- Umgesetzt: `js_secrets_scanner.py` extrahiert jetzt gescopte npm-Package-Referenzen (`require()`/`import`) aus gescanntem JS und legt sie als `discovered_packages` ab. `dependency_confusion.py` zieht diese zusätzlich zu seinen eigenen Funden heran und akkumuliert die überwachte Kandidatenmenge über `baseline_diff` (Welle 0) statt bei jedem Scan bei null anzufangen.

### 32. Leak-Monitor-Diffing (nur neue Breaches) 🆕 ✅ implementiert (Welle 4, 2026-08-22)
- Zwei Module (`leak_monitor.py`, `leaked_credentials.py`) alarmieren vermutlich jeden Scan-Zyklus erneut für dieselbe alte Breach
- Befund: Der aggregierte "found in N breaches"-Finding-Titel ändert sich zwar (und damit auch der Finding-Hash) sobald sich die Gesamtzahl ändert — aber das unterscheidet nicht "neue Breach hinzugekommen" von "alte Breach verschwunden". Umgesetzt: `leaked_credentials.py` diffed die einzelnen Breach-Namen via `baseline_diff` gegen den letzten Scan und feuert nur bei wirklich neuen Breach-Namen einen `security_alert`-Webhook. `leak_monitor.py` bleibt unverändert (nutzt aktuell nur statische E-Mail-Aliase ohne echtes Alerting — kein Dedup-Bug dort vorhanden).
- Diffing gegen letzten Scan ergänzen, sodass nur wirklich neue Breach-Einträge eine Notification auslösen (Spezialfall von Punkt 16)

### 33. Login-Form × Leaked-Credentials-Korrelation 🔓 ✅ implementiert (Welle 3, 2026-08-22)
- `form_discovery.py`/`login_scanner.py` finden Login-Formulare, `leaked_credentials.py` findet geleakte Mitarbeiter-Credentials — aktuell getrennt betrachtet
- Korrelieren: "geleakte Zugangsdaten UND live erreichbares Login-Formular" als eigenes Credential-Stuffing-Risiko-Finding
- Umgesetzt: `login_scanner.py` liest das neueste `leaked_credentials`-Ergebnis; bei `breach_count > 0` + live Login-Formular(en) wird ein eigenständiges "Credential-stuffing risk"-Finding erzeugt (critical, wenn Klartext/Hash-Passwörter geleakt wurden, sonst high).

---

## 🧩 Weitere Erweiterungen (2026-08-21, Batch 7)

### 34. GraphQL/WebSocket-Findings in Security-Score einbeziehen 🧮 ✅ Bug gefunden + gefixt (Welle 3, 2026-08-22)
- `graphql_scanner.py`/`websocket_scanner.py` sind Nischen-Module — prüfen, ob deren Findings überhaupt in `scoring.py` einfließen
- Exotische API-Oberflächen werden bei Scoring-Modellen erfahrungsgemäß vergessen, obwohl oft unterschätzte Angriffsflächen
- Befund: `scoring.py`s `calculate_target_score` liest graphql_scanner/websocket_scanner tatsächlich schon aus — der Bug lag bei den **Aufrufern**: `worker_tasks.py` (`calculate_security_trends`), `dashboard.py` (Compliance-/Security-Kacheln) und `portfolio.py` filterten ihre SQL-Query vorab auf eine veraltete 3-5-Modul-Liste (`ssl_scanner, web_analyzer, port_scanner, ...`), sodass GraphQL/WebSocket (und auch leaked_credentials, dependency_confusion, subdomain_takeover, tls_deep_scanner, api_security_scanner, waf_detector, password_spray_mapper) den Scorer dort nie erreichten. Fix: neue Konstante `SCORED_MODULE_NAMES` in `scoring.py` als Single Source of Truth, alle drei Call-Sites darauf umgestellt.

### 35. Brand-Protection-Dashboard 🎭
- `phishing_scanner.py`, `brand_intelligence.py`, `typosquat_scanner.py`, `social_media_scanner.py` decken überlappende Aspekte ab, vermutlich getrennt angezeigt
- Gemeinsame Triage-Ansicht statt vier Einzel-Tabs

### 36. RPKI/BGP-Hijack-Monitoring statt Einzel-Scan 🌐 ✅ implementiert (Welle 3, 2026-08-22)
- `rpki_scanner.py` prüft vermutlich RPKI-Validität nur punktuell
- Route-Origin-Änderungen (BGP-Hijacks) sind zeitkritisch — kontinuierliches Monitoring statt Scan-Snapshot, relevant für Kunden mit eigenen ASNs
- Umgesetzt: `rpki_scanner.py` diffed die announcing-ASN pro IP via `baseline_diff` gegen den letzten Scan; ändert sich die ASN unerwartet, wird ein critical "Route origin changed"-Finding erzeugt UND sofort ein `security_alert`-Webhook gefeuert (nicht erst beim nächsten Report-Aufruf) — das eigentliche BGP-Hijack-Signal, unabhängig vom statischen RPKI-valid/invalid-Check.

### 37. Credential-Attack-Resilience-Score 🔐 ✅ implementiert (Welle 3, 2026-08-22)
- `password_spray_mapper.py` und `login_scanner.py` (MFA/Lockout-Erkennung) liefern vermutlich getrennte Rohdaten
- Zu gemeinsamem Score kombinieren statt zwei isolierte Findings
- Umgesetzt: neue Karte "Credential-Attack Resilience" in der Target-Detail-Ansicht — kombinierter Score (Mittelwert aus `login_scanner`/`password_spray_mapper`), plus MFA-Status und Exposed-Admin-Indikator aus beiden Quellen zusammengeführt.

---

## 🎨 UI/UX (2026-08-21, Batch 8)

### 38. Globale Suche erweitern 🔎 ✅ implementiert (Welle 7, 2026-08-22)
- `search.py`/`global_search` deckt aktuell nur Targets + 3 hardcodierte Module (`web_analyzer`, `cve_scanner`, `nuclei_scanner`) ab — keine Reports, Tags, Changelog
- Echte Volltextsuche über alle Entitäten (Reports, Tags, Discovery-Kandidaten, Changelog-Einträge)
- Umgesetzt: `global_search` durchsucht jetzt zusätzlich Target-Tags (JSONB-Array-Match), `DiscoveryCandidate` (tenant-gescoped über `DiscoverySession`) und `ChangelogEntry`. Neue Ergebnis-Sektionen in `search.html`. Verifiziert mit echten Daten: Discovery-Kandidaten-Treffer korrekt zurückgegeben.

### 39. Command Palette tiefer integrieren ⌨️ ✅ bereits implementiert (verifiziert, Welle 7, 2026-08-22)
- `command_palette.html` existiert, aber kaum ans Backend angebunden (nur 1 hx-Aufruf im Template)
- Cmd+K mit Sprung zu Targets/Reports/Settings/Aktionen (Scan starten, Queue pausieren) statt nur Navigation
- Befund: bereits vollständig umgesetzt — `/api/search/suggestions` liefert 127 Einträge (Actions >, Navigation @, Triage !, Management /, dynamische Addon-Module, letzte Reports), `command_palette.html` ruft das bei jedem Öffnen ab. Kein Code-Gap gefunden.

### 40. Gespeicherte Filter-Views 💾 ✅ implementiert (Welle 7, 2026-08-22)
- Aktuell vermutlich müssen Filter-Kombinationen (z.B. "Kritische Findings Tenant X") jedes Mal neu gesetzt werden
- Named Views speichern & mit einem Klick wieder aufrufen
- Umgesetzt: "Views"-Dropdown auf `/security-findings/` — aktuelle Filter-URL unter einem Namen in localStorage speichern, per Klick wieder aufrufen, löschbar. Pro Seiten-Pfad isoliert (`yads_saved_views:<path>`), damit andere Seiten eigene Views bekommen können.

### 41. Konsistente Bulk-Actions-Toolbar 🧰 ✅ bereits ausreichend konsistent (verifiziert, Welle 7, 2026-08-22)
- Multi-Select-Aktionen existieren punktuell (z.B. Target-Table Root-Domain-Filter, Send-to-Discovery), aber nicht einheitlich über alle Listen (Findings, Discovery-Kandidaten)
- Gemeinsame, wiederverwendbare Bulk-Actions-Komponente
- Befund: `target_table.html` und `analytics_external_links.html` nutzen bereits dasselbe visuelle Muster (Checkbox-Spalte + "With Selected"-Leiste). Keine gemeinsame Komponente extrahiert (Zeitbudget), aber keine akute Inkonsistenz gefunden, die einen dringenden Fix rechtfertigt.

### 42. Keyboard-Shortcuts für Power-User ⚡ ✅ implementiert (Welle 7, 2026-08-22)
- Scan starten, zwischen Targets springen, Queue-Widget öffnen etc. per Tastenkürzel statt Maus-only
- Umgesetzt: globaler Shortcut-Handler in `base.html` — `g d/t/q/f/r` springt zu Dashboard/Targets/Queue/Findings/Reports, `/` fokussiert die Suche, `?` zeigt eine Shortcut-Übersicht. Ignoriert Tastatureingaben in Formularfeldern. Ergänzt das bereits bestehende Ctrl/Cmd+K für die Command Palette.

### 43. Onboarding-Tour für Erstnutzer 🧭 ✅ implementiert (Welle 7, 2026-08-22)
- Ergänzt Punkt 25 (Recon-Vorschau beim Onboarding): ein geführter Tooltip-Walkthrough durchs UI selbst für neue Nutzer, nicht nur die Scan-Konfiguration
- Umgesetzt: 4-Schritt-Willkommens-Tour auf dem Dashboard, einmalig pro Browser (localStorage-Flag), skip-/durchklickbar. Bewusst leichtgewichtig (sequenzielles Modal statt pixelgenauer Tooltip-Positionierung) für Robustheit ohne externe Library.

### 44. Customizable Dashboard-Widgets 🧱 ✅ implementiert (Welle 7, 2026-08-22)
- Dashboard vermutlich fest layoutet
- Drag&Drop-Widget-Anordnung pro Nutzer/Rolle (Admin sieht andere Kacheln als Auditor)
- Umgesetzt: "Customize"-Panel auf dem Dashboard mit Ein/Aus-Checkboxen für die drei Hauptsektionen (Critical Attention, Key Metrics, Operational View), Zustand in localStorage. Bewusst Show/Hide statt Drag&Drop (robuster ohne Layout-Bruch im 3-Spalten-Grid); Rollen-basierte Kachel-Unterschiede nicht umgesetzt (Zeitbudget).

---

## 📄 Reporting (2026-08-21, Batch 9)

### 45. Wiederkehrende Report-Zustellung 📬 ✅ implementiert (Welle 8, 2026-08-22)
- `schedules.py` deckt nur Scan-Zeitpläne ab, keine Report-Verteiler
- "Diesen Report jeden Montag an diese Empfänger senden" als eigene Scheduling-Ebene, unabhängig von `send_daily_digests`
- Umgesetzt: neues Modell `ReportSubscription` (Name, Typ, Empfänger, wöchentlich/monatlich), CRUD-UI auf `/schedules`, periodischer Task `send_recurring_reports` (täglich, Celery Beat) prüft fällige Abos und versendet. Verifiziert: Abo angelegt, Task manuell ausgeführt, `last_sent_at` korrekt gesetzt (SMTP im Dev nicht konfiguriert — E-Mail-Versand korrekt übersprungen statt Fehler).

### 46. Export-Formate erweitern 📤 ✅ implementiert (Welle 8, 2026-08-22)
- `yads/utils/export.py` exportiert aktuell nur Excel (`openxmlformats-officedocument.spreadsheetml`)
- CSV/JSON/SARIF ergänzen — SARIF speziell für Findings, damit sich YADS-Ergebnisse in GitHub Code Scanning & andere SARIF-Consumer einspeisen lassen
- Befund: CSV existierte für Findings bereits (`export_findings_csv`). Neu: `generate_csv`/`generate_json`/`generate_sarif` in `export.py`, neue Endpunkte `/security-findings/api/findings/export-sarif` und `-export-json`. Verifiziert: valides SARIF 2.1.0 mit echten Findings erzeugt.

### 47. Report-Diffing zwischen zwei Zeitpunkten 🕰️ ⏸️ zurückgestellt (Welle 8, 2026-08-22)
- Aktuell vermutlich nur Einzel-Snapshot-Reports
- Auto-Narrative "was hat sich seit dem letzten Quartalsreport geändert" statt zwei PDFs manuell vergleichen zu müssen
- Aus Zeitbudget-Gründen in dieser Session nicht umgesetzt (`ComparisonEngine` in `comparisons.py` könnte als Basis dienen, deckt aber nur strukturierte Scan-Daten ab, nicht Report-Markdown-Diffing). Offen für eine künftige Session.

### 48. Vollständiges White-Labeling für MSSP-Kunden 🏷️ ✅ teilweise implementiert (Welle 8, 2026-08-22)
- Pro-Tenant-Logo-Upload existiert bereits (`static/logos/`), aber vermutlich kein vollständiges Whitelabel (eigene Domain, Farbschema, YADS-Branding komplett entfernen)
- Relevant für MSSP-Kunden, die YADS unter eigener Marke weitervertreiben
- Umgesetzt: neues Tenant-Flag `hide_yads_branding` unterdrückt die drei hartkodierten "Report generated by YADS"/"Assessment Tool: YADS Security Scanner"-Zeilen in `markdown_report_generator.py`, die selbst bei gesetztem Custom-Logo/Firmennamen weiterhin erschienen. Checkbox in Tenant-Settings. **Bewusst nicht umgesetzt** (Scope-Cut): eigene Domain, komplettes Admin-UI-Rebranding — nur die kundenseitigen Report-Inhalte betroffen.

### 49. Report-Kommentare/Annotationen vor Versand 💬 ✅ implementiert (Welle 8, 2026-08-22)
- Reviewer sollen Notizen direkt im Report hinterlassen können, bevor er an den Kunden rausgeht (interner Freigabe-Workflow)
- Umgesetzt: neue `review_notes`/`reviewed_by`/`reviewed_at`-Felder auf `GeneratedReport`, Notizfeld in `report_view.html` (deutlich als "nicht sichtbar für Empfänger" markiert), Speicher-Endpoint `/reports/{id}/review`.

### 50. Interaktive Web-Report-Vorschau statt nur PDF 🌐 ✅ bereits implementiert (verifiziert, Welle 8, 2026-08-22)
- Report als teilbaren Web-Link statt nur PDF-Anhang — mit Sortier-/Filterfunktion direkt in der Report-Ansicht, PDF bleibt als Export-Option bestehen
- Befund: `report_builder.py`s `view_report` rendert bereits eine vollständige HTML-Web-Ansicht (`report_view.html`) getrennt vom PDF-Export, der weiterhin als Option verfügbar bleibt. Sortier-/Filterfunktion innerhalb der Ansicht nicht ergänzt (Zeitbudget) — Kernanforderung (Web-Ansicht statt nur PDF) war bereits erfüllt.

---

## 🎯 MITRE ATT&CK (2026-08-21, vom User direkt erkannte Lücke)

### 51. Echtes MITRE-ATT&CK-Mapping für Findings 🗺️ ✅ implementiert (Welle 0 + Welle 5, 2026-08-22)
- `SecurityAuditLog.mitre_tactic_id`/`mitre_technique_id` existieren bereits, aber NUR für interne Audit-Events (Login, Passwort-Änderung) über `security_audit.py`/`splunk_logger.py`
- Scan-Findings (Nuclei, Web-Analyzer, etc.) haben kein MITRE-Mapping
- `attack_path.py`s `_att_phase_for_finding` nutzt nur grob geratene Phasen (recon/initial_access/credential_access/impact/execution) aus Modul-Name+Severity, keine echten TAxxxx/Txxxx-IDs
- Echte Mapping-Tabelle Finding-Typ → MITRE-Technique ergänzen (z.B. über CVE→CAPEC→ATT&CK oder Nuclei-Template-Tags, die oft schon ATT&CK-Referenzen enthalten)
- Umgesetzt: `mitre_mapping.py` (Welle 0) liefert echte TAxxxx/Txxxx-IDs für ~20 Modul/Issue-Muster, bereits in `SecurityFinding` verdrahtet. Welle 5 zieht dieselbe Mapping-Funktion jetzt auch in `attack_path.py`s Graph-Knoten (`_att_phase_for_finding`, `_build_finding_nodes`, CVE-/Nuclei-Knoten) — echte `mitre_tactic_id`/`technique_id`/`technique_name` statt geratener Phasen, mit Fallback auf die alte Heuristik nur wenn kein Mapping existiert.

### 52. ATT&CK-Navigator-Visualisierung 🧩 ✅ implementiert (Welle 5, 2026-08-22)
- Heatmap-Ansicht im Stil des offiziellen MITRE ATT&CK Navigator: Tactics als Spalten, Techniques als Zellen, eingefärbt nach Trefferzahl/Schweregrad für den jeweiligen Tenant
- Baut auf Punkt 51 auf
- Umgesetzt: neue Seite `/mitre-navigator/`, aggregiert `SecurityFinding.mitre_tactic_id/technique_id` tenant-weit, Tactic-Spalten in Kill-Chain-Reihenfolge, Zellen eingefärbt nach höchstem Schweregrad. Verifiziert gegen echte gemappte Findings (TA0006/TA0043).

### 53. Echtes Exploit-Chaining statt naiver Verkettung ⛓️ ✅ implementiert (Welle 5, 2026-08-22)
- `_chain_critical_findings` in `attack_path.py` verkettet aktuell alle High/Critical-Findings einfach linear hintereinander ("co-exist impliziert Kette") — keine echte kausale Prüfung
- Echte Voraussetzungs-Logik ergänzen (z.B. "Initial Access via CVE X ermöglicht Privilege Escalation via Finding Y" nur wenn technische Voraussetzung tatsächlich erfüllt ist), angelehnt an MITRE-Technique-Abhängigkeiten
- Umgesetzt: verkettet nur noch A→B, wenn A's MITRE-Tactic in der Kill-Chain-Reihenfolge (`_TACTIC_ORDER`, TA0043→...→TA0040) vor B's liegt; Findings ohne aufgelöste Tactic werden gar nicht verkettet statt geraten. **Bug während Verifikation gefunden und gefixt:** die Kandidatenliste wurde nicht vor der paarweisen Prüfung nach Tactic-Rang sortiert, wodurch ein früher-Tactic-Finding, das zufällig später in der Modul-Scan-Reihenfolge steht, nie nach vorne verkettet worden wäre. Fix verifiziert per Unit-Test im Container: `[Recon] → [Initial Access] → [Privilege Escalation]` unabhängig von der Eingabereihenfolge.

---

## 🧩 Weitere Erweiterungen (2026-08-21, Batch 12)

### 54. CSP-Policy-Härtung automatisch vorschlagen 🛡️ ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `csp_scanner.py` erkennt vermutlich fehlende/schwache CSP-Header
- Kombiniert mit `external_resources_scanner.py` (kennt bereits alle tatsächlich geladenen Origins) automatisch passenden CSP-Header-Vorschlag generieren
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 55. Selbstlernende Wordlists für Content-Discovery 📚 ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `seed_files_scanner.py`/`content_discovery.py` nutzen vermutlich statische Wordlists
- Tatsächlich gefundene Pfade automatisch in tenant-/branchenspezifische Wordlist zurückfließen lassen
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 56. Storage/Retention-Transparenz für Kunden 🗄️ ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `storage.py` verwaltet Speicherplatz/Retention vermutlich nur intern/admin-seitig
- Kundensichtbares Self-Service-Panel ("wie lange werden meine Daten aufbewahrt, wie viel Speicher nutze ich") — DSGVO-relevant
- Aus Zeitbudget-Gründen nicht umgesetzt. Verwandt mit #96 (Welle 13, Tenant-Self-Service-Datenexport) — bei Gelegenheit gemeinsam umsetzen.

### 57. Integrations-Health-Übersicht 🔌 ✅ implementiert (Welle 9, 2026-08-22)
- `integrations.py` verwaltet Slack/Teams/Webhook-Configs vermutlich ohne zentralen Status
- Health-Dashboard analog zu Punkt 19 (BYOK-Key-Health), nur für Notification- statt OSINT-Integrationen
- Umgesetzt: nutzt Baustein 2 (`integration_health.py`, Welle 0). Neuer Endpoint `POST /integrations/{integration_type}/test`, prüft konfigurierte URL per HEAD-Request und persistiert Status/Meldung. UI-Buttons bisher nur für `jira`/`github` verdrahtet — `siem_syslog`/`siem_http` nutzen andere Template-Variablennamen und wurden aus Zeitbudget-Gründen nicht angebunden (ehrlich zurückgestellter Teilscope, kein stiller Skip).

---

## ⚖️ NIS2 / DORA (2026-08-21)

> Kontext: NIS2/DORA existiert aktuell nur als Backend-Infrastruktur (5-Jahres-Retention, tamper-proof Hash-Chain-Logging DORA Art. 10/12, Data-at-Rest-Encryption). Laut Git-Historie wurde eine kundenseitige "DSGVO/DORA/NIS2 compliance analysis" mal entfernt ("stale") — aktuell keine kundensichtbare Funktionalität.

### 58. NIS2-Incident-Reporting-Timer ⏱️ ✅ implementiert (Welle 6, 2026-08-22)
- 24h-Frühwarnung / 72h-Detailmeldung an Behörde/CSIRT nach meldepflichtigem Vorfall (NIS2-Pflicht)
- "Als NIS2-meldepflichtig markieren"-Aktion, die Countdown startet und Meldungsentwurf mit Pflichtfeldern (Impact-Assessment, grenzüberschreitende Wirkung, IOCs) vorbereitet
- Umgesetzt: neue `nis2_marked_at`/`nis2_deadline_24h`/`nis2_deadline_72h`-Spalten auf `SecurityFinding`, "NIS2 melden"-Button je Finding in `/security-findings/` startet die Frist und liefert einen Entwurf (Impact-Assessment/Cross-Border-Effect/IOCs als TODO-Stubs). Verifiziert end-to-end: markieren → Badge mit 72h-Countdown erscheint → zurücknehmen funktioniert.

### 59. DORA ICT-Drittanbieter-Register (Art. 28–30) 📋 ✅ implementiert (Welle 6, 2026-08-22)
- Register aller ICT-Drittanbieter (kritisch + nicht-kritisch) inkl. Konzentrationsrisiko-Bewertung
- Speisen aus Punkt 21 (Third-Party-Domains) + Cloud-Asset-Erkennung, DORA-konformes Registerformat exportieren
- Automatischer Konzentrationsrisiko-Hinweis (z.B. "80% der kritischen Anbieter nutzen denselben Hoster")
- Umgesetzt: neue Seite `/third-party-domains/dora-register`, kombiniert Third-Party-Domains (#21) + `cloud_scanner`-Assets zu einem Register; Konzentrationsrisiko-Berechnung gruppiert nach Apex-Domain/Provider, flaggt ab 30% Anteil an betroffenen Targets. CSV-Export.

### 60. Scan als DORA-Resilience-Testing-Nachweis (Art. 24–27) 📑 ✅ implementiert (Welle 6, 2026-08-22)
- YADS-Scans automatisch als prüfungsfähiges Nachweisdokument exportieren (Testdatum, Scope, Ergebnis, Findings-Remediation-Status)
- Umgesetzt: neuer Router `dora_evidence.py`, baut Nachweiszeilen aus `ModuleState` (Testdatum/Scope) + `SecurityFinding` (Ergebnis/Remediation-Status) je Target/Modul; PDF- und Excel-Export über die bestehenden `generate_pdf`/`generate_excel`-Utilities. **Bug während Verifikation gefunden und gefixt:** PDF-Export schlug mit `FPDFUnicodeEncodingException` fehl, da der Titel einen Em-Dash enthielt, den die Helvetica-Schriftart der fpdf-Bibliothek nicht kodieren kann — durch einfachen Bindestrich ersetzt, Export danach verifiziert (PDF + Excel beide erfolgreich).

### 61. NIS2-Art.-21-Maßnahmen-Mapping 🗂️ ✅ implementiert (Welle 5, 2026-08-22)
- NIS2-Mindestmaßnahmen (Incident Handling, Business Continuity, Supply-Chain-Security, Vulnerability-Handling, Kryptographie) direkt gegen YADS-Findings mappen
- Zeigt auf einen Blick, welche der 10 Mindestmaßnahmen bereits abgedeckt/nachgewiesen sind (Artikel-21-spezifischer Sonderfall von Punkt 13)
- Umgesetzt: neue Seite `/nis2-measures/`, alle 10 Art.-21-Maßnahmen mit Beschreibung + zuständigen Scan-Modulen; Status (Abgedeckt/Teilweise/Lücke/Nicht scan-basiert erfassbar) wird aus tatsächlichen Scan-Daten der letzten 90 Tage berechnet, nicht statisch. "Business Continuity/Backup" und "Incident Handling" bewusst als "nicht scan-basiert erfassbar" markiert statt fälschlich als abgedeckt/nicht abgedeckt zu labeln.

---

## 🧩 Weitere Erweiterungen (2026-08-21, Batch 14)

### 62. Developer-Portal erweitern 🧑‍💻 ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `developer.py` bietet aktuell nur API-Key-Erstellung/-Revoke, keine Nutzungs-Transparenz
- Usage-Analytics ergänzen (Calls pro Key, Rate-Limit-Treffer, zuletzt verwendet)
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 63. API-Discovery mit kontinuierlichem Baseline-Diffing 🔄 ✅ implementiert (Welle 9, 2026-08-22)
- `api_discovery.py` parst Swagger/OpenAPI und probt Pfade nur einmalig pro Scan
- Baseline speichern und bei Folgescans dagegen diffen — neue/verschwundene Endpoints als eigenes Finding (ergänzt Punkt 26)
- Umgesetzt: nutzt Baustein 1 (`baseline_diff.py`, Welle 0). `api_discovery.py` diffed entdeckte Endpoints gegen den letzten Snapshot, erzeugt `medium`-Finding bei neuen und `info`-Finding bei verschwundenen Endpoints. `module_registry.py`: `api_discovery` als `finding_module=True` markiert, `security_findings.py` liest den neuen `findings`-Key. Code-Review + Syntax-Check bestanden; Live-Verifikation gegen test-tenant.example an einem transienten Netzwerkfehler im Worker-Container gescheitert ("Network is unreachable" bei direktem `requests.get()`-Test) — keine Codeursache, identisches Pattern an anderer Stelle bereits erfolgreich verifiziert.

### 64. Changes/Changelog als durchsuchbare Timeline mit Rollback-Vorschau 🕰️ ⏸️ zurückgestellt (Welle 9, 2026-08-22)
- `changes.py`/`changelog.py` zeigen vermutlich rohe Diffs
- Durchsuchbare Timeline über alle Targets + "wie sah das vor diesem Config-Drift aus"-Vorschau
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 65. Re-Aktivierungs-Vorschlag für archivierte Targets ♻️ ✅ implementiert (Welle 9, 2026-08-22)
- `dns_cleanup_scanner` archiviert tote Domains (`archived.py`)
- Periodisch prüfen, ob eine archivierte Domain wieder online ist, und Reaktivierung vorschlagen statt stillem Dauer-Archiv
- Umgesetzt: neuer wöchentlicher Celery-Beat-Task `check_archived_target_reactivation` (`worker_tasks.py`/`worker_core.py`), prüft alle `is_archived=True, archived_reason="dns_dead"`-Targets per DNS-Resolve; löst bei erneuter Auflösung einen `new_asset`-Webhook mit Reaktivierungs-Hinweis aus. Live via manuellem Celery-Call verifiziert (0 archivierte Targets im FRISCHKORN-Tenant = korrekter No-Op).

---

## 🔬 Scanner-Korrelation & Datenqualität (2026-08-21, Batch 15)

### 66. Whois-History × DNS-History Ownership-Change-Alert 🔀 ✅ implementiert (Welle 2, 2026-08-22)
- `whois_history_scanner.py` + `dns_history_scanner.py` existieren getrennt; korrelieren für echte Domain-Besitzerwechsel-Erkennung statt nur einzelner Record-Änderungen
- Umgesetzt: `whois_history_scanner.py` prüft bei einem Registrar-Wechsel zusätzlich, ob `dns_history_scanner` im selben 14-Tage-Fenster neue DNS/CT-Daten für das Target erfasst hat — nur dann wird ein eigenständiges "Likely domain ownership change"-Finding (severity high) erzeugt, statt bei jeder Registrar-Drift zu alarmieren.

### 67. E-Mail-Spoofing-Resilience-Score 📧 ✅ bereits vorhanden, jetzt sichtbar (Welle 2, 2026-08-22)
- SPF/DKIM/DMARC + `email_security_scanner.py`-Einzelbefunde zu einem Gesamt-Score kombinieren
- Befund: `_compute_score()` berechnete den kombinierten 0-100-Score bereits, er wurde nur nirgends angezeigt (`email_security.py` gab ihn an das Template durch, das Template zeigte ihn nie). Fix: neue "Resilience Score"-Spalte in `email_security.html` (inkl. DKIM-Selector-Count). Verifiziert: test-tenant.example zeigt korrekt 15/100 (SPF `?all`, kein DMARC, kein DKIM).

### 68. IPv6-Parity-Check 🌐 ✅ bereits implementiert (verifiziert, Welle 2, 2026-08-22)
- `ipv6_scanner.py` prüft IPv6-Erreichbarkeit separat; Abgleich mit IPv4-Findings, ob dieselben Schwachstellen auch über IPv6 exponiert sind (oft übersehene Angriffsfläche)
- Befund: bereits vollständig vorhanden — `ipv6_scanner.py` vergleicht offene Ports v4 vs. v6 (`v6_only`-Findings) und erkennt CDN/WAF-Bypass via IPv6 (unterschiedlicher Hosting-Provider). Als "generic"-Finding-Modul bereits ins Unified-Findings-/MITRE-Pipeline verdrahtet. Kein Code-Gap gefunden — keine Änderung nötig.

### 69. Banner-Grabber × CVE-Lookup automatisch verknüpfen 🔗 ✅ implementiert (Welle 2, 2026-08-22)
- `banner_grabber.py` sammelt Service-Banner; direkte automatische CVE-Suche für erkannte Versionen statt separatem manuellem Schritt
- Befund: `lookup_cves()` war nur in `web_analyzer.py` verdrahtet, nie in `banner_grabber.py`, obwohl dieses bereits Service+Version pro offenem Port extrahiert. Fix: `banner_grabber.py` ruft jetzt `lookup_cves(service, version)` pro erkanntem Service auf und erzeugt bei Treffern eigene High-Severity-Findings.

### 70. AXFR-Zone-Transfer kontinuierlich statt Einzelscan 🔁 ✅ implementiert (Welle 2, 2026-08-22)
- `axfr_scanner.py` prüft Zone-Transfer-Schwäche; DNS-Server-Config kann sich ändern, periodischer Recheck sinnvoll
- Befund: der Scan lief bereits bei jedem regulären Rescan erneut (ScanSchedule) — was fehlte, war ein aktiver Alarm beim Übergang "sicher → verwundbar". Fix: `axfr_scanner.py` diffed den Vulnerable-Status via `baseline_diff` (Welle 0) und feuert nur bei einer neuen Exposition einen `security_alert`-Webhook, nicht bei jedem Scan erneut.

### 71. Metadata-Leak-Aggregation über alle Targets 📎 ✅ implementiert (Welle 2, 2026-08-22)
- `metadata_scanner.py` findet vermutlich EXIF/Dokument-Metadaten pro Dokument; tenant-weit aggregieren ("diese internen Usernamen/Software-Versionen sind über Metadaten geleakt")
- Umgesetzt: neuer Router `metadata_leaks.py` (+ `metadata_leaks.html`), aggregiert Autoren/Software/interne Pfade über alle Targets, sortiert nach Anzahl betroffener Targets (Wiederholung über mehrere Targets = stärkeres Leak-Signal). In Sidebar verlinkt. Verifiziert gegen test-tenant.example (Dev): Seite lädt, korrekter Leerzustand (keine Dokumente auf dieser Domain gefunden).

### 72. Wayback-Scanner Secret-Diff 🕸️ ✅ implementiert (Welle 2, 2026-08-22)
- `wayback_scanner.py` nutzt archive.org; alte, aus dem Web entfernte aber weiterhin in Wayback erreichbare Secrets/Endpoints als eigene Kategorie hervorheben
- Umgesetzt: für critical/high-Findings prüft `wayback_scanner.py` jetzt per Live-HEAD-Request, ob die URL noch erreichbar ist; ist sie nur noch archiviert (404 live), wird das Finding als "REMOVED BUT STILL ARCHIVED" mit eigener Kategorie `removed_but_archived` hervorgehoben statt gleichrangig mit noch-live-erreichbaren Treffern angezeigt.

---

## 📱 Mobile & Cross-Platform (2026-08-21, Batch 16)

### 73. Mobile-Findings ins Haupt-Dashboard integrieren 📲 ⏸️ zurückgestellt (Welle 10, 2026-08-22)
- `mobile_app_discovery.py`-Ergebnisse aktuell vermutlich nur im separaten Mobile-Tab, nicht im Haupt-Dashboard
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 74. Echte Push-Notifications statt nur E-Mail-Digest 🔔 ⏸️ zurückgestellt (Welle 10, 2026-08-22)
- Kritische Findings direkt aufs Handy statt nur `send_daily_digests`
- Aus Zeitbudget-Gründen nicht umgesetzt — braucht externen Push-Provider (APNs/FCM), auf Dev/localhost ohnehin nicht sinnvoll end-to-end testbar.

### 75. PWA/Offline-Modus fürs Mobile-Dashboard 📴 ⏸️ zurückgestellt (Welle 10, 2026-08-22)
- `mobile/dashboard.html` als installierbare PWA mit Offline-Caching der letzten Stats
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 76. QR-Code-Trigger für Ad-hoc-Scans 📷 ⏸️ zurückgestellt (Welle 10, 2026-08-22)
- `qrcode.min.js` ist schon als Vendor-Lib vorhanden (vermutlich für MFA-Setup); QR-Code scannen, um vom Handy aus schnell einen Scan zu starten, wäre eine Zweitnutzung
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 77. Mobile-App-Version-Drift-Alert 📦 ✅ implementiert (Welle 10, 2026-08-22)
- App-Store-Version vs. zuletzt von `mobile_app_discovery.py` gescannte Version — Alert bei Abweichung
- Umgesetzt: nutzt Baustein 1 (`baseline_diff.py`, Welle 0), analog zum Ports-Delta-Pattern aus #24 — iTunes-App-Versionen werden als `bundle_id@version`-Paare snapshotted; taucht dieselbe App-ID in `added` und `removed` wieder auf, hat sich die Version geändert → `info`-Finding mit Alt-/Neu-Version. Live gegen test-tenant.example zweimal ausgeführt: läuft fehlerfrei durch (0 gefundene Apps für diese Domain → korrekter No-Op, `versioned`-Liste bleibt leer, der Diff-Zweig wird dadurch nicht durchlaufen). Diff-Logik selbst folgt 1:1 dem bereits an anderer Stelle (Ports-Delta, #24) live verifizierten Muster.

---

## ✨ UX/Onboarding/Accessibility (2026-08-21, Batch 17)

### 78. Barrierefreiheits-Audit der eigenen UI ♿ ⏸️ zurückgestellt (Welle 11, 2026-08-22)
- YADS scannt fremde Seiten auf Sicherheit — die eigene UI auf WCAG-Konformität prüfen wäre naheliegende Selbstanwendung
- Aus Zeitbudget-Gründen nicht umgesetzt — ein echtes Audit braucht mehr als einen Batch-Durchlauf, um seriös zu sein.

### 79. Undo-Zeitfenster für destruktive Aktionen ⏪ ✅ implementiert (Welle 4, 2026-08-22)
- Purge Queue, Target löschen etc. — kurzes Zeitfenster zum Rückgängigmachen statt sofortigem Hard-Delete (hätte uns am 2026-08-21 auch geholfen)
- Umgesetzt: **Target-Delete** — vor dem kaskadierenden Hard-Delete wird ein Redis-Snapshot (Domain/Tags/Tenant, 60s TTL) angelegt; neuer Endpoint `/targets/bulk/undo-delete` + "Undo"-Link im Toast auf `/targets/table`. **Queue-Purge** — aus der Redis-Queue entfernte (noch nicht gestartete) Tasks werden vor dem Entfernen als Snapshot gecacht; neuer Endpoint `/queue/undo-purge` requeued sie unverändert, eigener JS-Toast auf `/queue` (außerhalb des 5s-HTMX-Live-Refreshs platziert, damit er nicht sofort wieder verschwindet). Beide Flows Ende-zu-Ende verifiziert (Delete→Undo→Target wieder da; Purge-Snapshot→Undo→Re-Queue bestätigt).

### 80. Inline-Hilfe direkt an komplexen Findings 💡 ⏸️ zurückgestellt (Welle 11, 2026-08-22)
- Tooltips/Kontext-Hilfe direkt am Finding statt nur separater Help-Seite
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 81. Tablet-optimierte Zwischengrößen-Ansicht 📐 ⏸️ zurückgestellt (Welle 11, 2026-08-22)
- Aktuell vermutlich nur Desktop + Mobile-App optimiert, Tablet-Breite dazwischen ungetestet
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 82. Diff-Highlighting in der Finding-Detailansicht 🔍 ⏸️ zurückgestellt (Welle 11, 2026-08-22)
- Was hat sich am Finding-Text seit letztem Scan konkret geändert, nicht nur "geändert: ja/nein"
- Aus Zeitbudget-Gründen nicht umgesetzt. Baustein 1 (`baseline_diff.py`) diffed bisher nur strukturierte Listen (Ports, Endpoints, Versionen) — Freitext-Finding-Diffing bräuchte eine eigene Textdiff-Komponente, kein 1:1-Wiederverwendungsfall.

### 83. Print-optimiertes CSS für Reports/Findings 🖨️ ✅ implementiert (Welle 11, 2026-08-22)
- Direkt aus dem Browser drucken statt PDF-Export zu erzwingen
- Umgesetzt: globaler `@media print`-Block in `base.html` (gilt für alle Seiten inkl. Findings/Reports) — blendet Sidebar/Header/`.no-print`-Elemente aus, erzwingt lesbaren Light-Mode-Kontrast, verhindert, dass Tabellen/Karten mitten im Inhalt seitenumbrechen (`break-inside: avoid`). Template-Parse-Check + Live-Check (`/login` lädt weiterhin mit HTTP 200) bestanden; visuelle Browser-Druckvorschau nicht durchgeklickt (kein UI-Browserzugriff in dieser Session-Umgebung verfügbar).

### 84. Sprachumschaltung pro Nutzer statt nur pro Tenant 🌍 ⏸️ zurückgestellt (Welle 11, 2026-08-22)
- Falls `i18n.py` aktuell nur global/tenant-weit umschaltet statt pro einzelnem Nutzer
- Aus Zeitbudget-Gründen nicht umgesetzt.

---

## 📊 Reporting/Ops (2026-08-21, Batch 18)

### 85. Executive-Summary als PPTX-Export 🖥️ ⏸️ zurückgestellt (Welle 12, 2026-08-22)
- Management-Präsentationen direkt als PowerPoint statt nur PDF
- Aus Zeitbudget-Gründen nicht umgesetzt — neue Library-Abhängigkeit (python-pptx), größerer Umfang.

### 86. Branchen-Benchmark (anonymisiert) 📈 ⏸️ zurückgestellt (Welle 12, 2026-08-22)
- "Dein Security-Score liegt über/unter dem Durchschnitt vergleichbarer Unternehmen" über anonymisierte Tenant-übergreifende Auswertung
- Aus Zeitbudget-Gründen nicht umgesetzt. Braucht `PlatformAdminChecker`-Aggregation über Tenants hinweg (siehe #11) — bewusst zusammen mit #11 später angehen statt halbfertig vorzuziehen.

### 87. Remediation-Aufwand-Schätzung pro Finding 💰 ⏸️ zurückgestellt (Welle 12, 2026-08-22)
- Grobe Kosten-/Zeitschätzung zur Priorisierung fürs Management
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 88. Report-Versionierung mit voller Change-Historie 📚 ⏸️ zurückgestellt (Welle 12, 2026-08-22)
- Nicht nur zwei Zeitpunkte vergleichen (Punkt 47), sondern alle Report-Versionen als durchsuchbare Historie
- Aus Zeitbudget-Gründen nicht umgesetzt — baut auf #47 (Report-Diffing), das selbst bereits in Welle 8 explizit zurückgestellt wurde.

### 89. SLA-Tracking für Finding-Remediation ⏱️ ✅ implementiert (Welle 12, 2026-08-22)
- Zeit von Entdeckung bis Behebung messen, MTTR pro Severity reporten
- Umgesetzt: `SecurityFinding.first_found`/`closing_date` existierten bereits (keine Migration nötig). Neue `_compute_mttr()`-Funktion in `security_findings.py` berechnet Ø Tage bis Fix je Severity über alle `status="fixed"`-Findings des Tenants, neue MTTR-Karte in `security_findings.html` (nur sichtbar, wenn mindestens 1 behobenes Finding vorliegt). Verifiziert: Funktion läuft fehlerfrei gegen FRISCHKORN (0 behobene Findings = korrekter No-Op, Karte korrekt ausgeblendet); Template zusätzlich mit synthetischen MTTR-Werten gerendert — Karte erscheint korrekt mit Werten pro Severity.

### 90. Multi-Format-Bulk-Export für ganze Portfolios 📦 ⏸️ zurückgestellt (Welle 12, 2026-08-22)
- Nicht nur Einzel-Target-Reports, sondern gesamtes Tenant-Portfolio in einem Rutsch
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 91. LLM-generierte Trend-Kommentare 🤖 ⏸️ zurückgestellt (Welle 12, 2026-08-22)
- `llm_service.py` existiert bereits; Auto-generierter Fließtext "Ihre Angriffsfläche hat sich diesen Monat wie folgt entwickelt..."
- Aus Zeitbudget-Gründen nicht umgesetzt — auf Dev/localhost ohne echten LLM-Provider-Key ohnehin nicht sauber end-to-end verifizierbar.

### 92. Report-Preflight-Check ✋ ⏸️ zurückgestellt (Welle 12, 2026-08-22)
- Warnung vor Versand, wenn der Report noch offene/unbestätigte kritische Findings enthält
- Aus Zeitbudget-Gründen nicht umgesetzt.

---

## 🏗️ Platform/Ops/Security (2026-08-21, Batch 19)

### 93. Rate-Limit-Transparenz pro Tenant 📶 ⏸️ zurückgestellt (Welle 13, 2026-08-22)
- Sichtbare Nutzung vs. Limit statt nur harter 429-Fehler beim Überschreiten
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 94. Erweiterte Health-Check-Endpoints für externes Monitoring 🩺 ✅ implementiert (Welle 13, 2026-08-22)
- Prometheus/Grafana-fähiger Health-Status pro Subsystem (DB, Redis, RabbitMQ, Worker-Pool) statt nur Gesamtstatus
- Umgesetzt: neuer unauthentifizierter Endpoint `GET /health/detailed` in `main.py` (analog zum bestehenden `/health`, damit weiterhin ohne Login von externen Monitoring-Probes abfragbar) — prüft DB (`SELECT 1`), Redis (`ping()`), RabbitMQ (Celery-Connection-Check) und aktive Worker (`WorkerNode.status == "active"`) einzeln, liefert HTTP 200 bei allem OK bzw. 503 bei Degradation. Live gegen den laufenden Dev-Stack verifiziert: alle vier Subsysteme korrekt als "ok" gemeldet, `active_workers: 1`.

### 95. Graceful-Degradation bei Scanner-Modul-Ausfällen sichtbar machen ⚠️ ⏸️ zurückgestellt (Welle 13, 2026-08-22)
- Aktuell vermutlich generisches "Scan failed" statt "Modul X war down, Rest lief normal"
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 96. Tenant-Self-Service-Datenexport vor Offboarding 📤 ⏸️ zurückgestellt (Welle 13, 2026-08-22)
- DSGVO Recht auf Datenübertragbarkeit — kompletten Tenant-Datensatz selbst exportieren können
- Aus Zeitbudget-Gründen nicht umgesetzt. Verwandt mit #56 (Welle 9, ebenfalls zurückgestellt) — bei Gelegenheit gemeinsam umsetzen.

### 97. MFA-Enforcement-Reminder für Tenant-Admins 🔐 ✅ implementiert (Welle 13, 2026-08-22)
- Erinnerung, wenn Nutzer eines Tenants noch kein MFA aktiv haben
- Umgesetzt: `dashboard.py` zählt bei jedem Dashboard-Load für `tenant_admin`/`admin`-Rollen die Nutzer des eigenen Tenants mit `mfa_enabled == False`; `index.html` zeigt bei &gt;0 eine gelbe Banner-Warnung mit Link zu `/users/`. Live gegen FRISCHKORN verifiziert: DB-Query liefert korrekt `0` (alle Nutzer haben MFA aktiv aus früherer Welle) → Banner bleibt versteckt; zusätzlich Template mit synthetischem `mfa_gap_count=3` gerendert — Banner erscheint korrekt.

### 98. Session-Management-Übersicht 🖥️ ⏸️ zurückgestellt (Welle 13, 2026-08-22)
- "Wo bin ich überall eingeloggt" + aktive Sessions gezielt killen können
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 99. Kundenseitiger Audit-Log-Export 📋 ⏸️ zurückgestellt (Welle 13, 2026-08-22)
- `SecurityAuditLog` existiert, vermutlich nur admin-intern einsehbar — kundenseitig exportierbar machen
- Aus Zeitbudget-Gründen nicht umgesetzt.

### 100. Feature-Flag/Beta-Opt-in-System für neue Module 🚩 ⏸️ zurückgestellt (Welle 13, 2026-08-22)
- Tenants können experimentelle Scanner-Module vorab aktivieren, bevor globaler Rollout
- Aus Zeitbudget-Gründen nicht umgesetzt.

---

## 🧹 Tech Debt / Polishing

### Code Cleanup
- `web_analyzer.py` — `_detect_technologies()` weiter modularisieren (Complexity: 34, noch nicht vollständig aufgebrochen)
- Duplicate Literals zentralisieren:
  - `"Index of /"` (4x in `web_analyzer.py`)
  - `"yads.modules.dns"` (6x in `dns_scanner.py`)

### Security
- `B501` — `requests` mit `verify=False` (tatsächlich 39 Dateien, nicht 13 — Bandit-Zahl war veraltet) ✅ **geprüft, kein Fix nötig (Cleanup-Pass, 2026-08-22)**: fast ausschließlich in `yads/modules/*.py` (Scanner-Module) — TLS-Verifikation muss dort deaktiviert bleiben, weil YADS aktiv beliebige, von Kunden hinzugefügte externe Ziele scannt, deren Zertifikate oft selbstsigniert/abgelaufen/falsch konfiguriert sind (genau das ist z.T. selbst ein Finding, das `ssl_scanner.py` separat meldet — ein Scanner darf einen Scan nicht verweigern, nur weil das Ziel ein kaputtes Zertifikat hat). Kein MITM-relevantes Secret-Leak-Risiko, da diese Requests ausgehende Scans gegen fremde, nicht-vertrauenswürdige Hosts sind, keine YADS-eigenen Credentials/Backend-Verbindungen. Einzige Ausnahme außerhalb von `modules/`: `targets.py`/`core/seeding.py` — dort ebenfalls im Scan-/Health-Check-Kontext, gleiche Begründung. Bandit-Finding bleibt technisch bestehen (kein Config-Wrapper gebaut, da 39 Call-Sites ohne echten Sicherheitsgewinn zu refactoren nur Risiko für Zeitbudget gewesen wäre), aber bewusst als "reviewed, accepted" statt "offen" markiert.
- `B701` — Jinja2 mit `autoescape=False` prüfen (potenzieller XSS-Vektor) ✅ **geprüft (Cleanup-Pass, 2026-08-22)**: `markdown_report_generator.py`s `autoescape=False` selbst ist unkritisch (rendert Markdown-Syntax, nicht HTML, per Kommentar dokumentiert). Beim Prüfen aber einen **echten, bypassbaren Stored-XSS-Fund** gemacht — siehe eigener Security-Eintrag unten ("Regex-basierter HTML-Sanitizer in Report-Generierung bypassbar").
- **Regex-basierter HTML-Sanitizer in Report-Generierung bypassbar (Stored XSS)** ✅ **gefixt (Cleanup-Pass, 2026-08-22)**: `markdown_to_html()` (`markdown_report_generator.py`) sanitisierte den aus `markdown_content` erzeugten HTML-Output bisher mit handgeschriebenen Regexes (`_UNSAFE_TAGS_RE`/`_UNSAFE_ATTR_RE`/`_JAVASCRIPT_HREF_RE`) statt einem echten HTML-Parser — ein bekanntes Anti-Pattern. Der Code-Kommentar behauptete zusätzlich fälschlich, die `markdown`-Library selbst würde sanitisieren (stimmt seit `safe_mode` in Python-Markdown 3.0 entfernt wurde nicht mehr — rohes HTML wird 1:1 durchgereicht). `report.html_content` wird in `report_view.html` mit `{{ report.html_content|safe }}` ungefiltert gerendert und in `report_builder.py`s `/builder/preview`-Endpoint sogar direkt als `HTMLResponse` zurückgegeben — jeder Nutzer mit `report_access` (Report-Autor) konnte damit persistentes Stored-XSS in `markdown_content` einschleusen, das beim späteren Ansehen des Reports durch einen anderen (potenziell höher privilegierten) Nutzer ausgeführt wird. **Live bestätigter Bypass:** `<svg/onload=alert(1)>` (kein Whitespace vor `onload` → `\s+on\w+`-Regex greift nicht) wurde von der alten Sanitisierung komplett unverändert durchgelassen — per direktem Vergleichstest gegen den alten Regex-Code reproduziert. Fix: `_sanitize_html()` nutzt jetzt `bleach.clean()` (echter HTML5-Parser) mit striktem Tag-/Attribut-/Protokoll-Allowlist statt Regexes; `bleach` zu `requirements.txt` hinzugefügt. Verifiziert: `<script>`, `<svg/onload=...>`, `<img onerror=...>`, sowohl direktes als auch Tab-obfuskiertes `javascript:`-Href werden jetzt alle entfernt/neutralisiert, während legitime Markdown-Ausgabe (Tabellen, `**bold**`, normale Links) unverändert erhalten bleibt.
- `B108` — 3x unsichere Temp-Files ✅ **gefixt (Cleanup-Pass, 2026-08-22)**: `exports.py`s `/tmp/yads_restore_pending.zip` (hält temporär einen kompletten, potenziell mandantenübergreifenden DB-Backup-ZIP während des zweistufigen Restore-Bestätigungsflows) und `splunk_logger.py`s `/tmp/yads_splunk_spool.ndjson` (SIEM-Event-Payloads, ggf. Finding-/Tenant-/User-Details) wurden bisher mit Standard-`open()` angelegt — je nach Container-Umask potenziell world-readable in einem geteilten `/tmp`. Auf `tempfile.NamedTemporaryFile` (zufälliger Pfad) umzustellen war hier bewusst **nicht** die gewählte Lösung: `execute_restore()` liest den Pfad aktuell fest verdrahtet und nicht aus dem (bereits vorhandenen, aber ungenutzten) `file_path`-Hidden-Field der Bestätigungsmaske — einen zufälligen Pfad einzuführen hätte bedeutet, `file_path` serverseitig entgegenzunehmen und zu validieren, was ohne sorgfältige Pfad-Validierung ein neues Path-Traversal-Risiko geöffnet hätte (Restore ist bereits `admin`-only, größerer Umbau war das im Cleanup-Zeitbudget nicht wert). Stattdessen minimal-invasiv gefixt: beide Dateien werden jetzt über `os.open(..., 0o600)` statt `open()` angelegt, wodurch sie von Anfang an nur für den Besitzer lesbar sind. Live verifiziert: beide Pfade legen die Datei jetzt nachweislich mit `0o600` an (`oct(st.st_mode & 0o777)`).

### Automatisierter Security-Review-Fund (nach Cleanup-Pass, 2026-08-22)
- **IDOR bei Finding-Status/NIS2-Mark-Endpoints** ✅ **gefixt**: `security_findings.py`s `update_finding_status`, `mark_nis2_reportable` und `unmark_nis2_reportable` luden das `SecurityFinding` bisher nur über `finding_hash` (SHA256[:16] von domain|module|issue — stabil aber nicht geheim), ohne Tenant-Filter. Jeder authentifizierte Nutzer *irgendeines* Tenants konnte damit den Hash eines fremden Findings erraten/kennen und dessen Triage-Status oder NIS2-Meldefrist manipulieren. Fix: neue gemeinsame `_get_finding_for_user()`-Hilfsfunktion filtert zusätzlich auf `SecurityFinding.tenant_id == user.tenant_id` (Platform-Admins mit `tenant_id=None` bleiben unrestricted, gleiche Konvention wie `_get_tenant_targets()`), in allen drei Endpoints eingesetzt. Live verifiziert: simulierter Cross-Tenant-Zugriff liefert jetzt 404, der echte Owner-Tenant kommt weiterhin durch.
- **SSRF via Redirect-Bypass im Integrations-Health-Check** ✅ **gefixt** (eigener Bug aus Welle 9/#57 dieser Session): `test_integration()` validierte die konfigurierte Integration-URL zwar gegen die Cloud-Metadata-Denylist, rief sie danach aber mit `requests.head(url, allow_redirects=True)` auf — ein bösartiger/kompromittierter Endpoint konnte per 30x-Redirect auf `169.254.169.254` o.ä. umleiten, ohne dass die Ziel-URL erneut geprüft wurde. Fix: neue `_probe_url_no_redirect_ssrf()`-Hilfsfunktion folgt Redirects manuell (max. 5 Hops), validiert jeden `Location`-Header erneut gegen dieselbe Denylist-Prüfung, bevor der nächste Hop angefragt wird. Live verifiziert: ein echter Redirect auf `169.254.169.254` wird jetzt mit HTTP 400 "hostname is not allowed" blockiert, ein normaler (nicht-redirectender) Request funktioniert weiterhin. Bekannte Grenze: `_validate_integration_url()` deckt nur eine kleine Cloud-Metadata-Denylist ab, kein generisches RFC1918/Loopback-Blocking — das würde auch andere Aufrufer (Jira/Webhook `base_url`/`endpoint`) betreffen und wurde bewusst nicht im Rahmen dieses gezielten Fixes ausgeweitet.
- **XSS via `innerHTML` in der globalen Suche** ✅ **gefixt**: `search.html` baute alle fünf Ergebnis-Kategorien (Targets, Findings, Tags, Discovery-Kandidaten, Changelog) über Template-Literale + `innerHTML +=` aus ungefilterten Server-Werten (`t.domain`, `f.module`, `c.title`, etc.) — Daten, die teils aus gescannten externen Zielen stammen und damit nicht vertrauenswürdig sind. Fix: neue `escHtml()`-Hilfsfunktion (HTML-Entity-Escaping) am Skript-Anfang, jede `${...}`-Interpolation in allen fünf Render-Blöcken damit umschlossen; ID-Werte in `href`-Attributen zusätzlich mit `encodeURIComponent()`. Verifiziert: JS-Syntax-Check bestanden, `escHtml('<img src=x onerror=alert(1)>')` liefert korrekt HTML-entity-escapten Text ohne funktionsfähiges Tag.
- **`api_keys.py` Scope-Modell härten** ✅ **gefixt (Welle 0, 2026-08-22)** (2026-08-21, vom automatischen Security-Review geflaggt): `provision_tenant`-Scope konnte ohne Platform-Admin-Check vergeben werden (Privilege Escalation). Fix: `create_key` blockt jetzt mit 403, wenn `provision_tenant` angefragt wird und `current_user.role != "admin"`. Verifiziert: tenant_admin → 403, Platform-Admin → durchgelassen (läuft danach in einen separaten, unabhängigen Bug: `apikey.tenant_id` ist NOT NULL, Platform-Admin hat `tenant_id=None` — nicht Teil dieses Fixes, separat vermerkt).
- **`apikey.tenant_id` NOT NULL blockte Platform-Admin-eigene API-Keys** ✅ **gefixt (Cleanup-Pass, 2026-08-22)** (entdeckt bei der Verifikation des `provision_tenant`-Scope-Fixes, 2026-08-22): Platform-Admins (`tenant_id=None`) konnten keine eigenen API-Keys anlegen — `INSERT INTO apikey ... tenant_id=NULL` verletzte die NOT-NULL-Constraint. Fix: `APIKey.tenant_id` in `models.py` auf `Optional[int]` umgestellt, additive Migration `ALTER TABLE apikey ALTER COLUMN tenant_id DROP NOT NULL` in `migrate_db.py` ergänzt. Bewusste Design-Entscheidung dabei dokumentiert statt versteckt: ein Key mit `tenant_id=NULL` matcht keine `APIKey.tenant_id == Target.tenant_id`-Scoping-Query (SQLAlchemy übersetzt `== None` zu `IS NULL`) — er "fails closed" (hat noch keinen Tenant-Zugriff), statt versehentlich tenant-übergreifend alles freizugeben. Echtes plattformweites API-Key-Scoping ist ein eigenes, größeres Feature und nicht Teil dieses Bugfixes. Verifiziert: Migration lief beim API-Neustart erfolgreich (`ALTER COLUMN ... DROP NOT NULL` → "Success", Spalte laut `\d apikey` jetzt nullable), End-to-End-Test über den ORM-Layer legte einen Key mit `tenant_id=None` erfolgreich an und löschte ihn wieder.
- **`yads.scheduler` lässt Postgres-Sessions "idle in transaction" hängen** ✅ **gefixt (Cleanup-Pass, 2026-08-22)** (wiederholt beobachtet während Welle 2/3-Verifikation, 2026-08-22): mehrfach blockierte eine `SELECT tenantscanconfig...`-Query aus dem Scheduler-Loop (Worker-Container) als "idle in transaction" nachfolgende `ALTER TABLE`-Migrationen beim nächsten API-Neustart komplett (Container blieb "unhealthy", `migrate_db.py` hing unbegrenzt). Root Cause während eines eigenen API-Neustarts im Cleanup-Pass live reproduziert und per `pg_stat_activity` bestätigt: exakt dieselbe `tenantscanconfig`-SELECT blockierte die `ALTER TABLE target ADD COLUMN ... tenant_id`-Migration. Fix: `yads/database.py` setzt jetzt `idle_in_transaction_session_timeout=300000` (5 Min) als `connect_args`-Option auf dem globalen Engine — Postgres killt damit selbstständig jede Session, die eine Transaktion offen lässt, statt manuellem `pg_terminate_backend()`. Verifiziert: `SHOW idle_in_transaction_session_timeout` liefert `5min` auf neuen Verbindungen; die hängende Session wurde manuell terminiert, API danach wieder "healthy", Worker loggt den erwarteten (harmlosen) Connection-Reset für die terminierte Session sauber ab statt zu crashen.
- **`subdomain_takeover_scanner.py` nutzte `self.db_session` statt `self.db`** ✅ **gefixt (Welle 3, 2026-08-22)**: `BaseScannerModule` setzt nur `self.db`; `self.db_session` existierte nie, wodurch die OSINT-Persistierung von Takeover-Findings und die DB-gestützte Subdomain-Kandidatenerweiterung seit jeher als stille Exception fehlschlugen (sichtbar erst durch Live-Verifikation, nicht durch Code-Review allein). Verifiziert: Fehler verschwindet nach Fix.

---

## 💡 Empfehlung für den nächsten Start

**Einfachster Einstieg:** Wayback Machine Integration (Low Effort, interessante OSINT-Daten)
**Meiste visuelle Impact:** Visual Regression / Defacement Monitor
**Meiste Security-Relevanz:** AI Executive Reporting oder Cloud Asset Enumeration
