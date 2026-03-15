# YADS Proxy-Kompatibilität — Analyse & Plan

Stand: März 2026
Zweck: Analyse welche YADS-Funktionen hinter einem HTTP-Proxy (z. B. ZScaler) kaputt gehen,
und wie Proxy-Unterstützung in Phasen nachgerüstet werden kann.

---

## 1. Ausgangssituation

Ein HTTP-Proxy (transparenter oder expliziter Proxy wie ZScaler) sitzt zwischen YADS-Worker
und dem Internet. Alle TCP-Verbindungen des Workers laufen durch den Proxy.

**Proxy-Variante im Fokus:** Expliziter HTTP/HTTPS-Proxy mit CONNECT-Tunneling.
Typische Env-Vars: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`.

---

## 2. Betroffene Komponenten und Kompatibilitätsbewertung

### ✅ Funktioniert nativ (60 % der Funktionen)

Diese Module nutzen `requests` oder `httpx` — beide respektieren `HTTPS_PROXY` automatisch:

| Modul | Methode | Proxy-kompatibel? |
|---|---|---|
| `ssl_scanner.py` | `requests.get()` | ✅ ja |
| `http_headers_scanner.py` | `requests.get()` | ✅ ja |
| `security_txt_scanner.py` | `requests.get()` | ✅ ja |
| `cors_scanner.py` | `requests.get()` | ✅ ja |
| `cookie_scanner.py` | `requests.get()` | ✅ ja |
| `cert_mismatch_scanner.py` | stdlib `ssl` + socket | ⚠️ nur mit CONNECT-Tunnel |
| `shodan_censys_scanner.py` | `requests` / APIs | ✅ ja |
| `threat_intel_scanner.py` | `requests` / APIs | ✅ ja |
| `git_exposure_scanner.py` | `requests.get()` | ✅ ja |
| `js_secrets_scanner.py` | `requests.get()` / Playwright | ⚠️ Playwright: nein |
| `crt.sh API` (DNS-Scanner) | `requests.get()` | ✅ ja |
| `Wayback Machine` | `requests.get()` | ✅ ja |
| `Google CSE / HIBP` | `requests.get()` | ✅ ja |

---

### ❌ Bricht hinter Proxy (40 % der Funktionen)

Diese Tools öffnen raw TCP-Sockets oder werden als Subprozesse gestartet — sie ignorieren `HTTP_PROXY`:

| Modul / Tool | Problem | Workaround |
|---|---|---|
| **Playwright / Chromium** | Subprozess, ignoriert System-Proxy | `--proxy-server=` Flag nötig |
| **Nmap** | Raw-Sockets, kein Proxy-Support | Nur im NO_PROXY-Bereich nutzbar |
| **Nuclei** | Go-Binary, eigene HTTP-Client-Config | `--proxy` Flag verfügbar (v3+) |
| `dns_scanner.py` — eigene DNS-Auflösung | UDP Port 53, kein HTTP-Proxy-Tunnel | DNS-over-HTTPS als Workaround |
| `axfr_scanner.py` | Raw DNS (TCP 53) | DNS-over-HTTPS als Workaround |
| `infrastructure_scanner.py` (Nmap) | Raw-Sockets | Nur bei direktem Netzzugang |
| `visual_osint.py` (Playwright) | Subprozess | Playwright `--proxy-server=` |
| `web_analyzer.py` (Playwright) | Subprozess | Playwright `--proxy-server=` |
| `crawler.py` (Playwright) | Subprozess | Playwright `--proxy-server=` |

---

## 3. Auswirkungen auf Kernfunktionen

| Funktion | Proxy-Auswirkung |
|---|---|
| Subdomain Enumeration (crt.sh) | ✅ funktioniert |
| DNS-Records | ❌ keine Auflösung (UDP 53 geblockt) |
| SSL/TLS-Analyse | ✅ via CONNECT-Tunnel |
| Web-Analyse / Tech-Stack-Detection | ❌ Playwright ohne Proxy |
| Screenshots / Visual OSINT | ❌ Playwright ohne Proxy |
| Vulnerability Scanning (Nuclei) | ⚠️ teilweise (--proxy Flag) |
| Port-Scanning (Nmap) | ❌ komplett |
| Threat Intelligence APIs | ✅ alle requests-basiert |
| Email Security (MX-Lookup) | ❌ DNS-abhängig |
| Bug Reports / Support Portal | ✅ requests-basiert |

---

## 4. Phasenplan zur Proxy-Fähigkeit

### Phase P-0: Sofortmaßnahmen (keine Code-Änderungen)

Reicht für ~60 % der Funktionalität.

**Aktion:** Proxy-Env-Vars im Docker-Compose setzen:

```bash
# In .env oder docker-compose.yml (yads-worker service):
environment:
  - HTTP_PROXY=http://proxy.corp.example.com:8080
  - HTTPS_PROXY=http://proxy.corp.example.com:8080
  - NO_PROXY=localhost,127.0.0.1,10.0.0.0/8,db,redis
```

`requests` und `httpx` lesen diese automatisch. Sofort wirksam für alle API-calls.

---

### Phase P-1: Playwright-Proxy-Unterstützung

Betrifft: `web_analyzer.py`, `visual_osint.py`, `crawler.py`, `js_secrets_scanner.py`

**Umsetzung:**
1. Neues Setting: `BROWSER_PROXY_URL` (z. B. `http://proxy.corp.example.com:8080`)
2. In `BaseScannerModule` oder direkt in den Playwright-Modulen:
   ```python
   proxy = {"server": settings.BROWSER_PROXY_URL} if settings.BROWSER_PROXY_URL else None
   browser = await p.chromium.launch(proxy=proxy)
   ```
3. Optional: `BROWSER_NO_PROXY` für interne Hosts

**Aufwand:** ~2–3 Stunden (4 Module, konsistente Änderung)

---

### Phase P-2: Nuclei Proxy-Unterstützung

Betrifft: `nuclei_scanner.py`

**Umsetzung:**
1. In `nuclei_scanner.py` beim Subprozess-Start:
   ```python
   if settings.HTTPS_PROXY:
       cmd.extend(["-proxy", settings.HTTPS_PROXY])
   ```
2. Nuclei v3+ unterstützt `--proxy http://...` nativ.

**Aufwand:** ~30 Minuten

---

### Phase P-3: DNS-over-HTTPS (DoH)

Betrifft: `dns_scanner.py`, `axfr_scanner.py`, `email_security_scanner.py` (MX-Lookup)

UDP Port 53 ist hinter Enterprise-Proxies meist geblockt. Lösung: DoH über `requests`.

**Umsetzung:**
1. Neues Setting: `DNS_OVER_HTTPS=true` + `DOH_PROVIDER=https://cloudflare-dns.com/dns-query`
2. Neue Hilfsfunktion `yads/utils/doh.py`: DNS-Queries über HTTPS statt UDP
3. `dns_scanner.py` und `email_security_scanner.py` nutzen DoH als Fallback wenn UDP fehlschlägt
4. AXFR bleibt nicht möglich (benötigt TCP 53 direkt)

**Aufwand:** ~4–6 Stunden (neues Utility + Integration in 3 Module)

---

### Phase P-4: Proxy-Konfiguration in YADS-UI

Proxy-Einstellungen direkt in den YADS-Einstellungen konfigurierbar machen.

**Umsetzung:**
1. Settings-Felder in `config.py`:
   - `HTTP_PROXY_URL`
   - `HTTPS_PROXY_URL`
   - `NO_PROXY_HOSTS`
   - `BROWSER_PROXY_URL`
   - `DNS_OVER_HTTPS`
2. UI-Sektion "Netzwerk / Proxy" in den Admin-Einstellungen
3. Bei Speichern: Env-Vars für laufende Prozesse setzen (oder Worker-Restart triggern)

**Aufwand:** ~4 Stunden

---

### Phase P-5: Nmap-Alternative für Proxy-Umgebungen

Nmap ist hinter Proxy grundsätzlich nicht nutzbar (Raw-Sockets).

**Optionen:**
- **Shodan/Censys als Ersatz:** Port-Daten aus Threat-Intel-Quellen (kein direktes Scanning)
- **Masscan über SOCKS5-Proxy:** Theoretisch möglich, aber komplex
- **Feature-Flag:** Nmap-Scan in Proxy-Umgebungen deaktivieren + Hinweis in UI

**Empfehlung:** Feature-Flag (Aufwand: 1 Stunde), Shodan/Censys als Daten-Ersatz nutzen.

---

## 5. Zusammenfassung: Proxy-Roadmap

| Phase | Was | Aufwand | Funktions-Gewinn |
|---|---|---|---|
| P-0 | Env-Vars setzen | 10 min | 60 % direkt |
| P-1 | Playwright proxy | 2–3 h | +15 % (Browser-Module) |
| P-2 | Nuclei proxy | 30 min | +5 % (Vuln-Scans) |
| P-3 | DNS-over-HTTPS | 4–6 h | +10 % (DNS-Module) |
| P-4 | UI-Konfiguration | 4 h | UX-Verbesserung |
| P-5 | Nmap-Fallback | 1 h | Graceful degradation |

**Realistisch erreichbar:** ~90 % Proxy-Kompatibilität nach P-0 bis P-3.
Die restlichen 10 % (Nmap raw scanning) sind technisch nicht proxy-fähig.

---

## 6. Nicht-Implementiertes (bewusst ausgelassen)

- **SOCKS5-Proxy-Unterstützung:** Würde SOCKS-Proxy für alle TCP-Verbindungen erfordern — machbar aber komplexer als HTTP-CONNECT
- **Proxy-Authentifizierung (NTLM/Kerberos):** Enterprise-Proxies nutzen oft NTLM. `requests` unterstützt NTLM via `requests-ntlm` — optionale Erweiterung in P-4
- **Transparent Proxy:** Wenn der Proxy transparent ist, funktioniert Phase P-0 ohne Konfiguration (OS-Level-Interception), aber Playwright und Raw-Socket-Tools bleiben betroffen
