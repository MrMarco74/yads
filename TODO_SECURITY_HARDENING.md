# TODO: Security Hardening — TLS & Post-Quantum Cryptography

> Status: **Offen / Nicht begonnen**  
> Kontext: Offene Punkte aus der LLMGui-YADS Integrationsphase + neue PQC-Anforderungen

---

## 1. TLS Enforcement Middleware (Phase 1 Restpoint)

**Ziel:** Alle unverschlüsselten HTTP-Requests zu YADS sollen abgelehnt werden — außer im `DEBUG`-Modus.

- [ ] `TLSEnforcementMiddleware` in `yads/api/main.py` einbauen
  - [ ] FastAPI-Middleware, die `request.url.scheme` prüft
  - [ ] Bei `http://` im Produktionsmodus → `HTTP 426 Upgrade Required` zurückgeben
  - [ ] `DEBUG`-Flag aus `settings.py` auslesen → Middleware deaktivierbar für lokale Entwicklung
  - [ ] Response-Header `Upgrade: TLS/1.3, HTTP/1.1` korrekt setzen
  - [ ] Tests: Sicherstellen dass `/api/v1/*` und `/api/scan/*` im Nicht-DEBUG-Modus nur HTTPS akzeptieren
- [ ] YADS-Doku in `docs/SECURITY.md` um TLS-Enforcement-Abschnitt erweitern
- [ ] LLMGui-seitige TLS-Audit-Warnung in `YadsDastTool` reviewen (läuft bereits, aber ggf. Fehlermeldung verbessern)

---

## 2. Post-Quantum Cryptography (PQC) Checks

**Ziel:** YADS soll PQC-bezogene Schwachstellen in gescannten Projekten erkennen und melden.

### 2a. PQC Scanner — Statische Analyse
- [x] Neues Analyse-Modul: `yads/analyzers/pqc_scanner.py`
  - [x] Pattern-Matching auf bekannte klassische Algorithmen, die PQC-vulnerable sind:
    - [x] RSA (alle Schlüssellängen) — erkennbar via `cryptography`, `rsa`, `M2Crypto`, `openssl` imports
    - [x] ECDSA / ECDH (P-256, P-384, secp256k1) — betroffen durch Shor-Algorithmus
    - [x] DH/DHE mit klassischen Gruppen
    - [x] AES-128 (Grover: effektiv 64-bit-Security) — Empfehlung auf AES-256 upgraden
    - [x] MD5 / SHA-1 (klassisch schwach, PQC-irrelevant aber gleich mitmelden)
  - [x] Erkennung von Hardcoded Keys / Certs im Code (Regex auf PEM-Blöcke)
  - [x] Ausgabe als `VulnerabilityReport` mit `severity=HIGH` für PQC-vulnerable Algorithmen

### 2b. PQC Dependency Check
- [x] Requirements-Scan auf Pakete ohne PQC-Unterstützung:
  - [x] `cryptography < 42.x` → noch keine ML-KEM / ML-DSA Unterstützung
  - [x] `pyOpenSSL` ohne PQC-Backend
  - [x] `requests` / `httpx` ohne LibreSSL 4.x / BoringSSL PQC
- [x] Mapping auf NIST PQC Finalists (FIPS 203/204/205):
  - [x] ML-KEM (Kyber) — Schlüsselaustausch-Empfehlung
  - [x] ML-DSA (Dilithium) — Signatur-Empfehlung
  - [x] SLH-DSA (SPHINCS+) — Hash-basierte Signatur-Alternative

### 2c. TLS Config Scan (Remote)
- [x] Prüfen ob der gescannte Dienst PQC-TLS unterstützt:
  - [x] TLS 1.3 als Minimum erzwingen
  - [x] Hybrid Key Exchange (X25519Kyber768 / X25519MLKEM768) prüfen via `ssl.SSLSocket`
  - [x] Falls nur klassische Cipher-Suites → Finding mit Remediation-Hinweis

### 2d. Report-Integration
- [x] PQC-Findings in den bestehenden Scan-Report-Flow einbinden (`/api/scan/vuln`)
- [x] PQC-spezifische CVSS-Risikoeinschätzung: klassische Kryptografie = `CVSS 7.5` (Quantum-Threat noch nicht akut, aber zukünftig kritisch)
- [x] Remediation-Hinweise für jeden Finding-Typ (welches NIST-Standardalgorithmus ersetzen)
- [x] `report_templates/` um PQC-Abschnitt erweitern (via `PDFReport` Integration)
- [x] Dedizierter PQC-Report (`generate_pqc_report`) implementiert

---

## Referenzen

- [NIST FIPS 203 – ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 – ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 – SLH-DSA (SPHINCS+)](https://csrc.nist.gov/pubs/fips/205/final)
- [BSI TR-02102-1: Kryptoempfehlungen](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html)
- [OWASP Cryptographic Failures (A02:2021)](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
