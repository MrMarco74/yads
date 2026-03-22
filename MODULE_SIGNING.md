# YADS Module Signing

Dieses Dokument beschreibt, wie offizielle YADS Add-On-Module signiert, verifiziert und deployed werden.

---

## Überblick

YADS verwendet **Ed25519-Signaturen**, um sicherzustellen, dass nur vertrauenswürdige Module installiert werden können. Der öffentliche Schlüssel ist direkt im Quellcode hinterlegt (`yads/core/module_signing.py`). Der passende private Schlüssel liegt lokal unter `yads_module_signing.key` und darf **niemals** in das Repository committed werden.

### Schlüsselauflösung (in dieser Reihenfolge)

| Priorität | Quelle | Verwendungszweck |
|-----------|--------|------------------|
| 1 | `MODULE_SIGNING_PUBLIC_KEY` (Env-Var) | Operator-Override für eigene Schlüssel |
| 2 | `YADS_OFFICIAL_PUBLIC_KEY` (hardcoded) | Offizieller YADS-Schlüssel für erste-Partei-Module |
| 3 | *(kein Schlüssel)* | Unsignierte Module erlaubt (Entwicklungsmodus) |

Ist `MODULE_SIGNING_DISABLED=true` gesetzt, wird die Prüfung komplett übersprungen.

### Auto-Signing (empfohlen für lokale Instanz)

Wenn `MODULE_SIGNING_PRIVATE_KEY_PATH` auf eine gültige PEM-Datei zeigt, signiert YADS jeden Upload **automatisch** — ohne externes Signing-Tool. Der private Schlüssel wird beim API-Start eingelesen und gecacht.

```env
# data/config.env
MODULE_SIGNING_PRIVATE_KEY_PATH=/run/secrets/yads_module_signing.key
```

Beim Start erscheint im Log:

```
INFO  Module signing private key ready for auto-signing.
```

Ist der Pfad nicht konfiguriert (normaler Zustand ohne Auto-Signing):

```
DEBUG No module signing private key configured (MODULE_SIGNING_PRIVATE_KEY_PATH not set).
```

> **Hinweis:** Der private Schlüssel darf nur auf vertrauenswürdigen internen Instanzen eingesetzt werden. In Mehrbenutzerumgebungen ist manuelles Signieren via `scripts/sign_module.py` vorzuziehen.

---

## Dateien

| Datei / Variable | Inhalt | Committen? |
|------------------|--------|-----------|
| `yads_module_signing.key` | Ed25519 **Private Key** (PEM) | ❌ Niemals |
| `yads_module_signing.pub` | Ed25519 **Public Key** (PEM) | Optional (Referenz) |
| `yads/core/module_signing.py` | Hardcoded Public Key + Verifikationslogik | ✅ Ja |
| `scripts/sign_module.py` | Signing-Tool (manuell) | ✅ Ja |
| `MODULE_SIGNING_PRIVATE_KEY_PATH` (Env-Var) | Pfad zum Private Key für Auto-Signing | n/a |

> `yads_module_signing.key` ist in `.gitignore` eingetragen und wird nicht getrackt.

---

## Modul signieren

### Voraussetzungen

```bash
pip install cryptography
```

### Schritt 1 — Modul als ZIP packen

Das ZIP muss eine `module_manifest.json` im Wurzelverzeichnis enthalten:

```
my_scanner.zip
├── module_manifest.json
└── my_scanner.py
```

Beispiel `module_manifest.json`:

```json
{
    "module_name": "my_scanner",
    "label": "My Scanner",
    "label_de": "Mein Scanner",
    "module_file": "my_scanner.py",
    "class_name": "MyScanner",
    "version": "1.0.0",
    "author": "YADS Security",
    "description": "Scannt XYZ.",
    "category": "recon",
    "passive": true
}
```

### Schritt 2 — Signatur erzeugen

```bash
python3 - <<'EOF'
import base64, hashlib
from cryptography.hazmat.primitives import serialization

zip_bytes = open("my_scanner.zip", "rb").read()
priv = serialization.load_pem_private_key(open("yads_module_signing.key", "rb").read(), password=None)
digest = hashlib.sha256(zip_bytes).digest()
sig = base64.urlsafe_b64encode(priv.sign(digest)).rstrip(b"=").decode()
print(sig)
EOF
```

Die ausgegebene Base64-Zeichenkette ist die Signatur. Sie wird beim Upload als `signature`-Formfeld mitgeschickt.

### Schritt 3 — Signatur in .sig-Datei speichern (optional)

```bash
python3 - <<'EOF'
import base64, hashlib
from cryptography.hazmat.primitives import serialization

zip_bytes = open("my_scanner.zip", "rb").read()
priv = serialization.load_pem_private_key(open("yads_module_signing.key", "rb").read(), password=None)
digest = hashlib.sha256(zip_bytes).digest()
sig = base64.urlsafe_b64encode(priv.sign(digest)).rstrip(b"=").decode()

open("my_scanner.sig", "w").write(sig)
print("Signature written to my_scanner.sig")
EOF
```

---

## Modul installieren

### Über die YADS-Weboberfläche

1. Plugin Manager öffnen: **Einstellungen → Plugin Manager**
2. ZIP-Datei hochladen
3. Im Feld **Signatur** die Signatur aus `my_scanner.sig` einfügen
4. Auf **Installieren** klicken

### Über die API (curl)

```bash
SIG=$(cat my_scanner.sig)

curl -X POST https://yads.example.com/scan-modules/upload \
  -H "Cookie: session=<your-session-cookie>" \
  -F "module_zip=@my_scanner.zip" \
  -F "signature=${SIG}"
```

---

## Signatur lokal prüfen

Vor dem Upload kann die Signatur lokal verifiziert werden:

```bash
python3 - <<'EOF'
import base64, hashlib
from cryptography.hazmat.primitives import serialization

zip_bytes = open("my_scanner.zip", "rb").read()
sig_b64   = open("my_scanner.sig").read().strip()
pub = serialization.load_pem_public_key(open("yads_module_signing.pub", "rb").read())

sig_padded = sig_b64 + "=" * (-len(sig_b64) % 4)
sig = base64.urlsafe_b64decode(sig_padded)
digest = hashlib.sha256(zip_bytes).digest()

try:
    pub.verify(sig, digest)
    print("OK — Signatur gültig")
except Exception as e:
    print(f"FEHLER — Signatur ungültig: {e}")
EOF
```

---

## Integritätsprüfung zur Laufzeit

Nach der Installation wird der SHA-256-Hash der installierten `.py`-Datei in der Datenbank (`installedmodule.file_hash`) gespeichert.

Bei **jedem YADS-Start** (`load_installed_modules_from_db`) wird der Hash der Datei auf dem Dateisystem mit dem gespeicherten Wert verglichen. Bei Abweichung:

- Das Modul wird **automatisch deaktiviert** (`is_active = False`)
- Ein `CRITICAL`-Eintrag wird ins Log geschrieben:
  ```
  INTEGRITY VIOLATION: Module 'my_scanner' file hash mismatch!
  Expected abc123..., got def456...
  ```
- Das Modul verschwindet aus dem Plugin Manager und der Scan-Auswahl
- Wiederherstellung: Modul erneut hochladen

---

## Schlüsselrotation

Wenn der private Schlüssel kompromittiert wurde oder rotiert werden soll:

### 1. Neues Schlüsselpaar erzeugen

```bash
python3 - <<'EOF'
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

priv = Ed25519PrivateKey.generate()
pub  = priv.public_key()

priv_pem = priv.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
pub_pem = pub.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

open("yads_module_signing.key", "wb").write(priv_pem)
open("yads_module_signing.pub", "wb").write(pub_pem)

pub_b64 = base64.b64encode(pub_pem).decode()
print("Neuer Public Key (base64):")
print(pub_b64)
EOF
```

### 2. Public Key in `module_signing.py` eintragen

Den ausgegebenen Base64-Wert in `yads/core/module_signing.py` ersetzen:

```python
YADS_OFFICIAL_PUBLIC_KEY: Optional[str] = (
    "<neuer base64-public-key hier>"
)
```

### 3. Alle offiziellen Module neu signieren

Jede `.zip`-Datei muss mit dem neuen privaten Schlüssel erneut signiert werden (Schritt 2 oben).

### 4. YADS neu deployen

```bash
docker compose restart yads-api
```

Nach dem Neustart sind alle bestehenden Module mit altem Hash-Eintrag in der DB weiterhin aktiv — sie werden nur bei Hash-Abweichung deaktiviert, nicht weil der Signing-Key rotiert wurde. Die Datei-Integrität ist unabhängig vom Signing-Key.

---

## Entwicklungsmodus (ohne Signierung)

Während der lokalen Entwicklung kann die Signaturprüfung deaktiviert werden:

```env
# data/config.env
MODULE_SIGNING_DISABLED=true
```

Mit dieser Einstellung werden Module ohne Signatur akzeptiert. **Nicht für Produktionsumgebungen geeignet.**

---

## Sicherheitshinweise

- Den privaten Schlüssel (`yads_module_signing.key`) **sicher und offline aufbewahren**
- Niemals in Git committen — `.gitignore` schützt die Datei, aber doppelt prüfen
- Keine Drittanbieter-Module ohne Quellcode-Prüfung installieren
- Bei Verdacht auf Kompromittierung sofort Schlüssel rotieren und alle installierten Module prüfen
