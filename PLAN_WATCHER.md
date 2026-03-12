# Implementation Plan: Health Watcher & Admin Alerting

## Overview

Ein zyklischer Hintergrund-Watcher, der laufend prüft ob Worker hängen, abstürzen
oder der Celery-Queue blockiert ist — und den Admin per Webhook / UI-Banner darüber
informiert. Läuft als Daemon-Thread im API-Prozess (kein eigener Dienst nötig).

---

## Architektur

### Wie er läuft

- Startet beim API-Start als `threading.Thread(daemon=True)` (wie `system_metrics`)
- Prüfintervall: **60 Sekunden** (konfigurierbar via `SystemConfig.WATCHER_INTERVAL_S`)
- Schreibt aktive Alerts in Redis (`yads:alerts:active`, JSON-Liste, TTL 5 min, wird
  bei jedem Cycle erneuert)
- Persistiert Alerthistorie in `SystemAlertLog` (neue DB-Tabelle)
- Sendet Webhook-Event `system_alert` bei jedem *neuen* Alert (Dedup via Redis-Key)

### Komponenten

| Datei | Zweck |
|-------|-------|
| `yads/core/watcher.py` | Watcher-Daemon + alle Checks |
| `yads/models.py` | `SystemAlertLog`-Modell ergänzen |
| `yads/api/routers/sysmetrics.py` | `GET /api/system/alerts` — HTMX-Fragment für Topbar-Banner |
| `yads/api/templates/base.html` | Alert-Banner im Topbar einhängen (HTMX-Poll 30s) |
| `yads/api/main.py` | Watcher `start()` im Lifespan |

---

## Checks (Watcher-Logik)

### 1. Worker Heartbeat-Check
**Quelle:** `WorkerNode` Tabelle
**Logik:** Worker mit `status='active'` aber `last_seen > 3 Minuten` ago → Alert
**Severity:** `warning` (3-5 min), `error` (>5 min)
**Message:** `"Worker <hostname> antwortet nicht mehr (letzter Heartbeat: X min ago)"`

### 2. Hängende Tasks
**Quelle:** `WorkerTask` Tabelle
**Logik:** Tasks mit `status='running'` und `started_at > 2 Stunden` ago → Alert
**Severity:** `warning`
**Message:** `"Task für <domain> läuft seit >2h (Worker: <hostname>)"`

### 3. Queue-Stau
**Quelle:** Celery via Redis (`celery` Queue-Length, Broker-Key)
**Logik:** Wenn `queue_depth > 100` und kein aktiver Worker → Alert
**Severity:** `warning` (>50), `error` (>200)
**Message:** `"Celery-Queue gestaut: X Tasks warten, X Worker aktiv"`

### 4. Celery-Worker offline
**Quelle:** Celery `inspect().active()` (mit 2s Timeout)
**Logik:** Wenn kein Celery-Worker antwortet und Queue nicht leer → Alert
**Severity:** `error`
**Message:** `"Kein Celery-Worker erreichbar — Scans können nicht starten"`

### 5. Redis-Verbindung
**Quelle:** `redis.ping()`
**Logik:** Falls Redis nicht antwortet (Timeout 1s) → Alert
**Severity:** `error`
**Message:** `"Redis nicht erreichbar — Queue und Logs ausgefallen"`

### 6. Datenbank-Verbindung
**Quelle:** Einfacher `SELECT 1` mit 2s Timeout
**Logik:** Falls DB nicht antwortet → Alert
**Severity:** `error`
**Message:** `"Datenbankverbindung ausgefallen"`

### 7. Disk-Space (primary worker)
**Quelle:** `psutil.disk_usage('/')`
**Logik:** >80% → warning, >90% → error
**Message:** `"Festplatte zu X% belegt — Screenshots und Logs können nicht gespeichert werden"`

---

## Datenmodell

```python
class SystemAlertLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    check_name: str           # z.B. "worker_heartbeat"
    severity: str             # "warning" | "error"
    message: str
    detail: Optional[str]     # JSON mit Kontext (z.B. worker node_id)
    fired_at: datetime
    resolved_at: Optional[datetime]   # gesetzt wenn in nächstem Cycle OK
    notified: bool = False    # Webhook bereits gesendet
```

**Dedup-Logik:** Gleicher `check_name` + `severity` → kein neuer DB-Eintrag + kein neuer
Webhook, solange der Alert nicht resolved war. Wenn resolved → neuer Entry beim nächsten
Auftreten.

---

## UI: Alert-Banner

### Topbar-Fragment (`GET /api/system/alerts`)
- Pollt alle 30s via HTMX in `base.html`
- Wenn keine aktiven Alerts → leeres `<div>` (kein Platz verschwendet)
- Wenn Alerts → schmales rotes/gelbes Banner über dem Topbar:

```
⚠ 2 Systemwarnungen  [Details anzeigen ▾]
```

Klick öffnet ein Dropdown mit der Alert-Liste (inline aufklappbar, kein Modal).

### Alert-History-Seite
- Neuer Tab in `/help/about` oder eigene Seite `/system/alerts`
- Tabelle mit `SystemAlertLog` (letzte 7 Tage, platform admin only)
- Spalten: Zeitpunkt, Check, Severity, Nachricht, Resolved

---

## Webhook-Event

Neues Event `system_alert` im `webhook_service.py`:

```python
{
    "event": "system_alert",
    "severity": "error",
    "check": "worker_heartbeat",
    "message": "Worker prod-worker-2 antwortet nicht mehr",
    "fired_at": "2026-03-12T14:32:00Z"
}
```

Gesendet an **alle aktiven Webhooks** (tenant-übergreifend, da System-Alert).

---

## Konfiguration

Neue `SystemConfig`-Keys:

| Key | Default | Beschreibung |
|-----|---------|--------------|
| `WATCHER_ENABLED` | `true` | Watcher an/aus |
| `WATCHER_INTERVAL_S` | `60` | Prüfintervall in Sekunden |
| `WATCHER_HEARTBEAT_WARN_MIN` | `3` | Minuten bis Worker-Warning |
| `WATCHER_HEARTBEAT_ERR_MIN` | `5` | Minuten bis Worker-Error |
| `WATCHER_TASK_HANG_H` | `2` | Stunden bis Task als hängend gilt |
| `WATCHER_QUEUE_WARN` | `50` | Queue-Tiefe für Warning |
| `WATCHER_QUEUE_ERR` | `200` | Queue-Tiefe für Error |
| `WATCHER_DISK_WARN_PCT` | `80` | Disk-Auslastung für Warning |
| `WATCHER_DISK_ERR_PCT` | `90` | Disk-Auslastung für Error |

---

## Implementierungsreihenfolge

1. **`yads/models.py`** — `SystemAlertLog` Modell + Migration
2. **`yads/core/watcher.py`** — Daemon-Thread + alle 7 Checks + Redis-Dedup
3. **`yads/api/routers/sysmetrics.py`** — `GET /api/system/alerts` HTMX-Fragment
4. **`yads/api/templates/base.html`** — Alert-Banner im Topbar (HTMX-Poll 30s)
5. **`yads/api/main.py`** — `watcher.start()` im Lifespan
6. **`yads/core/webhook_service.py`** — `system_alert` Event hinzufügen
7. **(Optional)** `/system/alerts` History-Seite

---

## Aufwand-Schätzung

| Schritt | Komplexität |
|---------|-------------|
| Modell + Migration | Niedrig |
| Watcher-Daemon | Mittel |
| HTMX-Fragment + Banner | Niedrig |
| Webhook-Integration | Niedrig |
| History-Seite | Mittel |
