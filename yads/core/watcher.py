"""
Health Watcher Daemon

Runs as a daemon thread in the API process. Every N seconds it executes a
set of system checks and writes the results to:
  - Redis key  yads:alerts:active  (JSON list, TTL = 2 × interval)
  - DB table   systemalertlog      (persistent history + dedup)

Newly fired alerts trigger a cross-tenant "system_alert" webhook notification.
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger("yads.watcher")

# ── Defaults (overridden by SystemConfig at runtime) ──────────────────────────
_DEFAULT_INTERVAL_S       = 60
_DEFAULT_HB_WARN_MIN      = 3
_DEFAULT_HB_ERR_MIN       = 5
_DEFAULT_TASK_HANG_H      = 2
_DEFAULT_QUEUE_WARN       = 50
_DEFAULT_QUEUE_ERR        = 200
_DEFAULT_DISK_WARN_PCT    = 80
_DEFAULT_DISK_ERR_PCT     = 90

REDIS_KEY_ACTIVE = "yads:alerts:active"
REDIS_KEY_DEDUP  = "yads:alerts:dedup:"   # + check_name:severity


# ── Thread state ──────────────────────────────────────────────────────────────
_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()


def start(redis_url: str):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop_event.clear()
    _thread = threading.Thread(
        target=_run_loop,
        args=(redis_url,),
        daemon=True,
        name="yads-watcher",
    )
    _thread.start()
    logger.info("Health watcher started.")


def stop():
    _stop_event.set()


# ── Main loop ─────────────────────────────────────────────────────────────────

def _run_loop(redis_url: str):
    import redis as redis_lib
    rc = redis_lib.from_url(redis_url, socket_connect_timeout=2)

    while not _stop_event.is_set():
        try:
            _cycle(rc)
        except Exception:
            logger.exception("Watcher cycle failed")
        _stop_event.wait(_get_cfg_int("WATCHER_INTERVAL_S", _DEFAULT_INTERVAL_S))


def _cycle(rc):
    from yads.database import engine
    from sqlmodel import Session

    alerts: list[dict] = []

    # Run all checks — each returns a list of alert dicts (may be empty)
    alerts += _check_redis(rc)
    alerts += _check_database(engine)
    alerts += _check_disk()
    alerts += _check_worker_heartbeats(engine)
    alerts += _check_hanging_tasks(engine)
    alerts += _check_celery_queue(rc, engine)
    alerts += _check_api_errors(rc)
    _check_scan_log_errors(rc, engine)  # tenant-scoped, written separately

    # Write active alerts to Redis (for the topbar fragment)
    ttl = max(120, _get_cfg_int("WATCHER_INTERVAL_S", _DEFAULT_INTERVAL_S) * 2)
    try:
        rc.setex(REDIS_KEY_ACTIVE, ttl, json.dumps(alerts))
    except Exception:
        pass  # If Redis is down we already have an alert for that

    # Persist new alerts + resolve old ones in DB
    with Session(engine) as session:
        _persist_alerts(alerts, session, rc)


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_redis(rc) -> list[dict]:
    try:
        rc.ping()
        return []
    except Exception:
        return [_alert("redis_connection", "error",
                       "Redis nicht erreichbar — Queue und Logs ausgefallen")]


def _check_database(engine) -> list[dict]:
    try:
        from sqlmodel import Session
        from sqlalchemy import text
        with Session(engine) as s:
            s.exec(text("SELECT 1"))
        return []
    except Exception:
        return [_alert("db_connection", "error",
                       "Datenbankverbindung ausgefallen")]


def _check_disk() -> list[dict]:
    try:
        import psutil
        usage = psutil.disk_usage("/")
        pct = usage.percent
        warn = _get_cfg_int("WATCHER_DISK_WARN_PCT", _DEFAULT_DISK_WARN_PCT)
        err  = _get_cfg_int("WATCHER_DISK_ERR_PCT",  _DEFAULT_DISK_ERR_PCT)
        if pct >= err:
            return [_alert("disk_space", "error",
                           f"Festplatte zu {pct:.0f}% belegt — Speicher fast voll",
                           detail={"pct": pct})]
        if pct >= warn:
            return [_alert("disk_space", "warning",
                           f"Festplatte zu {pct:.0f}% belegt",
                           detail={"pct": pct})]
    except Exception:
        pass
    return []


def _check_worker_heartbeats(engine) -> list[dict]:
    alerts = []
    try:
        from sqlmodel import Session, select
        from yads.models import WorkerNode
        warn_min = _get_cfg_int("WATCHER_HEARTBEAT_WARN_MIN", _DEFAULT_HB_WARN_MIN)
        err_min  = _get_cfg_int("WATCHER_HEARTBEAT_ERR_MIN",  _DEFAULT_HB_ERR_MIN)
        now = datetime.now(timezone.utc)

        with Session(engine) as session:
            workers = session.exec(
                select(WorkerNode).where(WorkerNode.status == "active")
            ).all()

        for w in workers:
            if not w.last_seen:
                continue
            last = w.last_seen
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            age_min = (now - last).total_seconds() / 60
            if age_min >= err_min:
                alerts.append(_alert(
                    f"worker_heartbeat_{w.node_id}", "error",
                    f"Worker '{w.hostname}' antwortet nicht mehr "
                    f"(letzter Heartbeat vor {age_min:.0f} min)",
                    detail={"node_id": w.node_id, "hostname": w.hostname, "age_min": round(age_min, 1)},
                ))
            elif age_min >= warn_min:
                alerts.append(_alert(
                    f"worker_heartbeat_{w.node_id}", "warning",
                    f"Worker '{w.hostname}' antwortet nicht mehr "
                    f"(letzter Heartbeat vor {age_min:.0f} min)",
                    detail={"node_id": w.node_id, "hostname": w.hostname, "age_min": round(age_min, 1)},
                ))
    except Exception:
        logger.debug("worker heartbeat check failed", exc_info=True)
    return alerts


def _check_hanging_tasks(engine) -> list[dict]:
    alerts = []
    try:
        from sqlmodel import Session, select
        from yads.models import WorkerTask, WorkerNode
        hang_h = _get_cfg_int("WATCHER_TASK_HANG_H", _DEFAULT_TASK_HANG_H)
        threshold = datetime.now(timezone.utc) - timedelta(hours=hang_h)

        with Session(engine) as session:
            tasks = session.exec(
                select(WorkerTask).where(
                    WorkerTask.status == "running",
                    WorkerTask.started_at <= threshold,
                )
            ).all()

            for t in tasks:
                worker_hostname = "?"
                if t.worker_node_id:
                    wn = session.get(WorkerNode, t.worker_node_id)
                    if wn:
                        worker_hostname = wn.hostname
                started = t.started_at
                if started and started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                age_h = (datetime.now(timezone.utc) - started).total_seconds() / 3600 if started else 0
                alerts.append(_alert(
                    f"hanging_task_{t.id}", "warning",
                    f"Task für '{t.target_domain or t.id}' läuft seit {age_h:.1f}h "
                    f"(Worker: {worker_hostname})",
                    detail={"task_id": t.id, "domain": t.target_domain, "worker": worker_hostname},
                ))
    except Exception:
        logger.debug("hanging task check failed", exc_info=True)
    return alerts


def _check_celery_queue(rc, engine) -> list[dict]:
    alerts = []
    try:
        queue_depth = rc.llen("celery")
        warn = _get_cfg_int("WATCHER_QUEUE_WARN", _DEFAULT_QUEUE_WARN)
        err  = _get_cfg_int("WATCHER_QUEUE_ERR",  _DEFAULT_QUEUE_ERR)

        if queue_depth < warn:
            return []

        # Count active Celery workers via inspect (short timeout)
        active_workers = 0
        try:
            from celery import Celery
            from yads.config import settings
            _app = Celery(broker=settings.REDIS_URL)
            inspect = _app.control.inspect(timeout=2.0)
            result = inspect.active()
            if result:
                active_workers = len(result)
        except Exception:
            pass

        sev = "error" if queue_depth >= err else "warning"
        alerts.append(_alert(
            "celery_queue", sev,
            f"Celery-Queue gestaut: {queue_depth} Tasks warten, "
            f"{active_workers} Worker aktiv",
            detail={"depth": queue_depth, "active_workers": active_workers},
        ))

        # Separate alert if no worker is active at all and queue is non-empty
        if active_workers == 0 and queue_depth > 0:
            alerts.append(_alert(
                "celery_no_worker", "error",
                "Kein Celery-Worker erreichbar — Scans können nicht starten",
                detail={"queue_depth": queue_depth},
            ))
    except Exception:
        logger.debug("celery queue check failed", exc_info=True)
    return alerts


# ── DB persistence + dedup ────────────────────────────────────────────────────

def _persist_alerts(current_alerts: list[dict], session, rc):
    """
    For each active alert: open a DB row if none is open for that check_name.
    For checks no longer firing: close (resolve) any open DB row.
    Fire webhook for newly-opened alerts.
    """
    from yads.models import SystemAlertLog
    from sqlmodel import select

    active_keys = {a["check_name"] for a in current_alerts}

    # Resolve alerts that are no longer firing
    open_rows = session.exec(
        select(SystemAlertLog).where(SystemAlertLog.resolved_at == None)  # noqa: E711
    ).all()
    for row in open_rows:
        if row.check_name not in active_keys:
            row.resolved_at = datetime.utcnow()
            session.add(row)
            logger.info(f"Alert resolved: {row.check_name}")

    # Open new rows + fire webhooks for truly new alerts
    open_check_names = {r.check_name for r in open_rows}
    for a in current_alerts:
        if a["check_name"] in open_check_names:
            continue  # already open, no duplicate
        row = SystemAlertLog(
            check_name=a["check_name"],
            severity=a["severity"],
            message=a["message"],
            detail=json.dumps(a.get("detail")) if a.get("detail") else None,
            fired_at=datetime.utcnow(),
        )
        session.add(row)
        logger.warning(f"New alert [{a['severity']}] {a['check_name']}: {a['message']}")
        _fire_webhook(a)
        row.notified = True

    session.commit()


def _fire_webhook(alert: dict):
    """Send system_alert webhook to all active webhooks across all tenants."""
    try:
        from sqlmodel import Session, select
        from yads.database import engine
        from yads.models import Webhook
        import requests as req

        payload = {
            "event": "system_alert",
            "severity": alert["severity"],
            "check": alert["check_name"],
            "message": alert["message"],
            "fired_at": datetime.utcnow().isoformat() + "Z",
        }
        headers = {"Content-Type": "application/json", "User-Agent": "YADS-Watcher/1.0"}

        with Session(engine) as session:
            hooks = session.exec(
                select(Webhook).where(
                    Webhook.is_active == True,
                    Webhook.event_types.contains(["system_alert"]),  # type: ignore[arg-type]
                )
            ).all()

        for hook in hooks:
            try:
                req.post(hook.url, json=payload, headers=headers, timeout=5)
            except Exception as exc:
                logger.debug(f"Webhook delivery failed {hook.url}: {exc}")
    except Exception:
        logger.debug("Webhook fire failed", exc_info=True)


# ── API Error Check ───────────────────────────────────────────────────────────

_API_ERROR_WINDOW_S = 300   # surface errors from the last 5 minutes
_API_ERROR_THRESHOLD = 3    # alert after ≥3 distinct errors in window


def _check_api_errors(rc) -> list[dict]:
    """
    Read the yads:api_errors Redis list (written by the 500-handler in main.py).
    If there are ≥ _API_ERROR_THRESHOLD errors within the last 5 minutes,
    generate a single aggregated warning alert so the topbar lights up.
    """
    try:
        import json as _json
        import time as _time

        raw = rc.lrange("yads:api_errors", 0, 49)
        if not raw:
            return []

        now = _time.time()
        recent = []
        for entry in raw:
            try:
                d = _json.loads(entry)
                if now - d.get("ts", 0) <= _API_ERROR_WINDOW_S:
                    recent.append(d)
            except Exception:
                pass

        if len(recent) < _API_ERROR_THRESHOLD:
            return []

        # Deduplicate by error type
        seen: set[str] = set()
        unique: list[dict] = []
        for d in recent:
            key = d.get("error", "")[:60]
            if key not in seen:
                seen.add(key)
                unique.append(d)

        sample = unique[0]
        detail_msg = sample.get("error", "?")[:120]
        url_msg = sample.get("url", "?")

        return [_alert(
            "api_errors",
            "error",
            f"{len(recent)} API-Fehler (letzte 5 min): {detail_msg}",
            detail={"count": len(recent), "sample_url": url_msg, "sample_error": detail_msg},
        )]
    except Exception:
        logger.debug("api error check failed", exc_info=True)
    return []


# ── Scan Log Error Check (tenant-scoped) ─────────────────────────────────────

REDIS_KEY_SCAN_ERRORS = "yads:scan_errors:tenant:"   # + tenant_id
_SCAN_ERROR_TTL = 3600   # suppress re-notification for 1h per target
_SCAN_ERROR_DEDUP = "yads:scan_errors:dedup:"        # + target_id


def _check_scan_log_errors(rc, engine):
    """
    Scan Redis log buffers of recently-active targets for ERROR/CRITICAL lines.
    Results are written per-tenant to Redis so the HTMX fragment can show them
    to the right user without exposing cross-tenant data.
    Dedup key prevents the same target from re-alerting within 1h.
    """
    try:
        import json as _json
        from sqlmodel import Session, select
        from yads.models import Target

        # Only check per-target log lists (scan:logs:<int>), not tenant/unified keys
        pattern = "scan:logs:*"
        keys = [
            k for k in rc.keys(pattern)
            if k.decode().replace("scan:logs:", "").isdigit()
        ]
        if not keys:
            return

        # Group errors by tenant_id
        tenant_errors: dict[int, list[dict]] = {}

        with Session(engine) as session:
            for key in keys:
                try:
                    target_id = int(key.decode().split(":")[-1])
                except (ValueError, AttributeError):
                    continue

                # Dedup: skip if we already notified for this target recently
                dedup_key = f"{_SCAN_ERROR_DEDUP}{target_id}"
                if rc.exists(dedup_key):
                    continue

                # Read last 50 log lines
                entries = rc.lrange(key, -50, -1)
                error_lines = []
                for raw in entries:
                    try:
                        entry = _json.loads(raw)
                        if entry.get("level") in ("ERROR", "CRITICAL"):
                            msg = (entry.get("msg") or entry.get("message") or "").strip()
                            if msg:
                                # Prefix with short module name if available
                                logger_name = entry.get("logger", "")
                                short_module = logger_name.split(".")[-1] if logger_name else ""
                                prefix = f"[{short_module}] " if short_module else ""
                                error_lines.append(f"{prefix}{msg}"[:200])
                    except Exception:
                        continue

                if not error_lines:
                    continue

                # Lookup tenant for this target
                target = session.get(Target, target_id)
                if not target or not target.tenant_id:
                    continue

                tid = target.tenant_id
                if tid not in tenant_errors:
                    tenant_errors[tid] = []
                tenant_errors[tid].append({
                    "target_id": target_id,
                    "domain": target.domain,
                    "errors": error_lines[:3],   # max 3 lines per target
                    "count": len(error_lines),
                })

                # Mark as notified for 1h
                rc.setex(dedup_key, _SCAN_ERROR_TTL, "1")

        # Write per-tenant result to Redis
        for tenant_id, errors in tenant_errors.items():
            rkey = f"{REDIS_KEY_SCAN_ERRORS}{tenant_id}"
            existing_raw = rc.get(rkey)
            existing = _json.loads(existing_raw) if existing_raw else []
            # Merge: add new entries, avoid duplicate target_ids
            known_ids = {e["target_id"] for e in existing}
            for e in errors:
                if e["target_id"] not in known_ids:
                    existing.append(e)
            rc.setex(rkey, _SCAN_ERROR_TTL, _json.dumps(existing))

    except Exception:
        logger.debug("scan log error check failed", exc_info=True)


def get_scan_errors_for_tenant(rc, tenant_id: int) -> list[dict]:
    """Return pending scan error notifications for a tenant (fast, no DB)."""
    try:
        raw = rc.get(f"{REDIS_KEY_SCAN_ERRORS}{tenant_id}")
        if raw:
            import json as _json
            return _json.loads(raw)
    except Exception:
        pass
    return []


def clear_scan_errors_for_tenant(rc, tenant_id: int):
    """Dismiss all scan error notifications for a tenant."""
    try:
        rc.delete(f"{REDIS_KEY_SCAN_ERRORS}{tenant_id}")
    except Exception:
        pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _alert(check_name: str, severity: str, message: str, detail: dict | None = None) -> dict:
    return {"check_name": check_name, "severity": severity, "message": message, "detail": detail}


def _get_cfg_int(key: str, default: int) -> int:
    try:
        from sqlmodel import Session, select
        from yads.database import engine
        from yads.models import SystemConfig
        with Session(engine) as s:
            cfg = s.get(SystemConfig, key)
            if cfg and cfg.value:
                return int(cfg.value)
    except Exception:
        pass
    return default


# ── Public helper for the HTMX fragment ──────────────────────────────────────

def get_active_alerts(rc) -> list[dict]:
    """Return current active alerts from Redis (fast, no DB needed)."""
    try:
        raw = rc.get(REDIS_KEY_ACTIVE)
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return []
