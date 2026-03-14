#!/usr/bin/env python3
"""
YADS Bug Report Watcher
=======================
Polls the YADS Support Portal for new bug reports and sends a desktop
notification (notify-send) when a new one arrives.

Reads credentials from ~/.yads/release_gui.yaml:
  support_portal_url: https://support.yads-security.com
  support_admin_token: <token>

State is persisted in ~/.local/share/yads-watcher/state.json so already-seen
reports never trigger a second notification, even across restarts.

Autostart: drop a .desktop file in ~/.config/autostart/ (see README below).
"""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POLL_INTERVAL_SECONDS = 60
CONFIG_FILE = Path.home() / ".yads" / "release_gui.yaml"
STATE_FILE = Path.home() / ".local" / "share" / "yads-watcher" / "state.json"
LOG_FILE = Path.home() / ".local" / "share" / "yads-watcher" / "watcher.log"

NOTIFY_APP_NAME = "YADS Support"
NOTIFY_ICON = "dialog-warning"  # standard freedesktop icon


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _load_config() -> dict:
    """Load support_portal_url and support_admin_token from release_gui.yaml."""
    if not CONFIG_FILE.exists():
        _log(f"ERROR: Config not found: {CONFIG_FILE}")
        sys.exit(1)
    try:
        import yaml  # type: ignore
        with CONFIG_FILE.open() as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        # Fallback: minimal YAML parser for simple key: value pairs
        data = {}
        for line in CONFIG_FILE.read_text().splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                k, _, v = line.partition(":")
                data[k.strip()] = v.strip().strip("'\"")
        return data


def _load_state() -> set:
    """Load set of already-seen report IDs."""
    if STATE_FILE.exists():
        try:
            return set(json.loads(STATE_FILE.read_text()).get("seen_ids", []))
        except (json.JSONDecodeError, OSError):
            pass
    return set()


def _save_state(seen_ids: set) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"seen_ids": list(seen_ids)}, indent=2))


def _fetch_reports(base_url: str, token: str) -> list:
    """Call GET /api/admin/reports and return list of report dicts."""
    url = base_url.rstrip("/") + "/api/admin/reports"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
            return body.get("reports", [])
    except urllib.error.HTTPError as exc:
        _log(f"HTTP {exc.code} from {url}: {exc.reason}")
        return []
    except urllib.error.URLError as exc:
        _log(f"Network error ({url}): {exc.reason}")
        return []
    except Exception as exc:
        _log(f"Unexpected error fetching reports: {exc}")
        return []


def _notify(report: dict) -> None:
    customer = report.get("customer_name") or "unknown"
    tenant = report.get("tenant_name") or ""
    version = report.get("yads_version") or ""
    description = (report.get("description") or "").strip()[:120]
    report_id = report.get("report_id", "?")

    summary = f"New Bug Report — {customer}"
    body_parts = []
    if tenant:
        body_parts.append(f"Tenant: {tenant}")
    if version:
        body_parts.append(f"Version: {version}")
    if description:
        body_parts.append(description)
    body_parts.append(f"ID: {report_id}")
    body = "\n".join(body_parts)

    try:
        subprocess.run(
            [
                "notify-send",
                "--app-name", NOTIFY_APP_NAME,
                "--icon", NOTIFY_ICON,
                "--urgency", "normal",
                summary,
                body,
            ],
            check=False,
            timeout=5,
        )
        _log(f"Notification sent for report {report_id} ({customer})")
    except FileNotFoundError:
        _log("WARNING: notify-send not found — cannot send desktop notification")
    except Exception as exc:
        _log(f"notify-send failed: {exc}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    _log("YADS Bug Report Watcher starting")

    cfg = _load_config()
    base_url = cfg.get("support_portal_url", "").strip()
    token = cfg.get("support_admin_token", "").strip()

    if not base_url:
        _log("ERROR: support_portal_url not set in config")
        sys.exit(1)
    if not token:
        _log("ERROR: support_admin_token not set in config")
        sys.exit(1)

    _log(f"Portal: {base_url} | Poll interval: {POLL_INTERVAL_SECONDS}s")

    # On first start, seed seen_ids with whatever exists now (don't spam old reports)
    seen_ids = _load_state()
    if not seen_ids:
        _log("First run — seeding state with existing reports (no notifications)")
        reports = _fetch_reports(base_url, token)
        seen_ids = {r["report_id"] for r in reports if "report_id" in r}
        _save_state(seen_ids)
        _log(f"Seeded {len(seen_ids)} existing report(s)")

    while True:
        try:
            reports = _fetch_reports(base_url, token)
            new_reports = [
                r for r in reports
                if r.get("report_id") and r["report_id"] not in seen_ids
            ]
            if new_reports:
                _log(f"Found {len(new_reports)} new report(s)")
                for report in new_reports:
                    _notify(report)
                    seen_ids.add(report["report_id"])
                _save_state(seen_ids)
            else:
                _log(f"No new reports (total known: {len(seen_ids)})")
        except Exception as exc:
            _log(f"Poll cycle error: {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
