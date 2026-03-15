#!/usr/bin/env python3
"""
YADS Bug Report Watcher — System Tray Edition
==============================================
Runs silently in the system tray. Shows a red badge with the count of
unread (status=new) bug reports. Sends a desktop notification when a
new report arrives.

Right-click menu:
  • "X neue Reports" (disabled label)
  • Im Browser öffnen
  • Als gelesen markieren (clears badge)
  • ──────────────────
  • Beenden

Reads credentials from ~/.yads/release_gui.yaml:
  support_portal_url, support_admin_token

State: ~/.local/share/yads-watcher/state.json
Log:   ~/.local/share/yads-watcher/watcher.log
"""

import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

import pystray
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POLL_INTERVAL_SECONDS = 60
CONFIG_FILE = Path.home() / ".yads" / "release_gui.yaml"
STATE_FILE  = Path.home() / ".local" / "share" / "yads-watcher" / "state.json"
LOG_FILE    = Path.home() / ".local" / "share" / "yads-watcher" / "watcher.log"
BASE_ICON   = Path(__file__).parent.parent / "bug_watcher.png"

NOTIFY_APP_NAME = "YADS Support"
NOTIFY_ICON     = str(BASE_ICON)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    ts   = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Config / State
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    if not CONFIG_FILE.exists():
        _log(f"ERROR: Config not found: {CONFIG_FILE}")
        sys.exit(1)
    try:
        import yaml  # type: ignore
        with CONFIG_FILE.open() as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        data: dict = {}
        for line in CONFIG_FILE.read_text().splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                k, _, v = line.partition(":")
                data[k.strip()] = v.strip().strip("'\"")
        return data


def _load_state() -> set:
    if STATE_FILE.exists():
        try:
            return set(json.loads(STATE_FILE.read_text()).get("seen_ids", []))
        except (json.JSONDecodeError, OSError):
            pass
    return set()


def _save_state(seen_ids: set) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"seen_ids": list(seen_ids)}, indent=2))


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def _fetch_reports(base_url: str, token: str) -> list:
    url = base_url.rstrip("/") + "/api/admin/reports"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read()).get("reports", [])
    except urllib.error.HTTPError as exc:
        _log(f"HTTP {exc.code} from {url}: {exc.reason}")
    except urllib.error.URLError as exc:
        _log(f"Network error ({url}): {exc.reason}")
    except Exception as exc:
        _log(f"Fetch error: {exc}")
    return []


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def _notify(report: dict) -> None:
    customer    = report.get("customer_name") or "unknown"
    tenant      = report.get("tenant_name") or ""
    version     = report.get("yads_version") or ""
    topic       = report.get("topic") or ""
    description = (report.get("description") or "").strip()[:120]
    report_id   = report.get("report_id", "?")

    summary = f"Neuer Bug Report — {customer}"
    parts   = []
    if topic:
        parts.append(f"Topic: {topic}")
    if tenant:
        parts.append(f"Tenant: {tenant}")
    if version:
        parts.append(f"Version: {version}")
    if description:
        parts.append(description)
    parts.append(f"ID: {report_id}")

    try:
        subprocess.run(
            ["notify-send", "--app-name", NOTIFY_APP_NAME,
             "--icon", NOTIFY_ICON, "--urgency", "normal",
             summary, "\n".join(parts)],
            check=False, timeout=5,
        )
    except Exception as exc:
        _log(f"notify-send failed: {exc}")


# ---------------------------------------------------------------------------
# Tray icon rendering
# ---------------------------------------------------------------------------

def _make_icon_image(badge_count: int) -> Image.Image:
    base = Image.open(BASE_ICON).convert("RGBA").resize((64, 64), Image.LANCZOS)

    if badge_count <= 0:
        return base

    img  = base.copy()
    draw = ImageDraw.Draw(img)

    # Red circle — top-right quadrant
    r  = 14
    cx = 64 - r - 1
    cy = r + 1
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(220, 30, 30, 255))

    # White count text
    text = str(badge_count) if badge_count < 100 else "99+"
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                                  size=15)
    except OSError:
        font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), text, font=font)
    tw   = bbox[2] - bbox[0]
    th   = bbox[3] - bbox[1]
    draw.text((cx - tw // 2, cy - th // 2 - 1), text, fill="white", font=font)

    return img


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class BugWatcher:
    def __init__(self, base_url: str, token: str):
        self.base_url   = base_url
        self.token      = token
        self.seen_ids   = _load_state()
        self.new_count  = 0          # unread new reports
        self.tray_icon  = None       # pystray.Icon

    # ---- tray icon management ----

    def _update_tray(self):
        if not self.tray_icon:
            return
        self.tray_icon.icon  = _make_icon_image(self.new_count)
        self.tray_icon.menu  = self._build_menu()

    def _build_menu(self) -> pystray.Menu:
        label = (f"{self.new_count} neuer Report"
                 if self.new_count == 1
                 else f"{self.new_count} neue Reports") if self.new_count else "Keine neuen Reports"

        return pystray.Menu(
            pystray.MenuItem(label, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Im Browser öffnen",    self._open_browser),
            pystray.MenuItem("Als gelesen markieren", self._mark_read,
                             enabled=self.new_count > 0),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Beenden", self._quit),
        )

    # ---- actions ----

    def _open_browser(self, icon=None, item=None):
        webbrowser.open(self.base_url.rstrip("/") + "/reports")

    def _mark_read(self, icon=None, item=None):
        self.new_count = 0
        self._update_tray()
        _log("Alle Reports als gelesen markiert")

    def _quit(self, icon=None, item=None):
        _log("Watcher beendet")
        self.tray_icon.stop()

    # ---- polling thread ----

    def _poll_loop(self):
        while True:
            try:
                reports     = _fetch_reports(self.base_url, self.token)

                # Badge = live count of status=new reports
                open_count  = sum(1 for r in reports if r.get("status") == "new")

                # Notify for truly new (not seen before) reports
                new_reports = [r for r in reports
                               if r.get("report_id") and r["report_id"] not in self.seen_ids]
                if new_reports:
                    _log(f"{len(new_reports)} neue Report(s) gefunden")
                    for r in new_reports:
                        _notify(r)
                        self.seen_ids.add(r["report_id"])
                    _save_state(self.seen_ids)

                if open_count != self.new_count:
                    self.new_count = open_count
                    self._update_tray()

                _log(f"Status: {open_count} offene Reports (bekannt: {len(self.seen_ids)})")
            except Exception as exc:
                _log(f"Poll-Fehler: {exc}")

            time.sleep(POLL_INTERVAL_SECONDS)

    # ---- entry point ----

    def run(self):
        # Synchronous initial fetch BEFORE the tray is created.
        # This avoids a race where the poll thread runs _update_tray() while
        # self.tray_icon is still None and the update is silently dropped.
        _log("Initial fetch on startup...")
        try:
            reports = _fetch_reports(self.base_url, self.token)
            if not self.seen_ids:
                # First ever run: seed all existing IDs so we don't spam notifications
                _log("First run — seeding existing report IDs (no notifications)")
                self.seen_ids = {r["report_id"] for r in reports if "report_id" in r}
                _save_state(self.seen_ids)
                _log(f"Seeded {len(self.seen_ids)} existing report(s)")
            self.new_count = sum(1 for r in reports if r.get("status") == "new")
            _log(f"Startup: {self.new_count} offene Reports")
        except Exception as exc:
            _log(f"Startup fetch failed: {exc}")

        # Start background poll thread (seen_ids already populated)
        t = threading.Thread(target=self._poll_loop, daemon=True)
        t.start()

        # Build tray with the correct initial badge count
        self.tray_icon = pystray.Icon(
            name   ="yads_bugreport_watcher",
            icon   =_make_icon_image(self.new_count),
            title  ="YADS Bug Report Watcher",
            menu   =self._build_menu(),
        )
        self.tray_icon.run()


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

def main():
    _log("YADS Bug Report Watcher (tray) starting")

    cfg      = _load_config()
    base_url = cfg.get("support_portal_url", "").strip()
    token    = cfg.get("support_admin_token", "").strip()

    if not base_url:
        _log("ERROR: support_portal_url not set in config")
        sys.exit(1)
    if not token:
        _log("ERROR: support_admin_token not set in config")
        sys.exit(1)

    _log(f"Portal: {base_url} | Poll: {POLL_INTERVAL_SECONDS}s")
    BugWatcher(base_url, token).run()


if __name__ == "__main__":
    main()
