#!/usr/bin/env python3
"""
YADS Support Watcher — System Tray Edition
==========================================
Runs silently in the system tray.

  🔴 Red badge   = open bug reports (status=new)
  🟢 Green badge = new contact requests from the website

Sends a desktop notification when a new report or contact request arrives.

Right-click menu:
  • "X neue Reports / Y neue Kontaktanfragen"
  • Im Browser öffnen
  • Als gelesen markieren
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


def _load_state() -> dict:
    """Return {'seen_report_ids': set, 'seen_contact_ids': set}."""
    if STATE_FILE.exists():
        try:
            raw = json.loads(STATE_FILE.read_text())
            return {
                "seen_report_ids":  set(raw.get("seen_report_ids",  raw.get("seen_ids", []))),
                "seen_contact_ids": set(raw.get("seen_contact_ids", [])),
            }
        except (json.JSONDecodeError, OSError):
            pass
    return {"seen_report_ids": set(), "seen_contact_ids": set()}


def _save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({
        "seen_report_ids":  list(state["seen_report_ids"]),
        "seen_contact_ids": list(state["seen_contact_ids"]),
    }, indent=2))


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def _fetch_json(url: str, token: str) -> dict | list:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        _log(f"HTTP {exc.code} from {url}: {exc.reason}")
    except urllib.error.URLError as exc:
        _log(f"Network error ({url}): {exc.reason}")
    except Exception as exc:
        _log(f"Fetch error: {exc}")
    return {}


def _fetch_reports(base_url: str, token: str) -> list:
    result = _fetch_json(base_url.rstrip("/") + "/api/admin/reports", token)
    return result.get("reports", []) if isinstance(result, dict) else []


def _fetch_contacts(base_url: str, token: str) -> list:
    result = _fetch_json(base_url.rstrip("/") + "/api/admin/contacts", token)
    return result.get("contacts", []) if isinstance(result, dict) else []


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def _notify_report(report: dict) -> None:
    customer    = report.get("customer_name") or "unknown"
    tenant      = report.get("tenant_name") or ""
    version     = report.get("yads_version") or ""
    topic       = report.get("topic") or ""
    description = (report.get("description") or "").strip()[:120]
    report_id   = report.get("report_id", "?")

    summary = f"Neuer Bug Report — {customer}"
    parts   = []
    if topic:       parts.append(f"Topic: {topic}")
    if tenant:      parts.append(f"Tenant: {tenant}")
    if version:     parts.append(f"Version: {version}")
    if description: parts.append(description)
    parts.append(f"ID: {report_id}")

    _send_notification(summary, "\n".join(parts))


def _notify_contact(contact: dict) -> None:
    name    = contact.get("name") or "Unbekannt"
    company = contact.get("company") or ""
    topic   = contact.get("topic") or ""
    msg     = (contact.get("message") or "").strip()[:120]
    cid     = contact.get("contact_id", "?")

    summary = f"Neue Kontaktanfrage — {name}"
    parts   = []
    if company: parts.append(f"Firma: {company}")
    if topic:   parts.append(f"Thema: {topic}")
    if msg:     parts.append(msg)
    parts.append(f"ID: {cid}")

    _send_notification(summary, "\n".join(parts))


def _send_notification(summary: str, body: str) -> None:
    try:
        subprocess.run(
            ["notify-send", "--app-name", NOTIFY_APP_NAME,
             "--icon", NOTIFY_ICON, "--urgency", "normal",
             summary, body],
            check=False, timeout=5,
        )
    except Exception as exc:
        _log(f"notify-send failed: {exc}")


# ---------------------------------------------------------------------------
# Tray icon rendering
# ---------------------------------------------------------------------------

def _make_icon_image(report_count: int, contact_count: int) -> Image.Image:
    base = Image.open(BASE_ICON).convert("RGBA").resize((64, 64), Image.LANCZOS)

    if report_count <= 0 and contact_count <= 0:
        return base

    img  = base.copy()
    draw = ImageDraw.Draw(img)

    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", size=14)
    except OSError:
        font = ImageFont.load_default()

    # Red badge (top-right) for open bug reports
    if report_count > 0:
        _draw_badge(draw, font, report_count, cx=64 - 15, cy=15, color=(220, 30, 30, 255))

    # Green badge (top-left) for new contact requests
    if contact_count > 0:
        _draw_badge(draw, font, contact_count, cx=15, cy=15, color=(34, 197, 94, 255))

    return img


def _draw_badge(draw: ImageDraw.ImageDraw, font, count: int,
                cx: int, cy: int, color: tuple) -> None:
    r    = 14
    text = str(count) if count < 100 else "99+"
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)
    bbox = draw.textbbox((0, 0), text, font=font)
    tw   = bbox[2] - bbox[0]
    th   = bbox[3] - bbox[1]
    draw.text((cx - tw // 2, cy - th // 2 - 1), text, fill="white", font=font)


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class SupportWatcher:
    def __init__(self, base_url: str, token: str):
        self.base_url      = base_url
        self.token         = token
        state              = _load_state()
        self.seen_reports  = state["seen_report_ids"]
        self.seen_contacts = state["seen_contact_ids"]
        self.report_count  = 0   # open (status=new) bug reports
        self.contact_count = 0   # unread contact requests
        self.tray_icon     = None

    # ---- tray ----

    def _update_tray(self):
        if not self.tray_icon:
            return
        self.tray_icon.icon  = _make_icon_image(self.report_count, self.contact_count)
        self.tray_icon.menu  = self._build_menu()

    def _build_menu(self) -> pystray.Menu:
        def _label(n, singular, plural):
            if n == 0:   return f"Keine {plural}"
            if n == 1:   return f"{n} {singular}"
            return f"{n} {plural}"

        return pystray.Menu(
            pystray.MenuItem(
                _label(self.report_count, "offener Report", "offene Reports"),
                None, enabled=False),
            pystray.MenuItem(
                _label(self.contact_count, "neue Kontaktanfrage", "neue Kontaktanfragen"),
                None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Im Browser öffnen",      self._open_browser),
            pystray.MenuItem("Als gelesen markieren",  self._mark_read,
                             enabled=(self.report_count > 0 or self.contact_count > 0)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Beenden", self._quit),
        )

    # ---- actions ----

    def _open_browser(self, icon=None, item=None):
        webbrowser.open(self.base_url.rstrip("/") + "/reports")

    def _mark_read(self, icon=None, item=None):
        self.report_count  = 0
        self.contact_count = 0
        self._update_tray()
        _log("Alle Reports/Kontaktanfragen als gelesen markiert")

    def _quit(self, icon=None, item=None):
        _log("Watcher beendet")
        self.tray_icon.stop()

    # ---- polling ----

    def _poll_loop(self):
        while True:
            try:
                self._do_poll()
            except Exception as exc:
                _log(f"Poll-Fehler: {exc}")
            time.sleep(POLL_INTERVAL_SECONDS)

    def _do_poll(self):
        # --- Bug reports ---
        reports     = _fetch_reports(self.base_url, self.token)
        open_count  = sum(1 for r in reports if r.get("status") == "new")
        new_reports = [r for r in reports
                       if r.get("report_id") and r["report_id"] not in self.seen_reports]
        for r in new_reports:
            _notify_report(r)
            self.seen_reports.add(r["report_id"])

        # --- Contact requests ---
        contacts     = _fetch_contacts(self.base_url, self.token)
        offen_count  = sum(1 for c in contacts if c.get("status") == "offen")
        new_contacts = [c for c in contacts
                        if c.get("contact_id") and c["contact_id"] not in self.seen_contacts]
        for c in new_contacts:
            _notify_contact(c)
            self.seen_contacts.add(c["contact_id"])

        if new_reports or new_contacts:
            _save_state({"seen_report_ids": self.seen_reports,
                         "seen_contact_ids": self.seen_contacts})

        if open_count != self.report_count or offen_count != self.contact_count:
            self.report_count  = open_count
            self.contact_count = offen_count
            self._update_tray()

        _log(f"Status: {open_count} offene Reports, {offen_count} offene Kontaktanfragen "
             f"(bekannt: {len(self.seen_reports)} rep / {len(self.seen_contacts)} cont)")

    # ---- startup ----

    def run(self):
        _log("Initial fetch on startup...")
        try:
            reports  = _fetch_reports(self.base_url, self.token)
            contacts = _fetch_contacts(self.base_url, self.token)

            first_run_reports  = not self.seen_reports
            first_run_contacts = not self.seen_contacts

            if first_run_reports:
                # Very first start — seed silently, no notifications
                self.seen_reports = {r["report_id"] for r in reports if "report_id" in r}
                _log(f"First run — seeding {len(self.seen_reports)} existing report(s)")
            else:
                # Subsequent start — notify about anything that arrived while we were down
                new_reports = [r for r in reports
                               if r.get("report_id") and r["report_id"] not in self.seen_reports]
                for r in new_reports:
                    _log(f"Startup: neue Report gefunden — {r.get('report_id')}")
                    _notify_report(r)
                    self.seen_reports.add(r["report_id"])
                if new_reports:
                    _log(f"Startup: {len(new_reports)} Report(s) während Offline verpasst, notifiziert")

            if first_run_contacts:
                self.seen_contacts = {c["contact_id"] for c in contacts if "contact_id" in c}
                _log(f"First run — seeding {len(self.seen_contacts)} existing contact(s)")
            else:
                new_contacts = [c for c in contacts
                                if c.get("contact_id") and c["contact_id"] not in self.seen_contacts]
                for c in new_contacts:
                    _log(f"Startup: neue Kontaktanfrage gefunden — {c.get('contact_id')}")
                    _notify_contact(c)
                    self.seen_contacts.add(c["contact_id"])
                if new_contacts:
                    _log(f"Startup: {len(new_contacts)} Kontaktanfrage(n) während Offline verpasst, notifiziert")

            _save_state({"seen_report_ids": self.seen_reports,
                         "seen_contact_ids": self.seen_contacts})

            # Badge = DB-driven counts (same pattern as reports)
            self.report_count  = sum(1 for r in reports if r.get("status") == "new")
            self.contact_count = sum(1 for c in contacts if c.get("status") == "offen")
            _log(f"Startup: {self.report_count} offene Reports, {self.contact_count} offene Kontaktanfragen")
        except Exception as exc:
            _log(f"Startup fetch failed: {exc}")

        t = threading.Thread(target=self._poll_loop, daemon=True)
        t.start()

        self.tray_icon = pystray.Icon(
            name  ="yads_support_watcher",
            icon  =_make_icon_image(self.report_count, self.contact_count),
            title ="YADS Support Watcher",
            menu  =self._build_menu(),
        )
        self.tray_icon.run()


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

def main():
    _log("YADS Support Watcher (tray) starting")

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
    SupportWatcher(base_url, token).run()


if __name__ == "__main__":
    main()
