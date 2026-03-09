import os
import smtplib
import ssl
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from email.message import EmailMessage
from typing import Optional, Union, List

logger = logging.getLogger("email_service")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - EMAIL_SERVICE - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="email")


def _get_config() -> dict:
    """Read SMTP config from SystemConfig DB, fallback to env vars."""
    cfg = {
        "host": os.environ.get("SMTP_HOST", ""),
        "port": int(os.environ.get("SMTP_PORT", "587")),
        "user": os.environ.get("SMTP_USER", ""),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "from_addr": os.environ.get("SMTP_FROM", "yads-donotreply@example.internal"),
        "tls": os.environ.get("SMTP_TLS", "true").lower() != "false",
    }
    try:
        from yads.database import engine
        from yads.models import SystemConfig
        from sqlmodel import Session
        with Session(engine) as session:
            for key, cfg_key in [
                ("SMTP_HOST", "host"), ("SMTP_PORT", "port"),
                ("SMTP_USER", "user"), ("SMTP_PASS", "password"),
                ("SMTP_PASSWORD", "password"),  # legacy key
                ("SMTP_FROM", "from_addr"), ("SMTP_TLS", "tls"),
            ]:
                val = session.get(SystemConfig, key)
                if val and val.value:
                    if cfg_key == "port":
                        try:
                            cfg[cfg_key] = int(val.value)
                        except ValueError:
                            pass
                    elif cfg_key == "tls":
                        cfg[cfg_key] = val.value.lower() != "false"
                    else:
                        cfg[cfg_key] = val.value
    except Exception:
        pass
    return cfg


def _wrap_html(body: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  body{{font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:20px}}
  .card{{background:#1e293b;border-radius:8px;padding:24px;max-width:600px;margin:0 auto}}
  h2{{color:#38bdf8;margin-top:0}}
  table{{width:100%;border-collapse:collapse;margin-top:12px}}
  th{{background:#0f172a;color:#94a3b8;text-align:left;padding:8px 12px;font-size:12px;text-transform:uppercase}}
  td{{padding:8px 12px;border-bottom:1px solid #334155;font-size:14px}}
  .badge-critical{{background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px}}
  .badge-high{{background:#ea580c;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px}}
  .badge-medium{{background:#ca8a04;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px}}
  .badge-low{{background:#16a34a;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px}}
  .footer{{margin-top:20px;font-size:12px;color:#64748b;text-align:center}}
  a{{color:#38bdf8}}
</style></head><body>
<div class="card">{body}
<div class="footer">YADS · Automated Security Report · Do not reply</div>
</div></body></html>"""


def _send_raw(subject: str, html_body: str, to_address: str) -> bool:
    cfg = _get_config()
    if not all([cfg["host"], cfg["port"], cfg["user"], cfg["password"]]):
        logger.warning("SMTP not configured, skipping email")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["from_addr"]
    msg["To"] = to_address
    msg.set_content("This email requires an HTML-capable email client.")
    msg.add_alternative(html_body, subtype="html")

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as server:
            if cfg["tls"]:
                server.starttls(context=ctx)
            server.login(cfg["user"], cfg["password"])
            server.send_message(msg)
        logger.info(f"Email sent to {to_address}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Email send failed to {to_address}: {e}")
        return False


class EmailService:
    def __init__(self):
        # Legacy compatibility: load config for .enabled check
        cfg = _get_config()
        self.smtp_host = cfg["host"]
        self.smtp_port = str(cfg["port"])
        self.smtp_user = cfg["user"]
        self.smtp_password = cfg["password"]
        self.sender_email = cfg["from_addr"]
        self.enabled = bool(cfg["host"] and cfg["user"] and cfg["password"])

    def send_mail(self, to_addr: Union[str, List[str]], subject: str, body_text: str, body_html: Optional[str] = None) -> bool:
        """Send a plain or HTML email (backwards-compatible method)."""
        if isinstance(to_addr, list):
            to_addr = ", ".join(to_addr)
        if body_html:
            return _send_raw(subject, body_html, to_addr)
        return _send_raw(subject, _wrap_html(f"<p>{body_text}</p>"), to_addr)

    @staticmethod
    def send_scan_finished(
        target_domain: str,
        target_id: int,
        changes: list,
        to_address: str,
        lang: str = "en",
        base_url: str = "",
    ):
        """Fire-and-forget: send notification when scan detects changes."""
        def _send():
            de = lang.lower().startswith("de")
            subject = (
                f"[YADS] Sicherheitsänderungen erkannt für {target_domain}"
                if de else
                f"[YADS] Security changes detected for {target_domain}"
            )
            date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            target_url = f"{base_url}/targets/{target_id}" if base_url else f"/targets/{target_id}"
            rows = "".join(
                f"<tr><td>{c.get('module_name', '-')}</td>"
                f"<td><span class='badge-{c.get('severity','medium').lower()}'>{c.get('severity','medium').upper()}</span></td>"
                f"<td>{c.get('description', '-')}</td></tr>"
                for c in changes[:50]
            )
            if de:
                body = f"""<h2>🔔 Sicherheitsänderungen erkannt</h2>
<p><strong>Domain:</strong> {target_domain}<br>
<strong>Datum:</strong> {date_str}<br>
<strong>Änderungen:</strong> {len(changes)}</p>
<table><tr><th>Modul</th><th>Schwere</th><th>Beschreibung</th></tr>{rows}</table>
<p style="margin-top:16px"><a href="{target_url}">→ Target in YADS öffnen</a></p>"""
            else:
                body = f"""<h2>🔔 Security Changes Detected</h2>
<p><strong>Domain:</strong> {target_domain}<br>
<strong>Date:</strong> {date_str}<br>
<strong>Changes:</strong> {len(changes)}</p>
<table><tr><th>Module</th><th>Severity</th><th>Description</th></tr>{rows}</table>
<p style="margin-top:16px"><a href="{target_url}">→ Open target in YADS</a></p>"""
            _send_raw(subject, _wrap_html(body), to_address)

        _executor.submit(_send)

    @staticmethod
    def send_daily_digest(
        tenant_name: str,
        targets_with_scores: list,
        to_address: str,
        lang: str = "en",
        base_url: str = "",
    ):
        """Fire-and-forget: send daily summary digest for a tenant."""
        def _send():
            de = lang.lower().startswith("de")
            date_str = datetime.utcnow().strftime("%Y-%m-%d")
            subject = (
                f"[YADS] Tägliche Sicherheitszusammenfassung — {date_str}"
                if de else
                f"[YADS] Daily Security Digest — {date_str}"
            )
            rows = ""
            for t in targets_with_scores[:100]:
                score = t.get("score")
                score_display = f"{score}" if score is not None else "-"
                changes = t.get("changes_count", 0)
                badge = f"<span class='badge-{'critical' if changes > 5 else 'high' if changes > 0 else 'low'}'>{changes}</span>"
                url = f"{base_url}/targets/{t['target_id']}" if base_url else "#"
                rows += (
                    f"<tr><td><a href='{url}'>{t['domain']}</a></td>"
                    f"<td>{t.get('last_scan', '-')}</td>"
                    f"<td>{score_display}</td>"
                    f"<td>{badge}</td></tr>"
                )
            if de:
                body = f"""<h2>📊 Tägliche Zusammenfassung — {tenant_name}</h2>
<p>Sicherheitsstatus für {len(targets_with_scores)} Ziele am {date_str}:</p>
<table>
<tr><th>Domain</th><th>Letzter Scan</th><th>Score</th><th>Änderungen</th></tr>
{rows}
</table>"""
            else:
                body = f"""<h2>📊 Daily Digest — {tenant_name}</h2>
<p>Security status for {len(targets_with_scores)} targets on {date_str}:</p>
<table>
<tr><th>Domain</th><th>Last Scan</th><th>Score</th><th>Changes</th></tr>
{rows}
</table>"""
            _send_raw(subject, _wrap_html(body), to_address)

        _executor.submit(_send)

    @staticmethod
    def send_test(to_address: str) -> bool:
        """Synchronous test email."""
        subject = "[YADS] Test Email"
        body = _wrap_html("<h2>✓ SMTP Configuration Working</h2><p>This is a test email from YADS.</p>")
        return _send_raw(subject, body, to_address)


# Singleton for legacy imports
email_service = EmailService()
