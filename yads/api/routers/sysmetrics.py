"""
System Metrics & Resource-Check Endpoints

/api/system/metrics        — HTMX topbar fragment (CPU / RAM / net)
/api/system/scan-errors    — HTMX topbar fragment (scan error badge, tenant-scoped)
/api/system/resource-check — Inline validation warnings for worker config modal
"""

from typing import Optional, Annotated
from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from yads.api.templating import templates

from yads.auth.deps import get_current_user_html, get_current_user_html_optional, PlatformAdminChecker
from yads.models import User

router = APIRouter(prefix="/api/system", tags=["system-metrics"])
ui_router = APIRouter(tags=["system-ui"])
 
_SCAN_ERRORS_BADGE = 'id="scan-errors-badge"'

# ── Thresholds ────────────────────────────────────────────────────────────────
_RAM_PER_TASK_GB   = 0.5   # conservative estimate: 512 MB per concurrent scan
_RAM_WARN_PCT      = 0.80  # warn above 80 % projected RAM usage
_RAM_CRIT_PCT      = 1.00  # error above 100 %
_CPU_WARN_FACTOR   = 2.0   # warn if tasks > cpu_count * 2
_CPU_CRIT_FACTOR   = 3.0   # error if tasks > cpu_count * 3
_NET_WARN_PCT      = 0.75  # warn if requested limit > 75 % of measured throughput baseline
_NET_MIN_SAMPLE_MB = 1.0   # only apply net-check when we have a real measurement


def _color(value: float, warn: float = 60.0, crit: float = 85.0) -> str:
    if value >= crit:
        return "text-red-400"
    if value >= warn:
        return "text-amber-400"
    return "text-emerald-400"


def _bar_color(value: float, warn: float = 60.0, crit: float = 85.0) -> str:
    if value >= crit:
        return "bg-red-500"
    if value >= warn:
        return "bg-amber-500"
    return "bg-emerald-500"


def _redis_client():
    from yads.config import settings
    import redis as redis_lib
    return redis_lib.from_url(settings.REDIS_URL, socket_connect_timeout=1)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _warn_box(level: str, title: str, detail: str) -> str:
    """Render a single warning/error/info box."""
    styles = {
        "error":   ("bg-red-900/40 border-red-700/60 text-red-300",   "text-red-400",   "✗"),
        "warning": ("bg-amber-900/40 border-amber-700/60 text-amber-300", "text-amber-400", "⚠"),
        "info":    ("bg-blue-900/30 border-blue-700/50 text-blue-300", "text-blue-400",  "ℹ"),
    }
    box_cls, title_cls, icon = styles.get(level, styles["info"])
    return (
        f'<div class="flex gap-2 p-3 rounded-lg border text-xs {box_cls}">'
        f'  <span class="{title_cls} flex-shrink-0 font-bold mt-0.5">{icon}</span>'
        f'  <div><span class="font-semibold">{title}</span>'
        f'  <span class="ml-1 opacity-80">{detail}</span></div>'
        f'</div>'
    )


# ── /api/system/metrics ───────────────────────────────────────────────────────

_EMPTY_WIDGET = (
    '<div id="sysmetrics-widget"'
    ' class="hidden md:flex items-center gap-3 text-xs text-slate-600 font-mono"'
    ' hx-get="/api/system/metrics" hx-trigger="every 5s" hx-swap="outerHTML">'
    '<span>— / — / —</span>'
    '</div>'
)


@router.get("/metrics", response_class=HTMLResponse)
async def system_metrics_fragment(
    request: Request,
    user: Annotated[Optional[User], Depends(get_current_user_html_optional)],
):
    """
    HTMX fragment: live CPU / RAM / network stats for the topbar.
    Polled every 3–5 seconds. Uses optional auth so an expired session
    never destroys the widget — it just goes quiet until re-login.
    """
    if not user:
        # Not logged in (or session expired) — return silent placeholder,
        # keep polling so widget recovers automatically after re-login.
        return HTMLResponse(_EMPTY_WIDGET)

    from yads.core import system_metrics
    m = system_metrics.get(_redis_client())

    if not m:
        # Redis unavailable or collector not yet started — keep polling
        return HTMLResponse(_EMPTY_WIDGET)

    cpu   = m["cpu_percent"]
    mem_u = m["mem_used_gb"]
    mem_t = m["mem_total_gb"]
    mem_p = m["mem_percent"]
    nin   = m["net_in_mbps"]
    nout  = m["net_out_mbps"]

    cpu_bar  = min(int(cpu),  100)
    mem_bar  = min(int(mem_p), 100)

    return HTMLResponse(f'''
<div id="sysmetrics-widget"
     class="hidden md:flex items-center gap-4 text-xs font-mono"
     hx-get="/api/system/metrics"
     hx-trigger="every 3s"
     hx-swap="outerHTML">

  <!-- CPU -->
  <div class="flex items-center gap-1.5" title="CPU utilization">
    <svg class="w-3.5 h-3.5 text-slate-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M9 3H7a2 2 0 00-2 2v2M9 3h6M9 3v18m6-18h2a2 2 0 012 2v2m0 0v10a2 2 0 01-2 2h-2m0 0H9m6 0v-2M3 9h2m0 6H3m18-6h-2m0 6h2"/>
    </svg>
    <div class="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden">
      <div class="h-1.5 rounded-full transition-all {_bar_color(cpu)}" style="width:{cpu_bar}%"></div>
    </div>
    <span class="{_color(cpu)} tabular-nums">{cpu:.0f}%</span>
  </div>

  <!-- RAM -->
  <div class="flex items-center gap-1.5" title="RAM usage">
    <svg class="w-3.5 h-3.5 text-slate-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
    </svg>
    <div class="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden">
      <div class="h-1.5 rounded-full transition-all {_bar_color(mem_p)}" style="width:{mem_bar}%"></div>
    </div>
    <span class="{_color(mem_p)} tabular-nums">{mem_u:.1f}<span class="text-slate-600">/{mem_t:.0f}G</span></span>
  </div>

  <!-- Network -->
  <div class="flex items-center gap-1" title="Network throughput">
    <svg class="w-3.5 h-3.5 text-slate-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"/>
    </svg>
    <span class="text-cyan-400 tabular-nums">↑{nout:.1f}</span>
    <span class="text-slate-600">/</span>
    <span class="text-indigo-400 tabular-nums">↓{nin:.1f}</span>
    <span class="text-slate-600 text-[10px]">Mb/s</span>
  </div>

</div>
''')


# ── /api/system/scan-errors ───────────────────────────────────────────────────

@router.get("/scan-errors", response_class=HTMLResponse)
async def scan_errors_fragment(
    request: Request,
    user: Annotated[User, Depends(get_current_user_html)],
):
    """
    HTMX fragment: scan error badge for the topbar.
    Tenant-scoped — only shows errors from the user's own tenant.
    Polled every 30s. Empty div when no errors.
    """
    from yads.core.watcher import get_scan_errors_for_tenant

    tenant_id = user.tenant_id
    if not tenant_id:
        # Platform admins have no tenant — skip
        return HTMLResponse(
            '<div id="scan-errors-badge"'
            ' hx-get="/api/system/scan-errors" hx-trigger="every 30s" hx-swap="outerHTML">'
            '</div>'
        )

    errors = get_scan_errors_for_tenant(_redis_client(), tenant_id)

    if not errors:
        return HTMLResponse(
            '<div id="scan-errors-badge"'
            ' hx-get="/api/system/scan-errors" hx-trigger="every 30s" hx-swap="outerHTML">'
            '</div>'
        )

    affected = len(errors)
    label = f"{affected} Scan{'s' if affected > 1 else ''} fehlgeschlagen"

    # Build dropdown items
    items_html = ""
    for e in errors:
        domain = e.get("domain", "?")
        count = e.get("count", 1)
        first_err = e.get("errors", [""])[0][:120]
        target_id = e.get("target_id")
        items_html += f'''
        <a href="/targets/{target_id}" class="flex gap-2 py-2 border-b border-slate-700/50 last:border-0 hover:bg-slate-800/50 rounded px-1 transition-colors">
          <span class="text-red-400 font-bold flex-shrink-0">✗</span>
          <div class="min-w-0">
            <div class="text-slate-200 text-xs font-semibold truncate">{domain}</div>
            <div class="text-slate-400 text-[10px] truncate">{first_err}</div>
            {'<div class="text-slate-500 text-[10px]">+' + str(count-1) + ' weitere Fehler</div>' if count > 1 else ''}
          </div>
        </a>'''

    return HTMLResponse(f'''
<div {_SCAN_ERRORS_BADGE}
     hx-get="/api/system/scan-errors" hx-trigger="every 30s" hx-swap="outerHTML"
     class="relative"
     x-data="{{ open: false }}">

  <button @click="open = !open"
          class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-red-700/60 bg-red-900/40 text-red-300 text-xs font-semibold transition-colors hover:bg-red-900/60">
    <span class="text-red-400">✗</span>
    <span>{label}</span>
    <svg class="w-3 h-3 transition-transform" :class="open ? \'rotate-180\' : \'\'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
    </svg>
  </button>

  <div x-show="open" @click.outside="open = false"
       x-transition:enter="transition ease-out duration-100"
       x-transition:enter-start="opacity-0 scale-95"
       x-transition:enter-end="opacity-100 scale-100"
       class="absolute right-0 top-full mt-2 w-80 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl z-50 p-3">
    <p class="text-[10px] text-slate-500 uppercase tracking-wider mb-2 font-semibold">Scan-Fehler</p>
    {items_html}
    <form hx-post="/api/system/scan-errors/dismiss" hx-target="#scan-errors-badge" hx-swap="outerHTML" class="mt-3">
      <button type="submit" class="w-full text-center text-xs text-slate-400 hover:text-slate-200 transition-colors py-1">
        Alle ausblenden
      </button>
    </form>
  </div>
</div>
''')


@router.post("/scan-errors/dismiss", response_class=HTMLResponse)
async def dismiss_scan_errors(
    request: Request,
    user: Annotated[User, Depends(get_current_user_html)],
):
    """Dismiss all scan error notifications for the current tenant."""
    from yads.core.watcher import clear_scan_errors_for_tenant
    if user.tenant_id:
        clear_scan_errors_for_tenant(_redis_client(), user.tenant_id)
    return HTMLResponse(
        '<div id="scan-errors-badge"'
        ' hx-get="/api/system/scan-errors" hx-trigger="every 30s" hx-swap="outerHTML">'
        '</div>'
    )


# ── /api/system/bug-report ────────────────────────────────────────────────────

@router.get("/bug-report", response_class=HTMLResponse)
async def bug_report_fragment(
    request: Request,
    user: Annotated[User, Depends(get_current_user_html)],
):
    """
    HTMX fragment: auto-populated bug report text for /help/bug-report.
    Returns a <pre> block with version, tenant, user, active errors/alerts.
    """
    from datetime import datetime, timezone
    from yads.config import settings

    tenant_name = "N/A"
    try:
        if user.tenant_id:
            from sqlmodel import Session
            from yads.database import engine
            from yads.models import Tenant
            with Session(engine) as session:
                t = session.get(Tenant, user.tenant_id)
                if t:
                    tenant_name = t.name
    except Exception:
        pass

    # Recent scan errors (last 5)
    error_lines = []
    try:
        from yads.core.watcher import get_scan_errors_for_tenant
        if user.tenant_id:
            errs = get_scan_errors_for_tenant(_redis_client(), user.tenant_id)
            for e in (errs or [])[-5:]:
                error_lines.append(f"  • {e}")
    except Exception:
        pass

    # Active system alerts
    alert_lines = []
    try:
        import json as _json
        raw = _redis_client().get("yads:alerts:active")
        if raw:
            for a in _json.loads(raw):
                sev = a.get("severity", "?").upper()
                alert_lines.append(f"  • [{sev}] {a.get('check_name','?')}: {a.get('message','')}")
    except Exception:
        pass

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ua = request.headers.get("user-agent", "unknown")[:120]

    lines = [
        "=== YADS Bug Report ===",
        "",
        f"Version   : {settings.VERSION}",
        f"Datum     : {now}",
        f"Tenant    : {tenant_name}",
        f"Benutzer  : {user.username}",
        f"Browser   : {ua}",
        "",
        "--- Fehlerbeschreibung ---",
        "[Bitte hier beschreiben, was passiert ist]",
        "",
        "--- Betroffene URL / Seite ---",
        "[z.B. https://prod.../targets/42]",
        "",
    ]
    if error_lines:
        lines += ["--- Letzte Scan-Fehler (automatisch) ---"] + error_lines + [""]
    if alert_lines:
        lines += ["--- Aktive System-Alerts (automatisch) ---"] + alert_lines + [""]

    lines += [
        f"======================",
        f"Bitte senden an : support@yads-security.com",
        f"Betreff          : Bug Report YADS v{settings.VERSION}",
    ]

    report_text = "\n".join(lines)

    # Build mailto href (subject + plain body)
    import urllib.parse
    subject = urllib.parse.quote(f"Bug Report YADS v{settings.VERSION}")
    body = urllib.parse.quote(report_text)
    mailto = f"mailto:support@yads-security.com?subject={subject}&body={body}"

    # Escape for HTML display
    display_text = (report_text
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;"))

    return HTMLResponse(f'''
<div id="bug-report-fragment">
  <pre id="bug-report-pre"
       class="bg-slate-900 border border-slate-700 rounded-xl p-4 text-xs text-slate-300
              font-mono whitespace-pre overflow-x-auto leading-relaxed select-all"
  >{display_text}</pre>

  <div class="flex flex-wrap gap-3 mt-4">
    <button onclick="copyBugReport()"
            class="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500
                   text-white text-sm font-medium rounded-lg transition-colors">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
      </svg>
      <span id="copy-btn-label">In Zwischenablage kopieren</span>
    </button>

    <a href="{mailto}"
       class="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600
              text-slate-200 text-sm font-medium rounded-lg transition-colors">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
      </svg>
      Im E-Mail-Programm öffnen
    </a>
  </div>

  <p class="mt-3 text-xs text-slate-500">
    Tipp: Du kannst den Text oben direkt bearbeiten, bevor du ihn kopierst. Das Feld ist vollständig selektierbar.
  </p>
</div>

<script>
function copyBugReport() {{
    const pre = document.getElementById('bug-report-pre');
    const label = document.getElementById('copy-btn-label');
    navigator.clipboard.writeText(pre.innerText).then(() => {{
        label.textContent = '✓ Kopiert!';
        setTimeout(() => label.textContent = 'In Zwischenablage kopieren', 2500);
    }}).catch(() => {{
        // Fallback: select all
        const sel = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(pre);
        sel.removeAllRanges();
        sel.addRange(range);
    }});
}}
</script>
''')


# ── /api/system/resource-check ────────────────────────────────────────────────

@router.get("/resource-check", response_class=HTMLResponse)
async def resource_check(
    user: Annotated[User, Depends(PlatformAdminChecker())],
    node_id: Annotated[str, Query(...)],
    tasks: Annotated[int, Query(..., ge=1, le=500)],
    net_mbps: Annotated[float, Query(..., ge=0)],
):
    """
    Inline resource validation for the worker config modal.
    Returns an HTML fragment with zero or more warning/error boxes.
    Called on every input change (debounced 600ms via HTMX).
    """
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import WorkerNode
    from yads.core import system_metrics

    boxes: list[str] = []

    # ── Fetch worker hardware info ────────────────────────────────────────────
    with Session(engine) as session:
        worker = session.exec(
            select(WorkerNode).where(WorkerNode.node_id == node_id)
        ).first()

    cpu_count  = worker.cpu_count  if worker and worker.cpu_count  else None
    memory_mb  = worker.memory_mb  if worker and worker.memory_mb  else None
    is_primary = worker.is_primary if worker else False

    # ── RAM check ─────────────────────────────────────────────────────────────
    if memory_mb:
        mem_total_gb  = memory_mb / 1024
        required_gb   = tasks * _RAM_PER_TASK_GB
        usage_pct     = required_gb / mem_total_gb if mem_total_gb > 0 else 0

        if usage_pct >= _RAM_CRIT_PCT:
            boxes.append(_warn_box(
                "error",
                "RAM-Überlastung möglich.",
                f"{tasks} Tasks × ~{int(_RAM_PER_TASK_GB*1024)} MB = "
                f"~{required_gb:.1f} GB benötigt, aber nur {mem_total_gb:.1f} GB verfügbar. "
                "Reduziere die Anzahl gleichzeitiger Tasks."
            ))
        elif usage_pct >= _RAM_WARN_PCT:
            boxes.append(_warn_box(
                "warning",
                "Hohe RAM-Auslastung erwartet.",
                f"~{required_gb:.1f} GB von {mem_total_gb:.1f} GB "
                f"({usage_pct*100:.0f}%) würden belegt. "
                "Puffer für OS und andere Prozesse einplanen."
            ))

    # ── CPU check ─────────────────────────────────────────────────────────────
    if cpu_count:
        if tasks > cpu_count * _CPU_CRIT_FACTOR:
            boxes.append(_warn_box(
                "error",
                "Kritisches CPU-Overcommit.",
                f"{tasks} Tasks auf {cpu_count} Kernen "
                f"({tasks/cpu_count:.1f}×). "
                "Scans werden sich stark verlangsamen und Timeouts riskieren."
            ))
        elif tasks > cpu_count * _CPU_WARN_FACTOR:
            boxes.append(_warn_box(
                "warning",
                "CPU-Overcommit.",
                f"{tasks} Tasks auf {cpu_count} Kernen "
                f"({tasks/cpu_count:.1f}×). "
                "Empfohlen: max. {int(cpu_count * _CPU_WARN_FACTOR)} Tasks für diesen Worker."
            ))

    # ── Network check (primary worker: use live metrics as baseline) ──────────
    if is_primary and net_mbps > 0:
        m = system_metrics.get(_redis_client())
        if m:
            current_total = m["net_in_mbps"] + m["net_out_mbps"]
            if current_total >= _NET_MIN_SAMPLE_MB and net_mbps < current_total:
                boxes.append(_warn_box(
                    "error",
                    "Netzlimit unter aktueller Auslastung.",
                    f"Aktuell werden {current_total:.1f} Mb/s gemessen, "
                    f"aber das Limit ist auf {net_mbps:.1f} Mb/s gesetzt. "
                    "Scans werden sofort gedrosselt."
                ))
            elif current_total >= _NET_MIN_SAMPLE_MB and net_mbps < current_total / _NET_WARN_PCT:
                boxes.append(_warn_box(
                    "warning",
                    "Netzwerkpuffer gering.",
                    f"Konfiguriertes Limit ({net_mbps:.1f} Mb/s) liegt nah an der "
                    f"aktuellen Auslastung ({current_total:.1f} Mb/s). "
                    "Bei Lastspitzen kann das Limit überschritten werden."
                ))
    elif not is_primary and net_mbps > 0:
        # For secondary workers we can only give a generic hint
        if net_mbps > 1000:
            boxes.append(_warn_box(
                "info",
                "Bandbreite prüfen.",
                f"{net_mbps:.0f} Mb/s konfiguriert. "
                "Stelle sicher, dass der Netzwerkanschluss dieses Workers "
                "diese Bandbreite tatsächlich unterstützt."
            ))

    # ── All good ──────────────────────────────────────────────────────────────
    if not boxes:
        return HTMLResponse(
            '<div id="resource-warnings" class="flex items-center gap-1.5 text-xs text-emerald-400">'
            '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">'
            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>'
            '</svg>Konfiguration sieht gut aus.</div>'
        )

    return HTMLResponse(
        f'<div id="resource-warnings" class="space-y-2">'
        + "".join(boxes)
        + "</div>"
    )


# ── /api/system/alerts ────────────────────────────────────────────────────────

@router.get("/alerts", response_class=HTMLResponse)
async def system_alerts_fragment(
    request: Request,
    user: Annotated[User, Depends(PlatformAdminChecker())],
):
    """
    HTMX fragment: alert banner for the topbar.
    Polled every 30s. Returns an empty div when all is healthy.
    """
    from yads.core import watcher

    alerts = watcher.get_active_alerts(_redis_client())

    errors   = [a for a in alerts if a["severity"] == "error"]
    warnings = [a for a in alerts if a["severity"] == "warning"]

    if not alerts:
        return HTMLResponse(
            '<div id="system-alerts-banner" '
            'hx-get="/api/system/alerts" hx-trigger="every 30s" hx-swap="outerHTML">'
            '</div>'
        )

    # Build the collapsed banner
    total = len(alerts)
    label = f"{total} Systemfehler" if errors else f"{total} Systemwarnung{'en' if total > 1 else ''}"
    banner_cls = "bg-red-900/80 border-red-700/70 text-red-200" if errors else "bg-amber-900/70 border-amber-700/60 text-amber-200"
    icon = "✗" if errors else "⚠"

    # Build dropdown items
    items_html = ""
    for a in alerts:
        sev_cls = "text-red-400" if a["severity"] == "error" else "text-amber-400"
        icon_sev = "✗" if a["severity"] == "error" else "⚠"
        items_html += (
            f'<div class="flex gap-2 py-2 border-b border-slate-700/50 last:border-0">'
            f'  <span class="{sev_cls} font-bold flex-shrink-0">{icon_sev}</span>'
            f'  <span class="text-slate-200 text-xs">{a["message"]}</span>'
            f'</div>'
        )

    return HTMLResponse(f'''
<div id="system-alerts-banner"
     hx-get="/api/system/alerts" hx-trigger="every 30s" hx-swap="outerHTML"
     class="relative"
     x-data="{{ open: false }}">

  <button @click="open = !open"
          class="flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-colors {banner_cls}">
    <span>{icon}</span>
    <span>{label}</span>
    <svg class="w-3 h-3 transition-transform" :class="open ? 'rotate-180' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
    </svg>
  </button>

  <div x-show="open" @click.outside="open = false"
       x-transition:enter="transition ease-out duration-100"
       x-transition:enter-start="opacity-0 scale-95"
       x-transition:enter-end="opacity-100 scale-100"
       class="absolute right-0 top-full mt-2 w-96 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl z-50 p-3 space-y-0">
    <p class="text-[10px] text-slate-500 uppercase tracking-wider mb-2 font-semibold">Aktive System-Alerts</p>
    {items_html}
    <a href="/system/alerts" class="block mt-2 text-center text-xs text-slate-400 hover:text-slate-200 transition-colors">
      Alert-Verlauf anzeigen →
    </a>
    <a href="/help/bug-report" class="block mt-1 text-center text-xs text-red-400 hover:text-red-300 transition-colors">
      Bug melden (Auto-Fill) →
    </a>
  </div>
</div>
''')


# ── /system/alerts  (history page) ───────────────────────────────────────────

@ui_router.get("/system/alerts", response_class=HTMLResponse)
async def system_alerts_page(
    request: Request,
    user: User = Depends(PlatformAdminChecker()),
):
    from datetime import datetime, timedelta
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import SystemAlertLog
    from yads.core import watcher

    since = datetime.now(timezone.utc) - timedelta(days=7)
    with Session(engine) as session:
        logs = session.exec(
            select(SystemAlertLog)
            .where(SystemAlertLog.fired_at >= since)
            .order_by(SystemAlertLog.fired_at.desc())
            .limit(200)
        ).all()

    active = watcher.get_active_alerts(_redis_client())

    return templates.TemplateResponse("system_alerts.html", {
        "request": request,
        "user": user,
        "logs": logs,
        "active": active,
    })


# ── /api/system/alerts/{id}/resolve ──────────────────────────────────────────

@router.post("/alerts/{alert_id}/resolve", response_class=HTMLResponse)
async def resolve_alert(
    alert_id: int,
    user: Annotated[User, Depends(PlatformAdminChecker())],
):
    """Manually mark a SystemAlertLog entry as resolved."""
    from datetime import datetime, timezone
    from sqlmodel import Session
    from yads.database import engine
    from yads.models import SystemAlertLog

    with Session(engine) as session:
        log = session.get(SystemAlertLog, alert_id)
        if not log:
            return HTMLResponse('<span class="text-red-400 text-xs">Not found</span>', status_code=404)
        if not log.resolved_at:
            log.resolved_at = datetime.now(timezone.utc)
            session.add(log)
            session.commit()
    return HTMLResponse('<span class="text-emerald-400 text-xs">✓ resolved</span>')


# ── /api/system/health-summary  (HTMX fragment for Operations Center) ─────────

def _svc_status(alerts: list[dict], check_names: list[str]) -> tuple[str, str]:
    """Return (css_class, label) for a service based on matching active alerts."""
    for a in alerts:
        if a.get("check_name") in check_names:
            if a["severity"] == "error":
                return "error", a["message"]
            return "warning", a["message"]
    return "ok", "OK"


def _status_dot(status: str) -> str:
    colors = {"ok": "bg-emerald-500", "warning": "bg-amber-500", "error": "bg-red-500"}
    pulse = ' animate-pulse' if status != "ok" else ''
    return f'<span class="inline-block w-2.5 h-2.5 rounded-full {colors.get(status, "bg-slate-500")}{pulse}"></span>'


def _svc_card(icon_svg: str, name: str, status: str, detail: str, link: str) -> str:
    border = {
        "ok":      "border-slate-700 bg-slate-900/60",
        "warning": "border-amber-700/60 bg-amber-900/10",
        "error":   "border-red-700/60 bg-red-900/10",
    }.get(status, "border-slate-700 bg-slate-900/60")
    label_cls = {
        "ok":      "text-emerald-400",
        "warning": "text-amber-400",
        "error":   "text-red-400",
    }.get(status, "text-slate-400")
    icon_cls = {
        "ok":      "text-emerald-400",
        "warning": "text-amber-400",
        "error":   "text-red-400",
    }.get(status, "text-slate-400")
    detail_escaped = detail.replace("<", "&lt;").replace(">", "&gt;")[:80]
    return f'''
<a href="{link}" class="flex flex-col gap-2 p-4 rounded-xl border {border} hover:border-slate-500 transition-all group">
  <div class="flex items-center gap-2.5">
    <span class="{icon_cls} flex-shrink-0">{icon_svg}</span>
    <span class="text-sm font-semibold text-slate-200">{name}</span>
    <span class="ml-auto">{_status_dot(status)}</span>
  </div>
  <div class="flex items-center gap-1.5">
    <span class="text-xs font-bold {label_cls}">{status.upper()}</span>
    <span class="text-xs text-slate-500 truncate">{detail_escaped}</span>
  </div>
</a>'''


@router.get("/health-summary", response_class=HTMLResponse)
async def health_summary_fragment(
    request: Request,
    user: Annotated[User, Depends(PlatformAdminChecker())],
):
    """
    HTMX fragment: full Operations Center live content.
    Polled every 30s from /system/health.
    """
    from datetime import datetime, timedelta
    from yads.core import watcher, system_metrics
    from yads.core.worker_manager import worker_manager

    rc = _redis_client()
    alerts = watcher.get_active_alerts(rc)

    # ── Service status cards ───────────────────────────────────────────────────
    redis_status, redis_detail = _svc_status(alerts, ["redis_connection"])
    db_status,    db_detail    = _svc_status(alerts, ["db_connection"])
    disk_status,  disk_detail  = _svc_status(alerts, ["disk_space"])
    queue_status, queue_detail = _svc_status(alerts, ["celery_queue"])

    # Queue depth for display
    try:
        queue_depth = rc.llen("celery")
        if queue_status == "ok":
            queue_detail = f"{queue_depth} Tasks"
    except Exception:
        queue_depth = 0

    icon_redis = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"/></svg>'
    icon_db    = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/></svg>'
    icon_disk  = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"/></svg>'
    icon_queue = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>'

    cards_html = (
        _svc_card(icon_redis, "Redis",     redis_status, redis_detail, "/system/alerts") +
        _svc_card(icon_db,    "Datenbank", db_status,    db_detail,    "/system/alerts") +
        _svc_card(icon_disk,  "Festplatte",disk_status,  disk_detail,  "/system/alerts") +
        _svc_card(icon_queue, "Queue",     queue_status, queue_detail, "/system/alerts")
    )

    # ── Active alerts list ─────────────────────────────────────────────────────
    errors   = [a for a in alerts if a["severity"] == "error"]
    warnings = [a for a in alerts if a["severity"] == "warning"]

    if not alerts:
        alerts_html = '''
<div class="flex items-center gap-2 text-emerald-400 text-sm p-4 bg-emerald-900/20 border border-emerald-700/30 rounded-xl">
  <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
  </svg>
  Alle Health-Checks OK — keine aktiven Alerts.
</div>'''
    else:
        rows = ""
        for a in errors + warnings:
            sev_cls  = "text-red-400 bg-red-900/50 border-red-700/40" if a["severity"] == "error" else "text-amber-400 bg-amber-900/50 border-amber-700/40"
            icon_sev = "✗" if a["severity"] == "error" else "⚠"
            detail_json = a.get("detail") or {}
            if isinstance(detail_json, str):
                import json as _json
                try:
                    detail_json = _json.loads(detail_json)
                except Exception:
                    detail_json = {}
            detail_parts = ", ".join(f"{k}={v}" for k, v in detail_json.items() if k not in ("node_id",))
            rows += f'''
<div class="flex items-start gap-3 p-3 rounded-lg border border-slate-700/50 bg-slate-900/50">
  <span class="text-xs font-bold px-1.5 py-0.5 rounded border {sev_cls} flex-shrink-0 mt-0.5">{icon_sev}</span>
  <div class="min-w-0">
    <span class="text-sm text-white">{a["message"]}</span>
    <div class="flex items-center gap-2 mt-1">
      <span class="text-[10px] font-mono text-slate-500">{a["check_name"]}</span>
      {f'<span class="text-[10px] text-slate-600">{detail_parts}</span>' if detail_parts else ''}
    </div>
  </div>
</div>'''
        alerts_html = f'''
<div class="space-y-2">
  {rows}
  <div class="flex items-center justify-center gap-4 pt-1">
    <a href="/system/alerts" class="text-xs text-indigo-400 hover:text-indigo-300 transition-colors">Vollständiger Alert-Verlauf →</a>
    <a href="/help/bug-report" class="text-xs text-red-400 hover:text-red-300 transition-colors">Bug melden →</a>
  </div>
</div>'''

    # ── Workers ────────────────────────────────────────────────────────────────
    try:
        workers = worker_manager.get_worker_list()
    except Exception:
        workers = []

    # Map worker alerts by node_id
    worker_alert_map: dict[str, str] = {}
    for a in alerts:
        cn = a.get("check_name", "")
        if cn.startswith("worker_heartbeat_"):
            nid = cn[len("worker_heartbeat_"):]
            worker_alert_map[nid] = a["severity"]

    if workers:
        worker_cards = ""
        for w in workers:
            nid    = w.get("node_id", "")
            host   = w.get("hostname", nid)
            status = w.get("status", "unknown")
            tasks  = w.get("current_tasks", 0)
            cap    = w.get("max_tasks", 0)
            last   = w.get("last_seen", "")

            # Determine visual status: alert overrides DB status
            vis = worker_alert_map.get(nid, None)
            if vis is None:
                if status == "active":
                    vis = "ok"
                elif status in ("offline", "draining"):
                    vis = "error"
                else:
                    vis = "warning"

            status_colors = {
                "ok":      ("border-emerald-800/40 bg-slate-900/60", "text-emerald-400", "bg-emerald-500"),
                "warning": ("border-amber-700/50 bg-amber-900/10",   "text-amber-400",   "bg-amber-500"),
                "error":   ("border-red-700/50 bg-red-900/10",       "text-red-400",     "bg-red-500"),
            }.get(vis, ("border-slate-700 bg-slate-900/60", "text-slate-400", "bg-slate-500"))

            pct = int(tasks / cap * 100) if cap > 0 else 0
            bar_color = "bg-emerald-500" if pct < 60 else ("bg-amber-500" if pct < 80 else "bg-red-500")

            worker_cards += f'''
<a href="/workers" class="flex flex-col gap-2 p-3 rounded-xl border {status_colors[0]} hover:border-slate-500 transition-all">
  <div class="flex items-center gap-2">
    <span class="inline-block w-2 h-2 rounded-full {status_colors[2]}{"" if vis == "ok" else " animate-pulse"}"></span>
    <span class="text-xs font-semibold text-slate-200 truncate">{host}</span>
    <span class="ml-auto text-[10px] {status_colors[1]} uppercase">{status}</span>
  </div>
  <div class="flex items-center gap-2">
    <div class="flex-1 bg-slate-800 rounded-full h-1 overflow-hidden">
      <div class="h-1 rounded-full {bar_color} transition-all" style="width:{pct}%"></div>
    </div>
    <span class="text-[10px] text-slate-400 tabular-nums flex-shrink-0">{tasks}/{cap}</span>
  </div>
</a>'''
        workers_html = f'<div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">{worker_cards}</div>'
    else:
        workers_html = '<p class="text-sm text-slate-500 italic">Kein Distributed Worker registriert — läuft im Standalone-Modus.</p>'

    # ── System metrics snapshot ────────────────────────────────────────────────
    m = system_metrics.get(rc)
    if m:
        cpu_c  = _color(m["cpu_percent"])
        ram_c  = _color(m["mem_percent"])
        metrics_html = f'''
<div class="flex flex-wrap gap-6 text-xs font-mono">
  <div class="flex items-center gap-2">
    <span class="text-slate-500">CPU</span>
    <span class="{cpu_c} font-bold">{m["cpu_percent"]:.0f}%</span>
  </div>
  <div class="flex items-center gap-2">
    <span class="text-slate-500">RAM</span>
    <span class="{ram_c} font-bold">{m["mem_used_gb"]:.1f} / {m["mem_total_gb"]:.1f} GB</span>
    <span class="text-slate-600">({m["mem_percent"]:.0f}%)</span>
  </div>
  <div class="flex items-center gap-2">
    <span class="text-slate-500">Net</span>
    <span class="text-cyan-400">↑{m["net_out_mbps"]:.1f}</span>
    <span class="text-indigo-400">↓{m["net_in_mbps"]:.1f}</span>
    <span class="text-slate-600">Mb/s</span>
  </div>
</div>'''
    else:
        metrics_html = '<span class="text-xs text-slate-600 italic">Metriken werden gesammelt…</span>'

    from datetime import timezone
    now_str = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    n_err  = len(errors)
    n_warn = len(warnings)
    overall = "ok" if not alerts else ("error" if errors else "warning")
    overall_badge = {
        "ok":      '<span class="px-2 py-0.5 rounded-full text-xs bg-emerald-900/50 border border-emerald-700/40 text-emerald-300 font-semibold">Alles OK</span>',
        "warning": f'<span class="px-2 py-0.5 rounded-full text-xs bg-amber-900/50 border border-amber-700/40 text-amber-300 font-semibold">{n_warn} Warnung{"en" if n_warn > 1 else ""}</span>',
        "error":   f'<span class="px-2 py-0.5 rounded-full text-xs bg-red-900/50 border border-red-700/40 text-red-300 font-semibold">{n_err} Fehler{f", {n_warn} Warn." if n_warn else ""}</span>',
    }[overall]

    return HTMLResponse(f'''
<div id="health-summary"
     hx-get="/api/system/health-summary"
     hx-trigger="every 30s"
     hx-swap="outerHTML">

  <!-- Status line -->
  <div class="flex items-center gap-3 mb-5">
    {overall_badge}
    <span class="text-xs text-slate-600 font-mono">Aktualisiert {now_str}</span>
    <span class="text-xs text-slate-700">· alle 30s</span>
  </div>

  <!-- Service status cards -->
  <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
    {cards_html}
  </div>

  <!-- Metrics bar -->
  <div class="mb-6 p-3 bg-slate-900/60 border border-slate-700/50 rounded-xl">
    <p class="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mb-2">System-Ressourcen (Host)</p>
    {metrics_html}
  </div>

  <!-- Active alerts -->
  <div class="mb-6">
    <h2 class="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
      <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/>
      </svg>
      Aktive Alerts
      {f'<span class="text-xs bg-red-900/50 text-red-300 border border-red-700/40 rounded px-1.5">{n_err}</span>' if n_err else ''}
      {f'<span class="text-xs bg-amber-900/50 text-amber-300 border border-amber-700/40 rounded px-1.5">{n_warn}</span>' if n_warn else ''}
    </h2>
    {alerts_html}
  </div>

  <!-- Workers -->
  <div>
    <div class="flex items-center justify-between mb-3">
      <h2 class="text-sm font-semibold text-slate-300 flex items-center gap-2">
        <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/>
        </svg>
        Worker
        <span class="text-xs text-slate-500 font-normal">({len(workers)} registriert)</span>
      </h2>
      <a href="/workers" class="text-xs text-indigo-400 hover:text-indigo-300 transition-colors">Worker-Monitor →</a>
    </div>
    {workers_html}
  </div>

</div>''')


# ── /system/health  (Operations Center page) ──────────────────────────────────

@ui_router.get("/system/health", response_class=HTMLResponse)
async def system_health_page(
    request: Request,
    user: Annotated[User, Depends(PlatformAdminChecker())],
):
    return templates.TemplateResponse("system_health.html", {
        "request": request,
        "user": user,
    })
