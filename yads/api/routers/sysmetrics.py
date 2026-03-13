"""
System Metrics & Resource-Check Endpoints

/api/system/metrics        — HTMX topbar fragment (CPU / RAM / net)
/api/system/scan-errors    — HTMX topbar fragment (scan error badge, tenant-scoped)
/api/system/resource-check — Inline validation warnings for worker config modal
"""

from typing import Optional
from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from yads.api.templating import templates

from yads.auth.deps import get_current_user_html, PlatformAdminChecker
from yads.models import User

router = APIRouter(prefix="/api/system", tags=["system-metrics"])
router = APIRouter(prefix="/api/system", tags=["system-metrics"])
ui_router = APIRouter(tags=["system-ui"])

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

@router.get("/metrics", response_class=HTMLResponse)
async def system_metrics_fragment(
    request: Request,
    user: User = Depends(get_current_user_html),
):
    """
    HTMX fragment: live CPU / RAM / network stats for the topbar.
    Polled every 3 seconds via hx-trigger="every 3s".
    """
    from yads.core import system_metrics
    m = system_metrics.get(_redis_client())

    if not m:
        # Redis unavailable or metrics not yet collected — keep polling
        return HTMLResponse(
            '<div id="sysmetrics-widget"'
            ' class="hidden md:flex items-center gap-3 text-xs text-slate-600 font-mono"'
            ' hx-get="/api/system/metrics" hx-trigger="every 5s" hx-swap="outerHTML">'
            '<span>— / — / —</span>'
            '</div>'
        )

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
    user: User = Depends(get_current_user_html),
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

    total_errors = sum(e.get("count", 1) for e in errors)
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
<div id="scan-errors-badge"
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
    user: User = Depends(get_current_user_html),
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


# ── /api/system/resource-check ────────────────────────────────────────────────

@router.get("/resource-check", response_class=HTMLResponse)
async def resource_check(
    node_id: str = Query(...),
    tasks: int    = Query(..., ge=1, le=500),
    net_mbps: float = Query(..., ge=0),
    user: User = Depends(PlatformAdminChecker()),
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
    user: User = Depends(PlatformAdminChecker()),
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
    <a href="/system/alerts" class="block mt-3 text-center text-xs text-indigo-400 hover:text-indigo-300 transition-colors">
      Alert-Verlauf anzeigen →
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

    since = datetime.utcnow() - timedelta(days=7)
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
