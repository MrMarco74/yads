import logging
import json
import os
import shutil
import threading
import aiofiles
from typing import Optional, List
from fastapi import APIRouter, Depends, Request, Form, UploadFile, File, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse
from sqlmodel import Session, select, func, text
from datetime import datetime

from yads.database import get_session, redis_client
from yads.auth.deps import RoleChecker, get_current_user_html
from yads.models import User, Target, ScanResult, ModuleState, SystemConfig
from yads.api.templating import templates

from yads.api.utils.update_checker import UpdateService
from yads.core.backup import create_backup_zip, restore_backup_from_zip
from yads.config import settings
# Shared, pre-configured Celery app (task_queues/task_routes -- see
# worker_core.py) -- NOT a fresh Celery(...) instance. A second,
# unconfigured instance here would silently lose all queue routing
# (e.g. check_nmap_available/check_nuclei_available/
# update_nuclei_templates being routed to the 'utility' queue instead of
# the pausable default 'celery' queue), which is exactly the bug this
# comment is here to prevent regressing.
from yads.worker_core import celery_app

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/logs", response_class=HTMLResponse)
async def view_logs_page(request: Request, user: User = Depends(RoleChecker(["admin", "tenant_admin"]))):
    """
    Renders the Logs page with a list of available log files.
    """
    log_dir = os.getenv("LOG_DIR", "logs")
    log_files = []
    if os.path.exists(log_dir):
        # List all .log files
        log_files = [f for f in os.listdir(log_dir) if f.endswith('.log')]
        log_files.sort()
    
    # Default to yads-api.log if available, else first one
    default_log = "yads-api.log"
    if default_log not in log_files and log_files:
        default_log = log_files[0]
    elif not log_files:
        default_log = ""

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "log_files": log_files,
        "current_log": default_log,
        "user": user
    })

@router.get("/api/logs/stream")
async def get_logs_stream(file: str = "yads-api.log", user: User = Depends(RoleChecker(["admin", "tenant_admin"]))):
    """Reads the last 100 lines of the specified log file. Filters by tenant if not global admin."""
    log_dir = os.getenv("LOG_DIR", "logs")
    
    # Security: Ensure clean filename (basename only) to prevent traversal
    safe_filename = os.path.basename(file)
    log_file = os.path.join(log_dir, safe_filename)
    
    if not os.path.exists(log_file):
        return {"logs": [f"Log file '{safe_filename}' not found."]}
    
    lines_to_return = []
    
    # Efficiently read last N lines
    # For now, we read full file or chunk and filter. 
    # Since we need to filter, reading just last 100 bytes is risky if we filter them all out.
    # We'll read a reasonable tail size, say last 2000 lines, filter them, and return last 100 matches.
    
    try:
        async with aiofiles.open(log_file, mode='r') as f:
            # Reading all lines might be memory intensive for huge logs.
            # But for YADS scale (<100MB logs usually due to rotation), it's okay for now.
            content = await f.read()
            lines = content.splitlines()
            
            # Filtering Logic
            if user.role == "admin":
                # Admin sees all
                lines_to_return = lines
            else:
                # Tenant Admin sees only lines with [Tenant: ID]
                tenant_tag = f"[Tenant: {user.tenant_id}]"
                lines_to_return = [line for line in lines if tenant_tag in line]
                
            return {"logs": lines_to_return[-100:]}
            
    except Exception as e:
        logger.error(f"Failed to read logs: {e}")
        return {"logs": [f"Error reading log file: {str(e)}"]}
@router.get("/api/system/binary-status")
async def binary_status(request: Request, user: User = Depends(RoleChecker(["admin"]))):
    """Return availability of optional external binaries (nmap, nuclei, …)."""
    BINARIES = [
        {"name": "nmap",   "label": "Nmap",   "install_hint": "apt-get install -y nmap",   "has_fallback": True,  "fallback_note": "socket-based scan (limited, no stealth)"},
        {"name": "nuclei", "label": "Nuclei", "install_hint": "See /admin/tools for update", "has_fallback": False, "fallback_note": ""},
    ]
    # nmap/nuclei only ever run on the worker (see Dockerfile's
    # base-scanner stage) -- checking shutil.which() here in the API
    # process would always be wrong (and for nmap specifically, an
    # apt-get-installed binary in the API container only lives in that
    # container's writable layer and disappears on every restart/
    # redeploy, which is why "Install nmap" appeared to work then
    # silently reverted). Ask the worker instead for both.
    #
    # These run on the 'utility' queue (see worker_core.py), not the
    # default 'celery' queue, so they keep working even while the scan
    # queue is paused (pause only cancels the 'celery'/'discovery'
    # consumers by name).
    WORKER_CHECK_TASK = {
        "nmap": "yads.worker.check_nmap_available",
        "nuclei": "yads.worker.check_nuclei_available",
    }
    result = []
    for b in BINARIES:
        try:
            status = celery_app.send_task(WORKER_CHECK_TASK[b["name"]]).get(timeout=5)
            available = bool(status.get("available"))
        except Exception as e:
            logger.debug(f"Failed to check {b['name']} availability on worker: {e}")
            available = False
        result.append({**b, "available": available, "mode": "full" if available else ("fallback" if b["has_fallback"] else "unavailable")})
    return result


def _nmap_sudo_modal_html(error_msg: str = "") -> str:
    error_html = ""
    if error_msg:
        error_html = f'<div class="bg-red-900/30 border border-red-500/40 rounded-lg p-2 mb-3 text-[10px] text-red-300">{error_msg}</div>'
    return f'''<div id="nmap-install-btn">
  <button type="button" disabled class="bg-amber-700/40 text-white/50 text-[10px] font-bold py-1.5 px-3 rounded cursor-not-allowed">Install nmap</button>
</div>
<div hx-swap-oob="beforeend:body">
<div id="nmap-sudo-overlay" class="fixed inset-0 z-[9999] flex items-center justify-center bg-black/70 backdrop-blur-sm">
  <div class="bg-slate-800 border border-slate-600 rounded-xl shadow-2xl p-6 w-full max-w-md mx-4">
    <div class="flex items-center gap-3 mb-4">
      <div class="w-10 h-10 rounded-full bg-amber-500/20 flex items-center justify-center flex-shrink-0">
        <svg class="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
        </svg>
      </div>
      <div>
        <h3 class="text-sm font-bold text-white">Root-Rechte erforderlich</h3>
        <p class="text-[10px] text-gray-400">apt-get benötigt erhöhte Berechtigungen</p>
      </div>
    </div>
    <div class="bg-amber-900/20 border border-amber-500/30 rounded-lg p-3 mb-4 flex items-start gap-2">
      <svg class="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>
      <p class="text-[10px] text-amber-200">Das Passwort wird <strong>ausschließlich für diese Operation</strong> verwendet und wird <strong>nicht gespeichert, geloggt oder übertragen</strong>.</p>
    </div>
    {error_html}
    <form hx-post="/admin/tools/nmap-install"
          hx-target="#nmap-install-btn"
          hx-swap="outerHTML"
          hx-on::after-request="if(event.detail.successful) document.getElementById('nmap-sudo-overlay').remove()">
      <label class="block text-[10px] font-semibold text-gray-300 mb-1.5">System-Passwort (sudo)</label>
      <input type="password"
             name="sudo_password"
             id="nmap-sudo-pwd"
             placeholder="Passwort eingeben..."
             required
             autocomplete="current-password"
             class="w-full bg-slate-700 border border-slate-600 text-white text-sm rounded-lg px-3 py-2 mb-4 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500/50"/>
      <div class="flex gap-2 justify-end">
        <button type="button"
                onclick="document.getElementById('nmap-sudo-overlay').remove()"
                class="text-[10px] text-gray-400 hover:text-white px-3 py-1.5 rounded border border-slate-600 hover:border-slate-400 transition-colors">
          Abbrechen
        </button>
        <button type="submit"
                class="bg-amber-600 hover:bg-amber-500 text-white text-[10px] font-bold py-1.5 px-4 rounded transition-colors">
          Installieren
        </button>
      </div>
    </form>
  </div>
</div>
<script>(function(){{var f=document.getElementById('nmap-sudo-pwd');if(f)setTimeout(function(){{f.focus();}},50);}})();</script>
</div>'''


@router.post("/admin/tools/nmap-install")
async def admin_nmap_install(request: Request, user: User = Depends(RoleChecker(["admin"]))):
    """
    Attempt to install nmap via apt-get.
    If apt-get fails due to missing permissions, returns an OOB sudo-password modal.
    The sudo password (if provided) is used once and never stored or logged.
    """
    import subprocess
    import shutil

    if shutil.which("nmap"):
        return HTMLResponse(content='<div id="nmap-install-btn"><span class="text-[10px] text-green-500 font-semibold">✓ Nmap bereits installiert</span></div>')

    form_data = await request.form()
    sudo_password: str = form_data.get("sudo_password", "") or ""  # type: ignore[assignment]
    using_sudo = bool(sudo_password.strip())

    logger.info(f"Admin {user.username} triggered nmap installation (sudo={'yes' if using_sudo else 'no'}).")

    try:
        if using_sudo:
            pwd_input = sudo_password + "\n"
            update_proc = subprocess.run(  # nosec B603 B607 - hardcoded sudo apt-get, password from admin form
                ["sudo", "-S", "apt-get", "update", "-qq"],
                input=pwd_input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60
            )
            proc = subprocess.run(  # nosec B603 B607 - hardcoded sudo apt-get nmap, password from admin form
                ["sudo", "-S", "apt-get", "install", "-y", "--no-install-recommends", "nmap"],
                input=pwd_input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120
            )
            sudo_password = ""  # discard immediately after use
            pwd_input = ""

            if proc.returncode == 0:
                return HTMLResponse(content='<div id="nmap-install-btn"><span class="text-[10px] text-green-500 font-semibold">✓ Nmap erfolgreich installiert</span></div>')
            output = proc.stdout or ""
            if "incorrect password" in output.lower() or "authentication failure" in output.lower() or proc.returncode == 1 and not output.strip():
                return HTMLResponse(content=_nmap_sudo_modal_html("Falsches Passwort. Bitte erneut versuchen."))
            return HTMLResponse(content=_nmap_sudo_modal_html(f"Fehler: {output[-200:]}"))
        else:
            # Attempt without sudo first (works when running as root in Docker)
            update_proc = subprocess.run(  # nosec B603 B607 - hardcoded apt-get, no user input
                ["apt-get", "update", "-qq"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60
            )
            proc = subprocess.run(  # nosec B603 B607 - hardcoded apt-get nmap, no user input
                ["apt-get", "install", "-y", "--no-install-recommends", "nmap"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120
            )
            if proc.returncode == 0:
                return HTMLResponse(content='<div id="nmap-install-btn"><span class="text-[10px] text-green-500 font-semibold">✓ Nmap erfolgreich installiert</span></div>')
            output = proc.stdout or ""
            if "Permission denied" in output or "E: Could not open lock" in output or proc.returncode in (100, 1):
                return HTMLResponse(content=_nmap_sudo_modal_html())
            return HTMLResponse(content=f'<div id="nmap-install-btn"><div class="bg-red-900/40 border border-red-500/50 text-red-200 p-2 rounded text-[10px]">Fehler: {output[-200:]}</div></div>')
    except Exception as e:
        sudo_password = ""
        return HTMLResponse(content=f'<div id="nmap-install-btn"><div class="bg-red-900/40 border border-red-500/50 text-red-200 p-2 rounded text-[10px]">Error: {str(e)}</div></div>')


@router.post("/admin/tools/nuclei-update")
async def admin_nuclei_update(request: Request, user: User = Depends(RoleChecker(["admin"]))):
    """
    Manually triggers 'nuclei -ut' to update vulnerability templates.
    Dispatched to a worker node via Celery -- the nuclei binary only exists
    in the worker image, not the API image (see Dockerfile's base-scanner
    stage), so running it in-process here always fails with
    FileNotFoundError. Runs on the 'utility' queue (see worker_core.py),
    so this keeps working even while the scan queue is paused.
    """
    logger.info(f"Admin {user.username} triggered Nuclei template update.")
    try:
        result = celery_app.send_task("yads.worker.update_nuclei_templates").get(timeout=600)
        if result.get("ok"):
            return HTMLResponse(content=f'<div class="bg-green-900/40 border border-green-500/50 text-green-200 p-2 rounded text-[10px] mt-2 animate-fade-in">{result["message"]}</div>')
        return HTMLResponse(content=f'<div class="bg-red-900/40 border border-red-500/50 text-red-200 p-2 rounded text-[10px] mt-2 animate-fade-in">{result["message"]}</div>')
    except Exception as e:
        logger.error(f"Nuclei update failed: {e}")
        return HTMLResponse(content=f'<div class="bg-red-900/40 border border-red-500/50 text-red-200 p-2 rounded text-[10px] mt-2 animate-fade-in">Error: {str(e)}</div>')

@router.post("/admin/update/check", response_class=HTMLResponse)
async def manual_update_check(request: Request, user: User = Depends(RoleChecker(["admin"]))):
    """
    Manually triggers an update check (HTMX).
    """
    try:
        # Use global redis_client
        r = redis_client
        r.delete(UpdateService.CACHE_KEY)

        update = UpdateService.check_for_updates()
        if update:
            return HTMLResponse(content=f'''
                <div class="bg-indigo-900/40 border border-indigo-500/50 p-4 rounded-xl animate-fade-in">
                    <div class="flex items-center gap-3">
                        <div class="p-2 bg-indigo-500/20 rounded-lg text-indigo-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        </div>
                        <div>
                            <p class="text-sm font-bold text-white">YADS Update Available: v{update['version']}</p>
                            <p class="text-xs text-indigo-300 mt-1">{update['text']}</p>
                            <a href="{update['url']}" target="_blank" class="inline-block mt-3 text-xs font-bold text-indigo-400 hover:text-indigo-300 underline uppercase tracking-wider">Download & Patch</a>
                        </div>
                    </div>
                </div>
            ''')
        else:
            return HTMLResponse(content=f'''
                <div class="bg-slate-800/50 border border-slate-700 p-4 rounded-xl animate-fade-in">
                    <div class="flex items-center gap-3">
                        <div class="p-2 bg-green-500/10 rounded-lg text-green-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                        </div>
                        <div>
                            <p class="text-sm font-bold text-white">System Up to Date</p>
                            <p class="text-xs text-slate-400">You are running the latest version (v{settings.VERSION}).</p>
                        </div>
                    </div>
                </div>
            ''')
    except Exception as e:
        return HTMLResponse(content=f'''
            <div class="bg-red-900/40 border border-red-500/50 p-4 rounded-xl text-red-200 text-xs animate-fade-in">
                Update check failed: {str(e)}
            </div>
        ''')

@router.get("/settings", response_class=HTMLResponse)
async def view_settings(request: Request, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin"]))):
    from yads.models import SystemConfig, Tenant

    # Fetch tenants for Export UI
    allowed_tenants = session.exec(select(Tenant).order_by(Tenant.name)).all()
    
    # Defaults
    auto_queue = settings.AUTO_QUEUE_SUBDOMAINS
    rate_limit = settings.SCAN_QUEUE_RATE_LIMIT
    web_request_delay = 2.0
    worker_concurrency = 4 # Default if not set
    session_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    otp_window = 1
    
    # Load from DB
    aq_conf = session.get(SystemConfig, "AUTO_QUEUE_SUBDOMAINS")
    if aq_conf:
        auto_queue = aq_conf.value.lower() == 'true'
        
    rl_conf = session.get(SystemConfig, "SCAN_QUEUE_RATE_LIMIT")
    if rl_conf:
        rate_limit = rl_conf.value

    # Web Timeout
    web_request_timeout = settings.WEB_REQUEST_TIMEOUT
    wt_conf = session.get(SystemConfig, "WEB_REQUEST_TIMEOUT")
    if wt_conf:
         try:
             web_request_timeout = int(wt_conf.value)
         except ValueError:
             pass

    wrd_conf = session.get(SystemConfig, "WEB_RATE_LIMIT_DELAY")
    if wrd_conf:
        try:
            web_request_delay = float(wrd_conf.value)
        except ValueError:
             pass

    wc_conf = session.get(SystemConfig, "WORKER_CONCURRENCY")
    if wc_conf:
        try:
            worker_concurrency = int(wc_conf.value)
        except ValueError:
            pass
        


    # Session Config
    sm_conf = session.get(SystemConfig, "ACCESS_TOKEN_EXPIRE_MINUTES")
    if sm_conf:
        try:
            session_minutes = int(sm_conf.value)
        except ValueError:
             pass

    otp_conf = session.get(SystemConfig, "OTP_VALID_WINDOW")
    if otp_conf:
        try:
            otp_window = int(otp_conf.value)
        except ValueError:
            pass

    # Load Approved Ciphers
    approved_ciphers = ""
    ac_conf = session.get(SystemConfig, "APPROVED_CIPHERS")
    if ac_conf:
        approved_ciphers = ac_conf.value
    else:
        # Default load
        try:
             if os.path.exists("ciphers.csv"):
                with open("ciphers.csv", "r") as f:
                    approved_ciphers = f.read()
        except Exception as e:
            logger.debug(f"Failed to load ciphers.csv: {e}")

    # Load Custom DNS
    custom_dns_servers = ""
    dns_conf = session.get(SystemConfig, "CUSTOM_DNS_SERVERS")
    if dns_conf:
        custom_dns_servers = dns_conf.value

    # Load Network Rate Limit
    network_rate_limit = ""
    nrl_conf = session.get(SystemConfig, "NETWORK_RATE_LIMIT")
    if nrl_conf:
        network_rate_limit = nrl_conf.value
        
    # Custom Wordlist Status
    has_custom_wordlist = False
    custom_wordlist_lines = 0
    default_wordlist_count = 18 # Default fallback list size
    try:
        # Use BASE_DIR from settings for robust path resolution
        # yads/data/wordlists/subdomains.txt
        wordlist_path = os.path.join(settings.BASE_DIR, "data", "wordlists", "subdomains.txt")
        
        # Fallback for Docker environment if path resolution is weird
        if not os.path.exists(wordlist_path):
            wordlist_path = "/app/yads/data/wordlists/subdomains.txt"
        
        if os.path.exists(wordlist_path):
            has_custom_wordlist = True
            with open(wordlist_path, 'rb') as f:
                custom_wordlist_lines = sum(1 for _ in f)
    except Exception as e:
        logger.debug(f"Failed to load wordlists: {e}")

    # Nuclei Update Status
    nuclei_last_updated = "Never"
    try:
        nuclei_path = "/root/nuclei-templates"
        if os.path.exists(nuclei_path):
             # Check modification time
             mtime = os.path.getmtime(nuclei_path)
             nuclei_last_updated = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
    except Exception as e:
        logger.debug(f"Failed to check nuclei templates: {e}")

    nuclei_binary_path = ""
    nbp_conf = session.get(SystemConfig, "NUCLEI_BINARY_PATH")
    if nbp_conf:
        nuclei_binary_path = nbp_conf.value

    # Splunk Config
    splunk_hec_url = ""
    splunk_hec_token = ""
    su_conf = session.get(SystemConfig, "SPLUNK_HEC_URL")
    if su_conf: splunk_hec_url = su_conf.value
    st_conf = session.get(SystemConfig, "SPLUNK_HEC_TOKEN")
    if st_conf: splunk_hec_token = st_conf.value

    # Email Config
    smtp_host = ""
    smtp_port = ""
    smtp_user = ""
    smtp_password = ""
    
    sh_conf = session.get(SystemConfig, "SMTP_HOST")
    if sh_conf: smtp_host = sh_conf.value
    
    sp_conf = session.get(SystemConfig, "SMTP_PORT")
    if sp_conf: smtp_port = sp_conf.value
    
    suser_conf = session.get(SystemConfig, "SMTP_USER")
    if suser_conf: smtp_user = suser_conf.value
    
    spass_conf = session.get(SystemConfig, "SMTP_PASSWORD")
    if spass_conf: smtp_password = spass_conf.value

    smtp_from = ""
    sf_conf = session.get(SystemConfig, "SMTP_FROM")
    if sf_conf: smtp_from = sf_conf.value

    email_notification_address = ""
    ena_conf = session.get(SystemConfig, "EMAIL_NOTIFICATION_ADDRESS")
    if ena_conf: email_notification_address = ena_conf.value

    email_notifications_enabled = False
    ene_conf = session.get(SystemConfig, "EMAIL_NOTIFICATIONS_ENABLED")
    if ene_conf: email_notifications_enabled = ene_conf.value.lower() == "true"

    base_url = ""
    bu_conf = session.get(SystemConfig, "BASE_URL")
    if bu_conf: base_url = bu_conf.value

    data_retention_days = 90
    dr_conf = session.get(SystemConfig, "DATA_RETENTION_DAYS")
    if dr_conf and dr_conf.value:
        try:
            data_retention_days = int(dr_conf.value)
        except ValueError:
            pass

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # --- TLS/SSL Certificate Settings ---
    https_only = False
    custom_ca_cert_path = ""
    client_cert_path = ""
    client_key_path = ""
    verify_ssl = True

    # Environment variable override status
    https_only_env_override = settings.DISABLE_HTTPS_ONLY

    https_conf = session.get(SystemConfig, "HTTPS_ONLY")
    if https_conf:
        https_only = https_conf.value.lower() == "true"

    ca_conf = session.get(SystemConfig, "CUSTOM_CA_CERT_PATH")
    if ca_conf:
        custom_ca_cert_path = ca_conf.value

    cc_conf = session.get(SystemConfig, "CLIENT_CERT_PATH")
    if cc_conf:
        client_cert_path = cc_conf.value

    ck_conf = session.get(SystemConfig, "CLIENT_KEY_PATH")
    if ck_conf:
        client_key_path = ck_conf.value

    vs_conf = session.get(SystemConfig, "VERIFY_SSL")
    if vs_conf:
        verify_ssl = vs_conf.value.lower() != "false"

    # Validate certificate files
    tls_validation = {"valid": True, "errors": [], "warnings": []}
    if custom_ca_cert_path and not os.path.exists(custom_ca_cert_path):
        tls_validation["errors"].append(f"CA certificate not found: {custom_ca_cert_path}")
        tls_validation["valid"] = False
    if client_cert_path and not os.path.exists(client_cert_path):
        tls_validation["errors"].append(f"Client certificate not found: {client_cert_path}")
        tls_validation["valid"] = False
    if client_key_path and not os.path.exists(client_key_path):
        tls_validation["errors"].append(f"Client key not found: {client_key_path}")
        tls_validation["valid"] = False
    if bool(client_cert_path) != bool(client_key_path):
        tls_validation["errors"].append("Client certificate and key must both be provided")
        tls_validation["valid"] = False

    # --- Distributed Worker Settings ---
    global_max_concurrent_scans = 50
    global_max_network_mbps = 500

    gmcs_conf = session.get(SystemConfig, "GLOBAL_MAX_CONCURRENT_SCANS")
    if gmcs_conf:
        try:
            global_max_concurrent_scans = int(gmcs_conf.value)
        except ValueError:
            pass

    gmnm_conf = session.get(SystemConfig, "GLOBAL_MAX_NETWORK_MBPS")
    if gmnm_conf:
        try:
            global_max_network_mbps = float(gmnm_conf.value)
        except ValueError:
            pass

    # --- Prometheus Metrics Settings ---
    metrics_enabled = settings.METRICS_ENABLED
    metrics_auth_mode = settings.METRICS_AUTH_MODE
    metrics_token = settings.METRICS_TOKEN or ""
    metrics_include_tenant_labels = settings.METRICS_INCLUDE_TENANT_LABELS

    me_conf = session.get(SystemConfig, "METRICS_ENABLED")
    if me_conf:
        metrics_enabled = me_conf.value.lower() == "true"

    mam_conf = session.get(SystemConfig, "METRICS_AUTH_MODE")
    if mam_conf:
        metrics_auth_mode = mam_conf.value

    mt_conf = session.get(SystemConfig, "METRICS_TOKEN")
    if mt_conf:
        metrics_token = mt_conf.value

    mitl_conf = session.get(SystemConfig, "METRICS_INCLUDE_TENANT_LABELS")
    if mitl_conf:
        metrics_include_tenant_labels = mitl_conf.value.lower() == "true"

    return templates.TemplateResponse("settings.html", {
        "allowed_tenants": allowed_tenants,
        "user": user,
        "request": request,
        "auto_queue": auto_queue,
        "rate_limit": rate_limit,
        "web_request_delay": web_request_delay,
        "web_request_timeout": web_request_timeout,
        "worker_concurrency": worker_concurrency,
        "approved_ciphers": approved_ciphers,
        "custom_dns_servers": custom_dns_servers,
        "network_rate_limit": network_rate_limit,
        "has_custom_wordlist": has_custom_wordlist,
        "custom_wordlist_lines": custom_wordlist_lines,
        "session_minutes": session_minutes,
        "otp_window": otp_window,
        "splunk_hec_url": splunk_hec_url,
        "splunk_hec_token": splunk_hec_token,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_password": smtp_password,
        "smtp_from": smtp_from,
        "email_notification_address": email_notification_address,
        "email_notifications_enabled": email_notifications_enabled,
        "base_url": base_url,
        "data_retention_days": data_retention_days,
        "global_max_concurrent_scans": global_max_concurrent_scans,
        "global_max_network_mbps": global_max_network_mbps,
        "default_wordlist_count": default_wordlist_count,
        "nuclei_last_updated": nuclei_last_updated,
        "nuclei_binary_path": nuclei_binary_path,
        # TLS/SSL Settings
        "https_only": https_only,
        "https_only_env_override": https_only_env_override,
        "custom_ca_cert_path": custom_ca_cert_path,
        "client_cert_path": client_cert_path,
        "client_key_path": client_key_path,
        "verify_ssl": verify_ssl,
        "tls_validation": tls_validation,
        # Prometheus Metrics Settings
        "metrics_enabled": metrics_enabled,
        "metrics_auth_mode": metrics_auth_mode,
        "metrics_token": metrics_token,
        "metrics_include_tenant_labels": metrics_include_tenant_labels,
        
        # OSINT Settings
        "hibp_api_key": session.get(SystemConfig, "HIBP_API_KEY").value if session.get(SystemConfig, "HIBP_API_KEY") else "",
        "dehashed_api_key": session.get(SystemConfig, "DEHASHED_API_KEY").value if session.get(SystemConfig, "DEHASHED_API_KEY") else "",
        "osint_webhook_url": session.get(SystemConfig, "OSINT_WEBHOOK_URL").value if session.get(SystemConfig, "OSINT_WEBHOOK_URL") else "",
        
        "workers": __import__('yads.core.worker_manager', fromlist=['worker_manager']).worker_manager.get_worker_list(),
    })

@router.post("/settings", response_class=HTMLResponse)
async def update_settings(
    request: Request,
    user: User = Depends(RoleChecker(["admin"])),
    auto_queue: bool = Form(False),
    rate_limit: str = Form(None, max_length=20),
    web_request_delay: str = Form(None, max_length=10),
    web_request_timeout: int = Form(None),
    worker_concurrency: int = Form(4),
    session_minutes: int = Form(60),
    otp_window: int = Form(1),
    approved_ciphers: Optional[str] = Form(None, max_length=2000),
    custom_dns_servers: str = Form(None, max_length=500),
    network_rate_limit: str = Form(None, max_length=20),
    splunk_hec_url: str = Form(None, max_length=500),
    splunk_hec_token: str = Form(None, max_length=1024),
    smtp_host: str = Form(None, max_length=253),
    smtp_port: str = Form(None, max_length=5),
    smtp_user: Optional[str] = Form(None, max_length=254),
    smtp_password: Optional[str] = Form(None, max_length=256),
    smtp_from: Optional[str] = Form(None, max_length=254),
    email_notification_address: Optional[str] = Form(None, max_length=254),
    email_notifications_enabled: bool = Form(False),
    base_url: Optional[str] = Form(None, max_length=500),
    data_retention_days: int = Form(90),
    nuclei_binary_path: Optional[str] = Form(None, max_length=500),

    # Distributed Worker Settings
    global_max_concurrent_scans: int = Form(50),
    global_max_network_mbps: float = Form(500),

    # TLS/SSL Settings
    https_only: bool = Form(False),
    custom_ca_cert_path: Optional[str] = Form(None, max_length=500),
    client_cert_path: Optional[str] = Form(None, max_length=500),
    client_key_path: Optional[str] = Form(None, max_length=500),
    verify_ssl: bool = Form(True),

    # Prometheus Metrics Settings
    metrics_enabled: bool = Form(False),
    metrics_auth_mode: str = Form("token", max_length=20),
    metrics_token: Optional[str] = Form(None, max_length=256),
    metrics_include_tenant_labels: bool = Form(False),

    # OSINT Settings
    hibp_api_key: Optional[str] = Form(None, max_length=100),
    dehashed_api_key: Optional[str] = Form(None, max_length=256),
    osint_webhook_url: Optional[str] = Form(None, max_length=500),

    session: Session = Depends(get_session)
):
    from yads.models import SystemConfig
    from typing import Optional

    # Helper to upsert config
    def set_conf(k, v):
        conf = session.get(SystemConfig, k)
        if not conf:
            conf = SystemConfig(key=k, value=v)
            session.add(conf)
        else:
            conf.value = v
            session.add(conf)
            
    # Update Auto Queue
    # NOTE: auto_queue is `bool = Form(False)`, so it's never actually None --
    # an unchecked checkbox arrives as False, not absent. The old
    # `is not None` check was therefore always true, silently forcing this
    # back on (true) on every settings save regardless of the checkbox.
    set_conf("AUTO_QUEUE_SUBDOMAINS", "true" if auto_queue else "false")
        
    # Rate Limit
    rl_conf = session.get(SystemConfig, "SCAN_QUEUE_RATE_LIMIT")
    if not rl_conf:
        rl_conf = SystemConfig(key="SCAN_QUEUE_RATE_LIMIT", value=rate_limit)
        session.add(rl_conf)
    else:
        rl_conf.value = rate_limit
        session.add(rl_conf)

    # Worker Concurrency
    wc_conf = session.get(SystemConfig, "WORKER_CONCURRENCY")
    if not wc_conf:
        wc_conf = SystemConfig(key="WORKER_CONCURRENCY", value=str(worker_concurrency))
        session.add(wc_conf)
    else:
        wc_conf.value = str(worker_concurrency)
        session.add(wc_conf)
        
    # Session Minutes
    sm_conf = session.get(SystemConfig, "ACCESS_TOKEN_EXPIRE_MINUTES")
    if not sm_conf:
        sm_conf = SystemConfig(key="ACCESS_TOKEN_EXPIRE_MINUTES", value=str(session_minutes))
        session.add(sm_conf)
    else:
        sm_conf.value = str(session_minutes)
        session.add(sm_conf)

    # OTP Window
    otp_conf = session.get(SystemConfig, "OTP_VALID_WINDOW")
    if not otp_conf:
        otp_conf = SystemConfig(key="OTP_VALID_WINDOW", value=str(otp_window))
        session.add(otp_conf)
    else:
        otp_conf.value = str(otp_window)
        session.add(otp_conf)

    # Approved Ciphers
    if approved_ciphers is not None:
        # Normalize line endings
        approved_ciphers = approved_ciphers.replace("\r\n", "\n")
        ac_conf = session.get(SystemConfig, "APPROVED_CIPHERS")
        if not ac_conf:
             ac_conf = SystemConfig(key="APPROVED_CIPHERS", value=approved_ciphers)
             session.add(ac_conf)
        else:
             ac_conf.value = approved_ciphers
             session.add(ac_conf)
             
    # Custom DNS Servers
    if custom_dns_servers is not None:
         dns_conf = session.get(SystemConfig, "CUSTOM_DNS_SERVERS")
         if not dns_conf:
             dns_conf = SystemConfig(key="CUSTOM_DNS_SERVERS", value=custom_dns_servers)
             session.add(dns_conf)
         else:
             dns_conf.value = custom_dns_servers
             session.add(dns_conf)

    # Network Rate Limit
    if network_rate_limit is not None:
         nrl_conf = session.get(SystemConfig, "NETWORK_RATE_LIMIT")
         if not nrl_conf:
             nrl_conf = SystemConfig(key="NETWORK_RATE_LIMIT", value=network_rate_limit)
             session.add(nrl_conf)
         else:
             nrl_conf.value = network_rate_limit
             session.add(nrl_conf)

    # Distributed Worker Settings
    set_conf("GLOBAL_MAX_CONCURRENT_SCANS", str(global_max_concurrent_scans))
    set_conf("GLOBAL_MAX_NETWORK_MBPS", str(global_max_network_mbps))

    # TLS/SSL Settings
    set_conf("HTTPS_ONLY", "true" if https_only else "false")
    set_conf("VERIFY_SSL", "true" if verify_ssl else "false")

    if custom_ca_cert_path is not None:
        custom_ca_cert_path = custom_ca_cert_path.strip()
        set_conf("CUSTOM_CA_CERT_PATH", custom_ca_cert_path)

    if client_cert_path is not None:
        client_cert_path = client_cert_path.strip()
        set_conf("CLIENT_CERT_PATH", client_cert_path)

    if nuclei_binary_path is not None:
        nuclei_binary_path = nuclei_binary_path.strip()
        set_conf("NUCLEI_BINARY_PATH", nuclei_binary_path)

    if client_key_path is not None:
        client_key_path = client_key_path.strip()
        set_conf("CLIENT_KEY_PATH", client_key_path)

    # OSINT Settings
    if hibp_api_key is not None:
        set_conf("HIBP_API_KEY", hibp_api_key.strip())
    if dehashed_api_key is not None:
        set_conf("DEHASHED_API_KEY", dehashed_api_key.strip())
        
    if osint_webhook_url is not None:
        set_conf("OSINT_WEBHOOK_URL", osint_webhook_url.strip())

    # Email / SMTP Settings
    if smtp_host is not None:
        set_conf("SMTP_HOST", smtp_host.strip())
    if smtp_port is not None:
        set_conf("SMTP_PORT", smtp_port.strip())
    if smtp_user is not None:
        set_conf("SMTP_USER", smtp_user.strip())
    if smtp_password is not None and smtp_password.strip():
        set_conf("SMTP_PASSWORD", smtp_password.strip())
    if smtp_from is not None:
        set_conf("SMTP_FROM", smtp_from.strip())
    if email_notification_address is not None:
        set_conf("EMAIL_NOTIFICATION_ADDRESS", email_notification_address.strip())
    set_conf("EMAIL_NOTIFICATIONS_ENABLED", "true" if email_notifications_enabled else "false")
    if base_url is not None:
        set_conf("BASE_URL", base_url.strip())
    set_conf("DATA_RETENTION_DAYS", str(max(0, data_retention_days)))

    # Prometheus Metrics Settings
    set_conf("METRICS_ENABLED", "true" if metrics_enabled else "false")
    set_conf("METRICS_AUTH_MODE", metrics_auth_mode)
    set_conf("METRICS_INCLUDE_TENANT_LABELS", "true" if metrics_include_tenant_labels else "false")

    if metrics_token is not None:
        metrics_token = metrics_token.strip()
        if metrics_token:  # Only save if non-empty
            set_conf("METRICS_TOKEN", metrics_token)

    session.commit()
    
    # Broadcast Updates
    
    # 1. Rate Limit
    if rate_limit:
        try:
             celery_app.control.rate_limit("yads.worker.run_all_scans", rate_limit)
        except Exception as e:
             logger.debug(f"Failed to ratelimit worker: {e}")

    # 3. Web Request Delay
    if web_request_delay:
        wrd_conf = session.get(SystemConfig, "WEB_RATE_LIMIT_DELAY")
        if not wrd_conf:
            wrd_conf = SystemConfig(key="WEB_RATE_LIMIT_DELAY", value=web_request_delay)
            session.add(wrd_conf)
        else:
            wrd_conf.value = web_request_delay
            session.add(wrd_conf)
        session.commit()

    # 4. Web Request Timeout
    if web_request_timeout:
        wt_conf = session.get(SystemConfig, "WEB_REQUEST_TIMEOUT")
        if not wt_conf:
             wt_conf = SystemConfig(key="WEB_REQUEST_TIMEOUT", value=str(web_request_timeout))
             session.add(wt_conf)
        else:
             wt_conf.value = str(web_request_timeout)
             session.add(wt_conf)
        session.commit()


    # 2. Worker Concurrency (Autoscale)
    try:
        # Set min=max to force fixed concurrency
        celery_app.control.autoscale(max=worker_concurrency, min=worker_concurrency)
    except Exception as e:
        logger.debug(f"Failed to autoscale worker: {e}")

    return RedirectResponse(url="/settings?saved=true", status_code=303)

@router.post("/settings/email/test")
async def test_email(
    request: Request,
    user: User = Depends(RoleChecker(["admin"])),
    session: Session = Depends(get_session)
):
    from yads.core.email_service import EmailService
    from fastapi.responses import JSONResponse
    to_addr = getattr(user, "email", None) or ""
    if not to_addr:
        return JSONResponse(status_code=400, content={"ok": False, "message": "Admin user has no email address configured."})
    success = EmailService.send_test(to_addr)
    if success:
        return JSONResponse(content={"ok": True, "message": f"Test email sent to {to_addr}"})
    return JSONResponse(status_code=500, content={"ok": False, "message": "Email send failed — check SMTP settings and logs."})


@router.post("/settings/wordlist/upload", response_class=RedirectResponse)
async def upload_custom_wordlist(
    wordlist_file: UploadFile = File(...), 
    session: Session = Depends(get_session)
):
    try:
        # Define path
        wordlist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlists")
        os.makedirs(wordlist_dir, exist_ok=True)
        wordlist_path = os.path.join(wordlist_dir, "subdomains.txt")
        
        # Save file
        async with aiofiles.open(wordlist_path, 'wb') as out_file:
            while content := await wordlist_file.read(1024):
                await out_file.write(content)
                
        return RedirectResponse(url="/settings?saved=true&msg=Wordlist+Uploaded", status_code=303)
    except Exception as e:
        logger.error(f"Failed to upload wordlist: {e}")
        return RedirectResponse(url=f"/settings?error=Upload+Failed:+{str(e)}", status_code=303)

@router.post("/settings/wordlist/delete", response_class=RedirectResponse)
async def delete_custom_wordlist(session: Session = Depends(get_session)):
    try:
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlists", "subdomains.txt")
        if os.path.exists(wordlist_path):
            os.remove(wordlist_path)
            
        return RedirectResponse(url="/settings?saved=true&msg=Custom+Wordlist+Deleted", status_code=303)
    except Exception as e:
        logger.error(f"Failed to delete wordlist: {e}")
        return RedirectResponse(url=f"/settings?error=Delete+Failed:+{str(e)}", status_code=303)

@router.post("/admin/reset", response_class=HTMLResponse)
async def admin_reset(session: Session = Depends(get_session)):
    """
    Resets the system:
    1. Purges Redis Queue
    2. Deletes DB Data (Targets, ScanResults, ModuleStates)
    """
    # 1. Purge & Kill Queue/Tasks
    try:
        # Purge waiting tasks
        celery_app.control.purge()
        
        # Revoke Active & Reserved Tasks
        i = celery_app.control.inspect()
        if i:
            active = i.active() or {}
            reserved = i.reserved() or {}
            
            # Combine all task IDs
            tasks_to_kill = []
            for worker_tasks in [active, reserved]:
                for worker, tasks in worker_tasks.items():
                    for task in tasks:
                         tasks_to_kill.append(task['id'])
            
            if tasks_to_kill:
                celery_app.control.revoke(tasks_to_kill, terminate=True)
                logger.warning(f"Reset: Revoked {len(tasks_to_kill)} active/reserved tasks.")
                
    except Exception as e:
        logger.error(f"Failed to purge queue: {e}")

    # 2. Delete Data
    # Truncate tables (Cascading usually handles it, but we do explicit delete for safety/clarity)
    session.exec(text("DELETE FROM changeevent"))
    session.exec(text("DELETE FROM scanresult"))
    session.exec(text("DELETE FROM modulestate"))
    session.exec(text("DELETE FROM target"))
    
    # 3. Clear Tenant Data (Requested by User)
    # Must preserve Users, but unlink them.
    session.exec(text('UPDATE "user" SET tenant_id = NULL'))
    session.exec(text("DELETE FROM usertenantlink"))
    session.exec(text("DELETE FROM tenant"))

    # 4. Re-Initialize Default Tenant -> REMOVED PER USER REQ
    # from yads.models import Tenant, UserTenantLink, User
    # default_tenant = Tenant(name="a customer")
    # session.add(default_tenant)
    # session.commit()
    # session.refresh(default_tenant)
    # logger.info("Reset: Re-created default tenant: a customer")
    
    # Auto-link 'admin' to default tenant -> REMOVED
    # admin = session.exec(select(User).where(User.username == "admin")).first()
    # if admin:
    #     session.add(UserTenantLink(user_id=admin.id, tenant_id=default_tenant.id))
    #     admin.tenant_id = default_tenant.id
    #     session.add(admin)
    #     session.commit()
    #     logger.info("Reset: Re-linked admin to default tenant.")

    # Reset Config? Maybe optional. Let's keep config.
    
    session.commit()
    
    logger.warning("System RESET executed by user.")
    
    return RedirectResponse(url="/settings?saved=true&msg=System+Reset+Complete", status_code=303)


async def admin_reset_system(request: Request, session: Session = Depends(get_session)):
    """
    Emergency Stop & Data Wipe:
    1. Purge Redis Queue
    2. Revoke all active tasks
    3. Delete all Targets & Scan Results
    """
    # 1. Purge Queue
    try:
        celery_app.control.purge()
    except Exception as e:
        logger.error(f"Failed to purge queue: {e}")

    # 2. Revoke Active/Reserved Tasks
    i = celery_app.control.inspect()
    active = i.active() if i else None
    reserved = i.reserved() if i else None
    
    if active:
        for worker, tasks in active.items():
            for task in tasks:
                celery_app.control.revoke(task['id'], terminate=True)
                
    if reserved:
        for worker, tasks in reserved.items():
            for task in tasks:
                celery_app.control.revoke(task['id'], terminate=True)

    # 3. Delete Data (Cascade)
    session.exec(text("DELETE FROM scanresult"))
    session.exec(text("DELETE FROM modulestate"))
    session.exec(text("DELETE FROM target"))
    session.commit()


# ---------------------------------------------------------------------------
# Rate-limit status endpoint
# ---------------------------------------------------------------------------

@router.get("/api/rate-limit/status")
async def get_rate_limit_status(
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
) -> JSONResponse:
    """
    Return current sliding-window usage for all external API rate limiters.

    Useful for monitoring whether YADS is close to hitting third-party API quotas.
    Accessible to platform admins and tenant admins.
    """
    try:
        from yads.core.api_rate_limiter import get_api_rate_limiter
        limiter = get_api_rate_limiter()
        status = limiter.get_status()
        return JSONResponse(content={"status": "ok", "services": status})
    except Exception as exc:
        logger.error("Failed to retrieve rate-limit status: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "detail": str(exc)},
        )


@router.post("/api/system/test-splunk")
async def test_splunk_connection(
    splunk_hec_url: str = Form(...),
    splunk_hec_token: str = Form(...),
    user: User = Depends(RoleChecker(["admin"])),
) -> JSONResponse:
    """
    Test Splunk HEC connectivity and token validity.
    """
    from yads.core.splunk_logger import splunk_logger
    success, msg = splunk_logger.test_connection(splunk_hec_url, splunk_hec_token)
    if success:
        return JSONResponse(content={"status": "ok", "message": msg})
    else:
        return JSONResponse(status_code=400, content={"status": "error", "detail": msg})


@router.get("/api/system/splunk-telemetry")
async def get_splunk_telemetry(
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
) -> JSONResponse:
    """
    Return current Splunk HEC queue depth, sent event count, and error metrics.
    """
    try:
        from yads.core.splunk_logger import splunk_logger
        stats = splunk_logger.get_stats()
        return JSONResponse(content={"status": "ok", "telemetry": stats})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(exc)})
