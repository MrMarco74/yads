import logging
import json
import os
import shutil
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
from celery import Celery
from yads.config import settings
celery_app = Celery('yads_worker', broker=settings.REDIS_URL, backend=settings.REDIS_URL)

logger = logging.getLogger(__name__)
router = APIRouter()


def _register_license_key_with_portal(license_token: str) -> None:
    """
    Auto-register the Ed25519 report-signing public key with the support portal.
    Called in a background thread after a license key is saved.
    Uses the self-service /api/register-key endpoint — no admin credentials needed.
    """
    try:
        import base64
        import requests
        from yads.core.license import _get_license_payload

        # Decode payload without DB (inline decode — token is already validated by caller)
        payload_b64 = license_token.split(".")[0]
        pad = len(payload_b64) % 4
        if pad:
            payload_b64 += "=" * (4 - pad)
        import json as _json
        payload = _json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))

        report_signing_key_b64 = payload.get("report_signing_key")
        customer_id = payload.get("customer_id")

        # Always send/update installation report when a license key is entered,
        # even for CE keys without customer_id — creates or updates the record.
        try:
            from yads.database import engine as _eng
            from yads.models import SystemConfig as _SC
            from sqlmodel import Session as _Sess
            from yads.api.routers.updates import get_update_manager

            with _Sess(_eng) as _s:
                uuid_conf = _s.get(_SC, "INSTANCE_UUID")
                instance_uuid = uuid_conf.value if uuid_conf else None

            version = "unknown"
            try:
                version = get_update_manager().state.current_version or version
            except Exception:
                pass

            if instance_uuid:
                portal_url_early = settings.SUPPORT_PORTAL_URL.rstrip("/")
                ir = requests.post(
                    f"{portal_url_early}/api/installation",
                    json={
                        "instance_uuid": instance_uuid,
                        "version": version,
                        "install_type": "installer",
                        "customer_id": customer_id or None,
                    },
                    timeout=10,
                    verify=settings.SUPPORT_PORTAL_VERIFY_SSL,
                )
                if ir.status_code == 200:
                    logger.info(f"[LicenseSync] Installation report sent for instance {instance_uuid[:8]}…")
                else:
                    logger.warning(f"[LicenseSync] Installation report failed: {ir.status_code}")
        except Exception as _ie:
            logger.warning(f"[LicenseSync] Could not send installation report: {_ie}")

        if not report_signing_key_b64 or not customer_id:
            logger.info("[LicenseSync] CE license — no report_signing_key/customer_id, skipping key registration.")
            return

        # Derive public key from private key seed
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        raw_seed = base64.b64decode(report_signing_key_b64)
        pub_bytes = Ed25519PrivateKey.from_private_bytes(raw_seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub_b64 = base64.b64encode(pub_bytes).decode()

        portal_url = settings.SUPPORT_PORTAL_URL.rstrip("/")
        verify_ssl = settings.SUPPORT_PORTAL_VERIFY_SSL
        resp = requests.post(
            f"{portal_url}/api/register-key",
            json={"license_token": license_token},
            timeout=10,
            verify=verify_ssl,
        )
        if resp.status_code == 200:
            logger.info(f"[LicenseSync] Successfully registered public key for customer {customer_id} with support portal.")
        elif resp.status_code == 503:
            logger.warning("[LicenseSync] Support portal self-registration not configured (LICENSE_AUTHORITY_PUBLIC_KEY missing).")
        else:
            logger.warning(f"[LicenseSync] Support portal returned {resp.status_code}: {resp.text[:200]}")

    except Exception as e:
        logger.warning(f"[LicenseSync] Failed to sync license key with support portal: {e}")


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
@router.post("/admin/tools/nuclei-update")
async def admin_nuclei_update(request: Request, user: User = Depends(RoleChecker(["admin"]))):
    """
    Manually triggers 'nuclei -ut' to update vulnerability templates.
    """
    import subprocess
    logger.info(f"Admin {user.username} triggered Nuclei template update.")
    try:
        # Run update command
        proc = subprocess.Popen(["nuclei", "-ut"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # nosec B603 B607 - hardcoded nuclei command, no user input
        stdout, stderr = proc.communicate(timeout=600) # 10 min timeout
        
        if proc.returncode == 0:
            last_line = stdout.splitlines()[-1] if stdout.strip() else "Templates are up to date."
            return HTMLResponse(content=f'<div class="bg-green-900/40 border border-green-500/50 text-green-200 p-2 rounded text-[10px] mt-2 animate-fade-in">{last_line}</div>')
        else:
            return HTMLResponse(content=f'<div class="bg-red-900/40 border border-red-500/50 text-red-200 p-2 rounded text-[10px] mt-2 animate-fade-in">Update failed ({proc.returncode}): {stderr[:100]}</div>')
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
             import os
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
    
    # --- License Info ---
    from yads.core.license import license_manager
    license_conf = session.get(SystemConfig, "license_key")
    license_data = None
    license_status = "Free Tier (Limit 5)"
    license_limit = 5

    if license_conf and license_conf.value:
        data = license_manager.verify(license_conf.value)
        if data:
            license_data = data
            license_limit = data.get("max_targets", 0)
            exp_date = datetime.fromtimestamp(data.get("exp", 0)).strftime("%Y-%m-%d")
            license_status = f"Valid (Customer: {data.get('sub')}, Expires: {exp_date})"
        else:
            license_status = "Invalid / Expired"

    # --- Activation Status ---
    activation_code_conf = session.get(SystemConfig, "ACTIVATION_CODE")
    activation_data = None
    is_business_license = bool(license_data and license_data.get("customer_id"))
    if activation_code_conf and activation_code_conf.value:
        activation_data = license_manager.verify(activation_code_conf.value)
    instance_uuid_conf = session.get(SystemConfig, "INSTANCE_UUID")
    instance_uuid = instance_uuid_conf.value if instance_uuid_conf else None

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
        "license_key": license_conf.value if license_conf else "",
        "license_status": license_status,
        "license_data": license_data,
        "license_limit": license_limit,
        "is_business_license": is_business_license,
        "activation_data": activation_data,
        "instance_uuid": instance_uuid,
        "ce_state": __import__('yads.core.community_edition', fromlist=['get_ce_state']).get_ce_state(session),
        "global_max_concurrent_scans": global_max_concurrent_scans,
        "global_max_network_mbps": global_max_network_mbps,
        "default_wordlist_count": default_wordlist_count,
        "nuclei_last_updated": nuclei_last_updated,
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
    splunk_hec_token: str = Form(None, max_length=256),
    smtp_host: str = Form(None, max_length=253),
    smtp_port: str = Form(None, max_length=5),
    smtp_user: Optional[str] = Form(None, max_length=254),
    smtp_password: Optional[str] = Form(None, max_length=256),
    smtp_from: Optional[str] = Form(None, max_length=254),
    email_notification_address: Optional[str] = Form(None, max_length=254),
    email_notifications_enabled: bool = Form(False),
    base_url: Optional[str] = Form(None, max_length=500),
    data_retention_days: int = Form(90),

    # License
    license_key: Optional[str] = Form(None, max_length=2048),

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
            
    # Save License
    if license_key is not None:
        trimmed_lic = license_key.strip()
        set_conf("license_key", trimmed_lic)
        settings.LICENSE_KEY = trimmed_lic
        logger.info(f"Runtime License Key updated via UI.")
        # Auto-register Ed25519 public key with support portal (fire-and-forget)
        if trimmed_lic:
            import threading
            threading.Thread(
                target=_register_license_key_with_portal,
                args=(trimmed_lic,),
                daemon=True,
            ).start()
    
    # Update Auto Queue
    if auto_queue is not None: set_conf("AUTO_QUEUE_SUBDOMAINS", "true") 
    else: set_conf("AUTO_QUEUE_SUBDOMAINS", "false")
        
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

    if client_key_path is not None:
        client_key_path = client_key_path.strip()
        set_conf("CLIENT_KEY_PATH", client_key_path)

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


@router.get("/license", response_class=HTMLResponse)
async def view_license(request: Request, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin"]))):
    from yads.core.license import license_manager
    from yads.models import SystemConfig

    license_conf = session.get(SystemConfig, "license_key")
    license_data = None
    license_status = "Free Tier (Limit 5)"
    license_limit = 5
    license_key = ""

    if license_conf and license_conf.value:
        license_key = license_conf.value
        data = license_manager.verify(license_conf.value)
        if data:
            license_data = data
            license_limit = data.get("max_targets", 0)
            exp_date = datetime.fromtimestamp(data.get("exp", 0)).strftime("%Y-%m-%d")
            license_status = f"Valid (Customer: {data.get('sub')}, Expires: {exp_date})"
        else:
            license_status = "Invalid / Expired"

    activation_code_conf = session.get(SystemConfig, "ACTIVATION_CODE")
    activation_data = None
    is_business_license = bool(license_data and license_data.get("customer_id"))
    if activation_code_conf and activation_code_conf.value:
        activation_data = license_manager.verify(activation_code_conf.value)
    instance_uuid_conf = session.get(SystemConfig, "INSTANCE_UUID")
    instance_uuid = instance_uuid_conf.value if instance_uuid_conf else None

    from yads.core.community_edition import get_ce_state
    ce_state = get_ce_state(session)

    msg = request.query_params.get("msg")
    error = request.query_params.get("error")

    return templates.TemplateResponse("license.html", {
        "request": request,
        "user": user,
        "license_key": license_key,
        "license_data": license_data,
        "license_status": license_status,
        "license_limit": license_limit,
        "is_business_license": is_business_license,
        "activation_data": activation_data,
        "instance_uuid": instance_uuid,
        "ce_state": ce_state,
        "msg": msg,
        "error": error,
    })


@router.post("/license/save-key")
async def save_license_key(
    request: Request,
    license_key: str = Form(default="", max_length=2048),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin"]))
):
    from yads.models import SystemConfig
    trimmed = license_key.strip()
    # Persist to DB (for immediate effect)
    existing = session.get(SystemConfig, "license_key")
    if existing:
        existing.value = trimmed
        session.add(existing)
    else:
        session.add(SystemConfig(key="license_key", value=trimmed))
    session.commit()
    # Persist to config file + update in-memory settings
    from yads.api.routers.setup import update_persistent_config
    update_persistent_config("LICENSE_KEY", trimmed)
    settings.LICENSE_KEY = trimmed
    if trimmed:
        import threading
        threading.Thread(target=_register_license_key_with_portal, args=(trimmed,), daemon=True).start()
    return RedirectResponse(url="/license?msg=Lizenzschlüssel+gespeichert", status_code=303)


@router.post("/license/check-activation")
async def check_activation_from_portal(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin"])),
):
    """
    Poll the support portal for an approved activation response code.
    If found, save it as the license key and redirect to /license with a success message.
    """
    import urllib.request as _urllib
    import urllib.error as _urlerr

    instance_uuid_conf = session.get(SystemConfig, "INSTANCE_UUID")
    if not instance_uuid_conf or not instance_uuid_conf.value:
        return RedirectResponse(url="/license?error=Keine+Instance-UUID+konfiguriert", status_code=303)

    instance_uuid = instance_uuid_conf.value.strip()
    portal_url = settings.SUPPORT_PORTAL_URL.rstrip("/")

    try:
        req = _urllib.Request(
            f"{portal_url}/api/installation/activation/{instance_uuid}",
            headers={"Accept": "application/json"},
        )
        ctx = None
        if not settings.SUPPORT_PORTAL_VERIFY_SSL:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with _urllib.urlopen(req, timeout=10, context=ctx) as resp:
            import json as _json
            data = _json.loads(resp.read())
    except _urlerr.URLError as e:
        return RedirectResponse(url=f"/license?error=Portal+nicht+erreichbar:+{e.reason}", status_code=303)
    except Exception as e:
        return RedirectResponse(url=f"/license?error=Fehler:+{e}", status_code=303)

    status = data.get("status")
    if status == "not_found":
        return RedirectResponse(url="/license?error=Keine+Aktivierungsanfrage+im+Portal+gefunden", status_code=303)
    if status == "pending":
        return RedirectResponse(url="/license?error=Aktivierung+noch+ausstehend+(pending)", status_code=303)
    if status == "rejected":
        return RedirectResponse(url="/license?error=Aktivierung+wurde+abgelehnt", status_code=303)

    response_code = data.get("response_code", "").strip()
    if not response_code:
        return RedirectResponse(url="/license?error=Kein+Antwortcode+im+Portal+hinterlegt", status_code=303)

    # Save as license key
    existing = session.get(SystemConfig, "license_key")
    if existing:
        existing.value = response_code
        session.add(existing)
    else:
        session.add(SystemConfig(key="license_key", value=response_code))
    session.commit()

    threading.Thread(target=_register_license_key_with_portal, args=(response_code,), daemon=True).start()
    return RedirectResponse(url="/license?msg=Aktivierungscode+erfolgreich+vom+Portal+abgerufen+und+gespeichert", status_code=303)


@router.post("/admin/license/validate", response_class=HTMLResponse)
async def validate_license_ui(
    request: Request,
    license_key: str = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin"]))
):
    from yads.core.license import license_manager
    
    trimmed_lic = license_key.strip()
    data = license_manager.verify(trimmed_lic)
    
    license_status = "Invalid or Expired"
    license_limit = 0
    license_data = {}
    
    if data:
        license_status = "Valid License"
        license_limit = data.get("max_targets", 0)
        license_data = data
        
    return templates.TemplateResponse("_license_card_content.html", {
        "request": request,
        "license_key": trimmed_lic,
        "license_status": license_status,
        "license_data": license_data,
        "license_limit": license_limit
    })



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

    return RedirectResponse(url="/settings?saved=true&msg=System+Reset+Complete", status_code=303)


# ── Community Edition endpoints ───────────────────────────────────────────────

@router.post("/admin/ce/activate", response_class=HTMLResponse)
async def ce_activate(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin"])),
):
    from yads.core.community_edition import activate, get_ce_state
    already = get_ce_state(session)["edition"] == "community"
    activate(session)
    state = get_ce_state(session)
    msg = "bereits aktiv" if already else "Community Edition aktiviert"
    return templates.TemplateResponse("_ce_card.html", {
        "request": request,
        "ce_state": state,
        "msg": msg,
    })


@router.post("/admin/ce/extend", response_class=HTMLResponse)
async def ce_extend(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin"])),
):
    from yads.core.community_edition import extend, get_ce_state
    ok, msg = extend(session)
    state = get_ce_state(session)
    return templates.TemplateResponse("_ce_card.html", {
        "request": request,
        "ce_state": state,
        "msg": msg,
    })
