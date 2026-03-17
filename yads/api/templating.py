from fastapi.templating import Jinja2Templates
from datetime import datetime
from yads.config import settings
from yads.core.i18n import t as _translate, get_lang, SUPPORTED_LANGS

# Shared Templates Instance
templates = Jinja2Templates(directory="yads/api/templates")
templates.env.add_extension('jinja2.ext.do')

# --- Globals ---

def get_all_tenants():
    """
    Helper to fetch tenants for the sidebar dropdown.
    Imported locally to avoid circular imports during startup.
    """
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    try:
        with Session(engine) as session:
            return session.exec(select(Tenant).order_by(Tenant.name)).all()
    except Exception:
        return []

templates.env.globals['get_available_tenants'] = get_all_tenants

def get_lic_status():
    from yads.database import engine
    from yads.core.license import license_manager
    from sqlmodel import Session
    try:
        with Session(engine) as session:
            return license_manager.get_license_status(session)
    except Exception:
        return None

templates.env.globals['get_license_status'] = get_lic_status

def get_activation_required():
    """Returns True if this is a business license that has not yet been activated."""
    from yads.database import engine
    from yads.core.license import license_manager, activation_verifier
    from yads.models import SystemConfig
    from sqlmodel import Session
    try:
        with Session(engine) as session:
            lic_conf = session.get(SystemConfig, "license_key")
            if not lic_conf or not lic_conf.value:
                return False
            lic_data = license_manager.verify(lic_conf.value)
            if not lic_data or not lic_data.get("customer_id"):
                return False  # CE — no activation required
            act_conf = session.get(SystemConfig, "ACTIVATION_CODE")
            uuid_conf = session.get(SystemConfig, "INSTANCE_UUID")
            instance_uuid = uuid_conf.value if uuid_conf else None
            if not act_conf or not act_conf.value:
                return True
            return not bool(activation_verifier.verify(act_conf.value, instance_uuid))
    except Exception:
        return False

templates.env.globals['get_activation_required'] = get_activation_required
templates.env.globals['settings'] = settings
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
templates.env.globals['_'] = _translate
templates.env.globals['get_lang'] = get_lang
templates.env.globals['SUPPORTED_LANGS'] = SUPPORTED_LANGS


# --- Filters ---

def timestamp_to_time(ts):
    try:
        if not ts: return "-"
        return datetime.fromtimestamp(ts).strftime('%H:%M:%S')
    except:
        return str(ts)

def prettify_task_name(name):
    if not name: return "Unknown"
    if name == "yads.worker.run_all_scans":
        return "Standard Scan"
    return name.split('.')[-1]

templates.env.filters["timestamp_to_time"] = timestamp_to_time
templates.env.filters["prettify_task"] = prettify_task_name
