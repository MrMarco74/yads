from fastapi.templating import Jinja2Templates
from datetime import datetime
from yads.config import settings
from yads.core.i18n import t as _translate, get_lang, SUPPORTED_LANGS
from jinja2 import pass_context
from markupsafe import Markup, escape

# Shared Templates Instance
print("--- YADS TEMPLATING SYSTEM INITIALIZING ---", flush=True)
templates = Jinja2Templates(directory="yads/api/templates")
templates.env.add_extension('jinja2.ext.do')

@pass_context
def csrf_token(context):
    """Returns a hidden CSRF input field."""
    request = context.get('request')
    if not request:
        return Markup('')
    token = request.scope.get('csrf_token', '')
    return Markup(f'<input type="hidden" name="_csrf" value="{escape(token)}">')

@pass_context
def csrf_token_value(context):
    """Returns the raw CSRF token value."""
    request = context.get('request')
    if not request:
        return ''
    return request.scope.get('csrf_token', '')

templates.env.globals['csrf_token'] = csrf_token
templates.env.globals['csrf_token_value'] = csrf_token_value

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
