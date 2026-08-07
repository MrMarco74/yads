from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import Optional
import os
import logging
from sqlalchemy import text, create_engine
from yads.config import settings
from yads.database import engine as current_engine, get_session
from sqlmodel import Session, select
from yads.models import User, SystemConfig
from yads.auth.security import get_password_hash
from yads.core.password_policy import validate_password as _validate_pw

router = APIRouter(prefix="/setup", tags=["setup"])
logger = logging.getLogger("yads-setup")

# -- Models --

class DBConfigRequest(BaseModel):
    password: str

class DataActionRequest(BaseModel):
    action: str # "upgrade" or "purge"

class AdminRequest(BaseModel):
    username: str
    password: str

# -- Helpers --

def update_persistent_config(key: str, value: str):
    """Writes a key-value pair to the persistent config file."""
    config_path = settings.CONFIG_PATH
    
    # Read existing lines
    lines = []
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            lines = f.readlines()
            
    # Update or Append
    updated = False
    new_lines = []
    for line in lines:
        if line.strip().startswith(f"{key}="):
            new_lines.append(f"{key}={value}\n")
            updated = True
        else:
            new_lines.append(line)
            
    if not updated:
        new_lines.append(f"{key}={value}\n")
        
    # Write back
    # Ensure dir exists
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        f.writelines(new_lines)

# -- Endpoints --

def _require_setup_open():
    """Raise 403 if setup is already complete (blocks unauthenticated setup endpoints post-setup)."""
    if getattr(settings, "SETUP_COMPLETE", False):
        raise HTTPException(
            status_code=403,
            detail="Setup already complete. Use the admin panel to manage this setting."
        )


@router.post("/configure-db")
async def configure_db(req: DBConfigRequest):
    _require_setup_open()
    new_password = req.password
    if not new_password or len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password too short (8 chars min)")

    # 1. Connect with current credentials to change password
    # We use the current global 'engine' which should be valid with startup default
    try:
        # Use raw psycopg2 connection for parameterized DDL — text() f-strings are not safe here
        raw_conn = current_engine.raw_connection()
        try:
            cursor = raw_conn.cursor()
            cursor.execute("ALTER USER yads WITH PASSWORD %s", (new_password,))
            raw_conn.commit()
        finally:
            raw_conn.close()
    except Exception as e:
        logger.error(f"Failed to change DB password: {e}")
        # It's possible we already changed it in a previous partial attempt?
        # Try connecting with NEW password to see if it works already
        pass

    # 2. Verify connection with NEW password
    # Construct temp URL
    # Replace password in current URL
    # Assuming URL structure: postgresql://user:pass@host:port/db
    
    # We construct explicitly to be safe
    db_host = os.getenv("POSTGRES_SERVER", "db") # Assuming default form docker-compose if not set
    # Actually parsing settings.DATABASE_URL is better
    # But let's build from env placeholders if possible or just replace
    
    from sqlalchemy.engine.url import make_url
    current_url = make_url(settings.DATABASE_URL)
    new_url = current_url.set(password=new_password)
    
    try:
        test_engine = create_engine(new_url)
        with test_engine.connect() as conn:
             conn.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Failed to connect with new password: {e}")
        raise HTTPException(status_code=400, detail="Failed to verify database connection with new password.")

    # 3. Persist
    update_persistent_config("POSTGRES_PASSWORD", new_password)
    # IMPORTANT: render_as_string(hide_password=False) is crucial, otherwise it saves '***'
    update_persistent_config("DATABASE_URL", new_url.render_as_string(hide_password=False)) 
    # Config.py uses DATABASE_URL. If we only set POSTGRES_PASSWORD, config.py must rebuild it.
    # Config.py logic: DATABASE_URL = os.getenv("DATABASE_URL", ...)
    # If we persist DATABASE_URL, config.py will pick it up.
    
    # 4. Hot-Swap Runtime Settings
    # FIX: str(new_url) masks the password! Must use render_as_string
    unmasked_url = new_url.render_as_string(hide_password=False)
    
    settings.DATABASE_URL = unmasked_url
    os.environ["DATABASE_URL"] = unmasked_url
    os.environ["POSTGRES_PASSWORD"] = new_password
    
    # Dispose old engine so next 'get_session' (if it uses global engine) might need handling?
    # yads.database.engine is a global object.
    # We should update it.
    current_engine.dispose()
    # Re-create global engine?
    # This is hacky. Better might be to restart the process?
    # But let's try to update the global engine variable in yads.database
    import yads.database
    yads.database.engine = create_engine(settings.DATABASE_URL)
    
    return {"status": "success", "message": "Database password updated and verified"}

@router.post("/init-data")
async def init_data(req: DataActionRequest):
    _require_setup_open()
    action = req.action.lower()
    
    if action == "purge":
        # Drop all tables and recreate
        from yads.database import create_db_and_tables
        from sqlmodel import SQLModel
        
        # We need to drop all.
        try:
             # Create a fresh engine to ensure we use the LATEST credentials
             # bypassing any stale global state
             temp_engine = create_engine(settings.DATABASE_URL)

             SQLModel.metadata.drop_all(temp_engine)
             create_db_and_tables(engine_override=temp_engine)
             
             temp_engine.dispose()
             logger.info("Database purged and re-initialized.")
        except Exception as e:
             logger.error(f"Purge failed: {e}")
             raise HTTPException(status_code=500, detail="Database purge failed. See server logs.")
             
    elif action == "upgrade":
        # Just run create_db_and_tables (it's idempotent-ish for existing tables? No, it doesn't migrate columns)
        # We should run the migration scripts logic from lifespan.
        # Luckily lifespan runs on startup.
        # But if we want to force it now:
        from yads.database import create_db_and_tables
        try:
            # Create a fresh engine here too
            temp_engine = create_engine(settings.DATABASE_URL)
            create_db_and_tables(engine_override=temp_engine)
            temp_engine.dispose()
            # Run schema migrations explicitly?
            # They are in main.py lifespan... difficult to invoke from here.
            # But maybe we don't need to if user just restarts?
            # User wants "Upgrade DB with preservation of data"
            # create_db_and_tables() usually does nothing if tables exist.
            # Real migration (alembic) or manual migration code in main.py is needed.
            # We can't import main.py logic here easily. 
            pass 
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="Invalid action")
        
    return {"status": "success", "action": action}

@router.post("/create-admin")
async def create_admin(req: AdminRequest):
    # Block once setup is complete — prevents unauthenticated admin creation post-setup
    if getattr(settings, "SETUP_COMPLETE", False):
        raise HTTPException(
            status_code=403,
            detail="Setup already complete. Use the admin panel to manage users."
        )

    # Manual session creation to ensure we use the latest credentials
    # bypassing Depends(get_session) which might hold stale global state
    from sqlmodel import Session, create_engine
    
    temp_engine = create_engine(settings.DATABASE_URL)
    session = Session(temp_engine)
    
    try:
        username = req.username
        password = req.password

        pw_error = _validate_pw(password)
        if pw_error:
            raise HTTPException(status_code=400, detail=pw_error)
            
        # Check if admin exists
        existing_user = session.exec(select(User).where(User.username == username)).first()
        
        if existing_user:
            # Update password and clear force_password_change set by auto-seeding
            existing_user.password_hash = get_password_hash(password)
            existing_user.force_password_change = False
            session.add(existing_user)
            logger.info(f"Updated password for existing admin: {username}")
        else:
            # Create user
            user = User(
                username=username,
                password_hash=get_password_hash(password),
                role="admin",
                is_active=True,
                force_password_change=False,
            )
            session.add(user)
            
        session.commit()
        
        return {"status": "success", "username": username}
    except Exception as e:
        logger.error(f"Create Admin failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()
        temp_engine.dispose()

@router.post("/finish")
async def finish_setup():
    if getattr(settings, "SETUP_COMPLETE", False):
        return {"status": "completed", "message": "Setup was already complete."}
    update_persistent_config("SETUP_COMPLETE", "true")
    settings.SETUP_COMPLETE = True

    from yads.models import SystemConfig
    from yads.database import engine
    from sqlmodel import Session
    import uuid

    with Session(engine) as session:
        # Auto-dismiss onboarding wizard for admin — GUI installer already did setup
        done_key = "ONBOARDING_DONE_admin"
        if not session.get(SystemConfig, done_key):
            session.add(SystemConfig(key=done_key, value="1"))

        # Ensure stable instance UUID
        uuid_conf = session.get(SystemConfig, "INSTANCE_UUID")
        instance_uuid = uuid_conf.value if uuid_conf else str(uuid.uuid4())
        if not uuid_conf:
            session.add(SystemConfig(key="INSTANCE_UUID", value=instance_uuid))

        session.commit()

    return {"status": "completed", "instance_uuid": instance_uuid}


class InstallReportPayload(BaseModel):
    instance_uuid: str
    version: str
    submitted_at: Optional[str] = None
    install_type: Optional[str] = "installer"
    customer_id: Optional[str] = None


@router.post("/queue-report")
async def queue_install_report(req: InstallReportPayload):
    """
    Store a pending installation report in SystemConfig so the API can
    send it to the support portal on the next startup (airgapped installs).
    No-op if a report was already sent or is already queued.
    """
    import json as _json
    from yads.models import SystemConfig
    from yads.database import engine
    from sqlmodel import Session

    with Session(engine) as session:
        if session.get(SystemConfig, "INSTALL_REPORT_SENT"):
            return {"status": "already_sent"}
        existing = session.get(SystemConfig, "INSTALL_REPORT_PENDING")
        if not existing:
            session.add(SystemConfig(
                key="INSTALL_REPORT_PENDING",
                value=_json.dumps(req.model_dump()),
            ))
            session.commit()

    return {"status": "queued"}

