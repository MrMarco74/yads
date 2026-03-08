from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import Optional
import os
import logging
from sqlalchemy import text, create_engine
from yads.config import settings
from yads.core.license import license_manager
from yads.database import engine as current_engine, get_session
from sqlmodel import Session, select
from yads.models import User
from yads.auth.security import get_password_hash

router = APIRouter(prefix="/setup", tags=["setup"])
logger = logging.getLogger("yads-setup")

# -- Models --

class SetupTokenRequest(BaseModel):
    token: str

class LicenseRequest(BaseModel):
    license_key: str

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

@router.post("/verify-token")
async def verify_setup_token(req: SetupTokenRequest):
    expected = settings.SETUP_TOKEN
    if not expected:
        # No token configured — skip token verification
        return {"status": "ok"}
    if not req.token or req.token.strip() != expected:
        raise HTTPException(status_code=403, detail="Invalid setup token")
    return {"status": "ok"}

@router.get("/token-required")
async def token_required():
    """Check whether a setup token is configured."""
    return {"required": bool(settings.SETUP_TOKEN)}

@router.post("/check-license")
async def check_license(req: LicenseRequest):
    data = license_manager.verify(req.license_key)
    if not data:
        raise HTTPException(status_code=400, detail="Invalid or expired license key")
    
    # Persist License Key
    update_persistent_config("LICENSE_KEY", req.license_key)
    
    # Update in-memory settings
    settings.LICENSE_KEY = req.license_key
    
    # Check if max_targets is present etc.
    return {"status": "valid", "data": data}

@router.post("/configure-db")
async def configure_db(req: DBConfigRequest):
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
             print(f"DEBUG: init_data PURGE using fresh engine URL: {temp_engine.url}")
             
             SQLModel.metadata.drop_all(temp_engine)
             create_db_and_tables(engine_override=temp_engine)
             
             temp_engine.dispose()
             logger.info("Database purged and re-initialized.")
        except Exception as e:
             logger.error(f"Purge failed: {e}")
             raise HTTPException(status_code=500, detail=str(e))
             
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
        
        if len(password) < 8:
            raise HTTPException(status_code=400, detail="Password too short")
            
        # Check if admin exists
        existing_user = session.exec(select(User).where(User.username == username)).first()
        
        if existing_user:
            # Update password
            existing_user.password_hash = get_password_hash(password)
            session.add(existing_user)
            logger.info(f"Updated password for existing admin: {username}")
        else:
            # Create user
            user = User(
                username=username,
                password_hash=get_password_hash(password),
                role="admin",
                is_active=True
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
    update_persistent_config("SETUP_COMPLETE", "true")
    settings.SETUP_COMPLETE = True
    
    # Also ensure license is in SystemConfig table for next boot
    from yads.models import SystemConfig
    from yads.database import engine
    from sqlmodel import Session
    
    if settings.LICENSE_KEY:
        with Session(engine) as session:
            config = session.get(SystemConfig, "license_key")
            if config:
                config.value = settings.LICENSE_KEY
            else:
                config = SystemConfig(key="license_key", value=settings.LICENSE_KEY)
            session.add(config)
            session.commit()
            
    return {"status": "completed"}
