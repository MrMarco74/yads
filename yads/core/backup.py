import logging
import json
import os
import shutil
import zipfile
import io
from datetime import datetime
from typing import List, Type, Dict, Any
from sqlmodel import Session, select, SQLModel, text
from sqlalchemy import MetaData

from yads.config import settings

# Encryption dependencies
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)
from yads.models import Target, ScanResult, ModuleState, SystemConfig, ChangeEvent, Tenant, User, UserTenantLink, SecurityTrend, Webhook, ScanSchedule, Notification, ChangelogEntry

# List of models to backup/restore in order (parents first for restore)
MODELS = [Tenant, User, UserTenantLink, SystemConfig, ChangelogEntry, Target, ScanResult, ModuleState, ChangeEvent, SecurityTrend, Webhook, ScanSchedule, Notification]

# Tables excluded by default in Safe Import Mode
SYSTEM_TABLES = ["user", "usertenantlink", "systemconfig", "changeevent"]

SCREENSHOT_DIR = "yads/api/static/screenshots"

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derives a url-safe base64-encoded 32-byte key from password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: bytes, password: str) -> bytes:
    """
    Encrypts data using Fernet (AES).
    Format: [16 bytes salt][Fernet Token]
    """
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    f = Fernet(key)
    token = f.encrypt(data)
    return salt + token

def decrypt_data(data: bytes, password: str) -> bytes:
    """
    Decrypts data. Expects [16 bytes salt][Fernet Token].
    """
    if len(data) < 16:
        raise ValueError("Invalid encrypted data (too short)")
    
    salt = data[:16]
    token = data[16:]
    key = _derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(token)

def json_serializer(obj):
    """Custom JSON serializer for datetime objects"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def create_backup_zip(session: Session, tenant_ids: List[int] = None, password: str = None) -> io.BytesIO:
    """
    Creates a ZIP archive containing:
    1. JSON dumps of all DB tables (optionally filtered by tenant).
    2. The entire screenshots directory.
    
    If password is provided, returns an ENCRYPTED blob (not a valid zip until decrypted).
    
    Returns a BytesIO object of the file (Zip or Encrypted Blob).
    """
    memory_file = io.BytesIO()
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # 1. Backup Database Tables
        for model in MODELS:
            table_name = model.__tablename__
            
            # Filtering Logic
            stmt = select(model)
            
            if tenant_ids:
                if table_name == "tenant":
                     stmt = stmt.where(model.id.in_(tenant_ids))
                     
                elif hasattr(model, "tenant_id"):
                     # SecurityTrend, Webhook, Target, User
                     stmt = stmt.where(model.tenant_id.in_(tenant_ids))

                elif table_name == "scanschedule":
                     # Link via Target
                     stmt = stmt.join(Target).where(Target.tenant_id.in_(tenant_ids))

                elif table_name == "changeevent":
                     # Link via ScanResult -> Target
                     stmt = stmt.join(ScanResult).join(Target).where(Target.tenant_id.in_(tenant_ids))
                     
                elif table_name == "scanresult" or table_name == "modulestate":
                     # Direct link to Target
                     stmt = stmt.join(Target).where(Target.tenant_id.in_(tenant_ids))

                elif table_name == "usertenantlink":
                     stmt = stmt.where(model.tenant_id.in_(tenant_ids))

                elif table_name == "systemconfig" or table_name == "notification" or table_name == "changelogentry":
                     # Skip SystemConfig, Notification, ChangelogEntry for partial (tenant) backups
                     # They are global system data.
                     continue
            
            # For SystemConfig in full backup (no tenant_ids), it just passes through.
            
            records = session.exec(stmt).all()
            
            # Serialize to list of dicts
            data = [record.model_dump() for record in records]
            
            # Write JSON to zip
            json_str = json.dumps(data, default=json_serializer, indent=2)
            zf.writestr(f"data/{table_name}.json", json_str)
            
        # 2. Metadata (Version, Timestamp)
        meta = {
            "version": settings.VERSION,
            "timestamp": datetime.utcnow().isoformat(),
            "compatibility": "1.9", # Bumped for encryption feature awareness?
            "tenant_ids": tenant_ids if tenant_ids else [],
            "type": "partial" if tenant_ids else "full",
            "encrypted": True if password else False
        }
        zf.writestr("metadata.json", json.dumps(meta, indent=2))
            
        # 3. Backup Screenshots
        # Logic: If tenant_ids provided, only include screenshots referenced in ScanResults for those tenants.
        # Otherwise, include all.
        
        allowed_files = None
        if tenant_ids:
            # Fetch relevant screenshots
            stmt = select(ScanResult.data).join(Target).where(
                Target.tenant_id.in_(tenant_ids),
                ScanResult.module_name.in_(["web_analyzer", "visual_osint"])
            )
            results = session.exec(stmt).all()
            allowed_files = set()
            for r_data in results:
                if r_data and isinstance(r_data, dict) and "screenshot_path" in r_data:
                    fname = r_data["screenshot_path"]
                    if fname: allowed_files.add(fname)
                    
        if os.path.exists(SCREENSHOT_DIR):
            for root, dirs, files in os.walk(SCREENSHOT_DIR):
                for file in files:
                    # Filter check
                    if allowed_files is not None and file not in allowed_files:
                        continue

                    file_path = os.path.join(root, file)
                    # Archive path should be relative to storing "screenshots/" at root of zip
                    archive_path = os.path.join("screenshots", os.path.relpath(file_path, SCREENSHOT_DIR))
                    zf.write(file_path, arcname=archive_path)
                    
    memory_file.seek(0)
    raw_zip_bytes = memory_file.read()
    
    if password:
        logger.info("Encrypting backup archive...")
        encrypted_bytes = encrypt_data(raw_zip_bytes, password)
        return io.BytesIO(encrypted_bytes)
        
    memory_file.seek(0)
    return memory_file

def restore_backup_from_zip(session: Session, zip_bytes: bytes, target_tenant_ids: List[int] = None, exclude_system: bool = True, password: str = None):
    """
    Restores data from a ZIP archive.
    Strategy: 
    - If Full Backup (no tenant_ids in meta): Wipe All -> Restore All.
    - If Tenant Backup: Purge specific Tenants -> Restore data.
    
    Args:
        exclude_system: If True, skips User, UserTenantLink, SystemConfig to prevent overwriting admins/settings.
        password: If provided, attempts to decrypt data first.
    """
    logger.info(f"Starting backup restore process... (exclude_system={exclude_system}, password_provided={bool(password)})")
    
    # Decryption Logic
    if password:
        try:
            zip_bytes = decrypt_data(zip_bytes, password)
            logger.info("Backup successfully decrypted.")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Invalid password or corrupted backup file.")
    
    # Try opening as Zip to verify (or it might fail if encrypted but no password given)
    try:
        zf_check = zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') 
        zf_check.close()
    except zipfile.BadZipFile:
        if not password:
            raise ValueError("File is not a valid ZIP. It might be encrypted (password required).")
        raise
    
    meta = {}
    
    # Pre-Check: Read Metadata
    with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
        if "metadata.json" in zf.namelist():
            try:
                meta = json.loads(zf.read("metadata.json"))
                logger.debug(f"Backup metadata found: {meta}")
            except Exception as e:
                logger.error(f"Failed to read metadata.json: {e}")
    
    backup_type = meta.get("type", "full")
    tenant_ids = meta.get("tenant_ids", [])
    logger.info(f"Backup type: {backup_type}, Tenant IDs in backup: {tenant_ids}")
    
    table_names = [model.__tablename__ for model in MODELS]

    # Tables to SKIP if exclude_system is True
    # User requested to exclude 'changeevent' as well.
    SYSTEM_TABLES = ["user", "usertenantlink", "systemconfig", "changeevent", "changelogentry"]

    if backup_type == "partial" and tenant_ids:
        logger.info("Performing PARTIAL restore strategy.")
        
        # --- PARTIAL RESTORE STRATEGY ---
        # 1. Purge Existing Data for these Tenants
        logger.debug(f"Purging existing data for tenants: {tenant_ids}")
        
        # Get Targets for these tenants
        # Fetch objects first to safely get distinct IDs
        targets = session.exec(select(Target).where(Target.tenant_id.in_(tenant_ids))).all()
        target_ids = [t.id for t in targets if t.id is not None]
        
        target_ids_str = ",".join(map(str, target_ids)) if target_ids else "NULL"
        logger.debug(f"Found {len(target_ids)} targets to purge: {target_ids}")

        if target_ids:
             # Delete dependent tables
             logger.debug("Deleting ChangeEvents, ScanResults, ModuleStates, Targets...")
             session.exec(text("DELETE FROM changeevent WHERE scan_result_id IN (SELECT id FROM scanresult WHERE target_id IN :tids)"), {"tids": tuple(target_ids)})
             session.exec(text("DELETE FROM scanresult WHERE target_id IN :tids"), {"tids": tuple(target_ids)})
             session.exec(text("DELETE FROM modulestate WHERE target_id IN :tids"), {"tids": tuple(target_ids)})
             session.exec(text("DELETE FROM target WHERE id IN :tids"), {"tids": tuple(target_ids)})
        
        # Purge Users and Tenant
        if tenant_ids:
             if not exclude_system:
                 logger.debug("Deleting UserTenantLinks, Users...")
                 session.exec(text("DELETE FROM usertenantlink WHERE tenant_id IN :tids"), {"tids": tuple(tenant_ids)})
                 session.exec(text("DELETE FROM \"user\" WHERE tenant_id IN :tids"), {"tids": tuple(tenant_ids)})
             
             # Always delete/refresh Tenant? Or keeps it?
             # If we exclude system, we usually KEEP Tenants too, but Tenants are parent of Targets.
             # If we delete Tenant, we lose the link.
             # IF exclude_system is True, we SHOULD NOT delete the Tenant if it exists.
             # But if we don't delete it, `restore` might duplicate or fail PK?
             # `session.add` on existing PK -> Update or Error.
             # In standard restore, we usually Wipe.
             # Strategy: If exclude_system, DO NOT DELETE Tenant.
             if not exclude_system:
                  logger.debug("Deleting Tenants...")
                  session.exec(text("DELETE FROM tenant WHERE id IN :tids"), {"tids": tuple(tenant_ids)})
        
    else:
        # --- FULL WIPE STRATEGY ---
        logger.info("Performing FULL restore strategy.")
        
        if exclude_system:
             # If skipping system, we can't TRUNCATE everything.
             # We must delete ONLY data tables.
             logger.info("exclude_system=True: Deleting only data tables, preserving Users/Settings.")
             # Data tables: Target, ScanResult, ModuleState, ChangeEvent.
             # Tenant?
             # If we keep Users, we must keep Tenants they belong to.
             # So we only wipe Targets and below.
             
             session.exec(text("TRUNCATE TABLE changeevent, scanresult, modulestate, target RESTART IDENTITY CASCADE"))
             # Do NOT truncate Tenant, User, UserTenantLink, SystemConfig
        else:
             logger.info("Wiping ALL data (TRUNCATE).")
             tables_str = ", ".join(table_names)
             # Fix for User Table quotes
             safe_tables = []
             for t in table_names:
                 if t == "user":
                     safe_tables.append('"user"')
                 else:
                     safe_tables.append(t)
             tables_str = ", ".join(safe_tables)
             
             logger.debug(f"Truncating tables: {tables_str}")
             session.exec(text(f"TRUNCATE TABLE {tables_str} RESTART IDENTITY CASCADE"))
    
    session.commit()
    logger.debug("Purge/Truncate complete. Committing transaction.")
    
    # 2. Restore Files (Screenshots)
    logger.info("Restoring files (screenshots)...")
    if backup_type == "full":
        if os.path.exists(SCREENSHOT_DIR):
             # Only wipe screenshots if full restore?
             # Or if we are overwriting targets.
             # Safe to wipe/overwrite.
            logger.debug(f"Full backup: Removing existing screenshot directory {SCREENSHOT_DIR}")
            shutil.rmtree(SCREENSHOT_DIR)
        os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    
    # 3. Read Zip & Insert
    logger.info("Restoring database records...")
    with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
        # Restore Screenshots logic... (omitted for brevity, unchanged)
        count_files = 0
        for member in zf.namelist():
            if member.startswith("screenshots/"):
                rel_path = member[len("screenshots/"):]
                if not rel_path: continue
                target_path = os.path.join(SCREENSHOT_DIR, rel_path)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "wb") as f:
                    f.write(zf.read(member))
                count_files += 1
        logger.debug(f"Restored {count_files} screenshot files.")
        
        # --- LEGACY RECOVERY LOGIC ---
        if "data/tenant.json" not in zf.namelist() and "data/target.json" in zf.namelist():
             # ... (Keep existing legacy logic) ...
             # Code omitted for brevity in search/replace, ASSUMING tool keeps unchanged context.
             # WAIT, I am replacing a huge chunk. I must include the logic.
             logger.warning("Legacy backup detected: data/tenant.json missing. scanning targets...")
             try:
                 target_data = json.loads(zf.read("data/target.json"))
                 needed_tenant_ids = {item["tenant_id"] for item in target_data if "tenant_id" in item and item["tenant_id"]}
                 for tid in needed_tenant_ids:
                      existing = session.exec(select(Tenant).where(Tenant.id == tid)).first()
                      if not existing:
                          logger.info(f"Creating placeholder tenant for ID {tid}")
                          t = Tenant(id=tid, name=f"Restored_Tenant_{tid}_{int(datetime.utcnow().timestamp())}")
                          session.add(t)
                 session.commit()
             except Exception as e:
                 logger.error(f"Failed to recover missing tenants: {e}")

        # Restore Database
        for model in MODELS:
            table_name = model.__tablename__
            
            # EXCLUSION CHECK
            if exclude_system and table_name in SYSTEM_TABLES:
                logger.info(f"Skipping restore of system table: {table_name}")
                continue
            
            # If exclude_system is True, we also need to handle TENANT carefully.
            # If Tenant exists, we might get PK Error if we try to insert duplicate ID.
            # If table is Tenant and exclude_system is True:
            # We should perform upsert (merge) or skip if exists.
            
            filename = f"data/{table_name}.json"
            
            if filename in zf.namelist():
                logger.debug(f"Restoring table: {table_name}")
                json_data = json.loads(zf.read(filename))
                
                count_records = 0
                for item in json_data:
                    if exclude_system and table_name == "tenant":
                         # Check existance
                         tid = item.get("id")
                         if tid:
                             existing = session.exec(select(Tenant).where(Tenant.id == tid)).first()
                             if existing:
                                 # Skip overwriting existing Tenant
                                 logger.info(f"Skipping existing Tenant ID {tid}")
                                 continue
                             else:
                                 logger.info(f"Restoring new Tenant ID {tid}")
                    
                    # For other tables (Target, etc.), we already purged them, so safe to add.
                    # Or full wipe -> safe.
                    
                    db_obj = model.model_validate(item)
                    session.add(db_obj)
                    count_records += 1
                logger.debug(f"Restored {count_records} records for {table_name}")
                
                # Critical: Flush tenants immediately so FKs work for subsequent tables
                if table_name == "tenant":
                    session.flush()
                    
        session.commit()
        logger.info("Database restore flush complete.")
        
    # Reset Sequences
    logger.info("Resetting sequences...")
    for model in MODELS:
        table_name = model.__tablename__
        
        # Quote table name if needed (especially for "user")
        safe_table_name = f'"{table_name}"' if table_name == "user" else table_name
        
        if hasattr(model, "id"):
             try:
                 max_id = session.scalar(text(f"SELECT MAX(id) FROM {safe_table_name}"))  # nosec B608 - safe_table_name is derived from SQLModel.__tablename__ (compile-time constant), never user input
                 if max_id:
                     seq_name = f"{table_name}_id_seq" # Sequences usually don't need quotes if standard naming, but let's check.
                     # Postgres creates "user_id_seq". Unquoted sequence name is usually fine unless it matches keyword.
                     logger.debug(f"Resetting sequence {seq_name} to {max_id}")
                     session.exec(text("SELECT setval(:seq_name, :max_id, true)"), {"seq_name": seq_name, "max_id": max_id})
             except Exception as e:
                 # Ignore errors only for sequence reset, but rollback transaction to clear state
                 logger.warning(f"Failed to reset sequence for {table_name}: {e}")
                 session.rollback()
                 pass
                      
    session.commit()
    logger.info("Restore process completed successfully.")
