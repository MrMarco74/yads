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

logger = logging.getLogger(__name__)
from yads.models import Target, ScanResult, ModuleState, SystemConfig, ChangeEvent, Tenant, User, UserTenantLink

# List of models to backup/restore in order (parents first for restore)
MODELS = [Tenant, User, UserTenantLink, SystemConfig, Target, ScanResult, ModuleState, ChangeEvent]

SCREENSHOT_DIR = "yads/api/static/screenshots"

def json_serializer(obj):
    """Custom JSON serializer for datetime objects"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def create_backup_zip(session: Session, tenant_ids: List[int] = None) -> io.BytesIO:
    """
    Creates a ZIP archive containing:
    1. JSON dumps of all DB tables (optionally filtered by tenant).
    2. The entire screenshots directory.
    
    Returns a BytesIO object of the zip file.
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
                     # Target, User
                     stmt = stmt.where(model.tenant_id.in_(tenant_ids))
                     
                elif table_name == "usertenantlink":
                     stmt = stmt.where(model.tenant_id.in_(tenant_ids))

                elif table_name in ["scanresult", "modulestate"]:
                     # Direct link to Target
                     stmt = stmt.join(Target).where(Target.tenant_id.in_(tenant_ids))
                     
                elif table_name == "changeevent":
                     # Link via ScanResult -> Target
                     stmt = stmt.join(ScanResult).join(Target).where(Target.tenant_id.in_(tenant_ids))
                     
                elif table_name == "systemconfig":
                     # Skip SystemConfig for partial backups? 
                     # Or keep global config? Usually settings are global.
                     # User said "restore backup function restores settings". 
                     # If we are doing tenant backup, maybe we skip settings?
                     # But current code skipped it.
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
            "compatibility": "1.x",
            "tenant_ids": tenant_ids if tenant_ids else [],
            "type": "partial" if tenant_ids else "full"
        }
        zf.writestr("metadata.json", json.dumps(meta, indent=2))
            
        # 3. Backup Screenshots (Include all for simplicity, or filter?)
        # Filtering files is hard without DB check.
        # We include all for now, restore handles overwrite.
        if os.path.exists(SCREENSHOT_DIR):
            for root, dirs, files in os.walk(SCREENSHOT_DIR):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Archive path should be relative to storing "screenshots/" at root of zip
                    archive_path = os.path.join("screenshots", os.path.relpath(file_path, SCREENSHOT_DIR))
                    zf.write(file_path, arcname=archive_path)
                    
    memory_file.seek(0)
    return memory_file

def restore_backup_from_zip(session: Session, zip_bytes: bytes, target_tenant_ids: List[int] = None):
    """
    Restores data from a ZIP archive.
    Strategy: 
    - If Full Backup (no tenant_ids in meta): Wipe All -> Restore All.
    - If Tenant Backup: Purge specific Tenants -> Restore data.
    """
    logger.info("Starting backup restore process...")
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
    
    # Override logic: if we are forcing restore to specific tenants??
    # Current arg "target_tenant_ids" is unused logic-wise in original code, 
    # but likely intended to match or remap. WE USE METADATA logic for now.
    
    table_names = [model.__tablename__ for model in MODELS]

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
             session.exec(text(f"DELETE FROM changeevent WHERE scan_result_id IN (SELECT id FROM scanresult WHERE target_id IN ({target_ids_str}))"))
             session.exec(text(f"DELETE FROM scanresult WHERE target_id IN ({target_ids_str})"))
             session.exec(text(f"DELETE FROM modulestate WHERE target_id IN ({target_ids_str})"))
             session.exec(text(f"DELETE FROM target WHERE id IN ({target_ids_str})"))
        
        # Purge Users and Tenant
        tenant_ids_str = ",".join(map(str, tenant_ids))
        if tenant_ids_str:
             logger.debug("Deleting UserTenantLinks, Users, Tenants...")
             session.exec(text(f"DELETE FROM usertenantlink WHERE tenant_id IN ({tenant_ids_str})"))
             session.exec(text(f"DELETE FROM \"user\" WHERE tenant_id IN ({tenant_ids_str})"))
             session.exec(text(f"DELETE FROM tenant WHERE id IN ({tenant_ids_str})"))
        
    else:
        # --- FULL WIPE STRATEGY ---
        logger.info("Performing FULL restore strategy. Wiping all data.")
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
            logger.debug(f"Full backup: Removing existing screenshot directory {SCREENSHOT_DIR}")
            shutil.rmtree(SCREENSHOT_DIR)
        os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    
    # 3. Read Zip & Insert
    logger.info("Restoring database records...")
    with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
        # Restore Screenshots
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
        # If data/tenant.json is missing, but data/target.json exists, we must create placeholder tenants
        # to prevent FK violations.
        if "data/tenant.json" not in zf.namelist() and "data/target.json" in zf.namelist():
             logger.warning("Legacy backup detected: data/tenant.json missing. scanning targets for missing tenants...")
             try:
                 target_data = json.loads(zf.read("data/target.json"))
                 needed_tenant_ids = set()
                 for item in target_data:
                     if "tenant_id" in item and item["tenant_id"]:
                         needed_tenant_ids.add(item["tenant_id"])
                 
                 logger.info(f"Found {len(needed_tenant_ids)} implicit tenant IDs: {needed_tenant_ids}")
                 
                 # Create them if they don't exist in current session (which should be empty if full restore)
                 # If partial mode, we check DB.
                 
                 # For safety, just Upsert/Check each.
                 for tid in needed_tenant_ids:
                      # check if exists
                      existing = session.exec(select(Tenant).where(Tenant.id == tid)).first()
                      if not existing:
                          logger.info(f"Creating placeholder tenant for ID {tid}")
                          # Use a placeholder name that won't collide easily
                          t = Tenant(id=tid, name=f"Restored_Tenant_{tid}_{int(datetime.utcnow().timestamp())}")
                          session.add(t)
                 
                 session.commit() # Commit tenants so Targets can link
             except Exception as e:
                 logger.error(f"Failed to recover missing tenants: {e}")
                 # proceeding, might fail later
                     
        # Restore Database
        for model in MODELS:
            table_name = model.__tablename__
            filename = f"data/{table_name}.json"
            
            if filename in zf.namelist():
                logger.debug(f"Restoring table: {table_name}")
                json_data = json.loads(zf.read(filename))
                
                count_records = 0
                for item in json_data:
                    # filtering needed?
                    # The backup already filtered the data. checking tenant_id here is duplicate but safe.
                    # Just add them.
                    
                    db_obj = model.model_validate(item)
                    session.add(db_obj)
                    count_records += 1
                logger.debug(f"Restored {count_records} records for {table_name}")
                    
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
                 max_id = session.exec(text(f"SELECT MAX(id) FROM {safe_table_name}")).first()
                 if max_id:
                     seq_name = f"{table_name}_id_seq" # Sequences usually don't need quotes if standard naming, but let's check.
                     # Postgres creates "user_id_seq". Unquoted sequence name is usually fine unless it matches keyword.
                     logger.debug(f"Resetting sequence {seq_name} to {max_id}")
                     session.exec(text(f"SELECT setval('{seq_name}', {max_id}, true)"))
             except Exception as e:
                 # Ignore errors only for sequence reset, but rollback transaction to clear state
                 logger.warning(f"Failed to reset sequence for {table_name}: {e}")
                 session.rollback()
                 pass
                      
    session.commit()
    logger.info("Restore process completed successfully.")
