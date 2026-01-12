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
from yads.models import Target, ScanResult, ModuleState, SystemConfig, ChangeEvent

# List of models to backup/restore in order (parents first for restore, but usually we use generic approach)
# For specific table names, we rely on SQLModel
MODELS = [Target, ScanResult, ModuleState, SystemConfig, ChangeEvent]

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
            if tenant_ids and hasattr(model, "tenant_id"):
                 stmt = stmt.where(model.tenant_id.in_(tenant_ids))
            elif tenant_ids and table_name in ["scanresult", "modulestate", "changeevent"]:
                 # These relate to Target, which has tenant_id.
                 # Optimization: Join with Target?
                 # Or just filtering by target's tenant.
                 # For simplicity in this codebase, we join.
                 # Assuming all these link to Target via target_id
                 from yads.models import Target
                 stmt = stmt.join(Target).where(Target.tenant_id.in_(tenant_ids))
            elif tenant_ids:
                 # SystemConfig, User, etc.
                 # If config, we might include all or exclude?
                 # Strategy: If partial backup, exclude SystemConfig/User unless explicitly handled.
                 # Typically tenant backup = App Data (Targets & Results).
                 # We skip SystemConfig for tenant backups.
                 if table_name == "systemconfig":
                     continue
                 if table_name == "user":
                     # Users are cross-tenant usually, unless we filter by tenant_id (if User has it)
                     # User model HAS tenant_id.
                     if hasattr(model, "tenant_id"):
                         stmt = stmt.where(model.tenant_id.in_(tenant_ids))
            
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
    meta = {}
    
    # Pre-Check: Read Metadata
    with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
        if "metadata.json" in zf.namelist():
            try:
                meta = json.loads(zf.read("metadata.json"))
            except:
                pass
    
    backup_type = meta.get("type", "full")
    tenant_ids = meta.get("tenant_ids", [])
    
    # Force constraint checking deferred? NOT supported in simple SQLModel/SQLite (but we use Postgres).
    # Ideally we assume the user confirmed the action.
    
    table_names = [model.__tablename__ for model in MODELS]

    if backup_type == "partial" and tenant_ids:
        # --- PARTIAL RESTORE STRATEGY ---
        # 1. Purge Existing Data for these Tenants
        # We must delete children first, then parents.
        # Order: ChangeEvent, ScanResult, ModuleState -> Target -> Tenant? (No, Tenant stays)
        # ScanResult, ModuleState, ChangeEvent depend on Target.
        # Target depends on Tenant.
        # User depends on Tenant.
        
        # Safe Delete Order:
        # ChangeEvent -> Using Cascade from ScanResult usually?
        # Let's use manual deletion to be safe and explicit.
        
        # Get Targets for these tenants
        from yads.models import Target
        targets_to_purge = session.exec(select(Target.id).where(Target.tenant_id.in_(tenant_ids))).all()
        
        if targets_to_purge:
             session.exec(text(f"DELETE FROM changeevent WHERE scan_result_id IN (SELECT id FROM scanresult WHERE target_id IN ({','.join(map(str, targets_to_purge))}))"))
             session.exec(text(f"DELETE FROM scanresult WHERE target_id IN ({','.join(map(str, targets_to_purge))})"))
             session.exec(text(f"DELETE FROM modulestate WHERE target_id IN ({','.join(map(str, targets_to_purge))})"))
             session.exec(text(f"DELETE FROM target WHERE id IN ({','.join(map(str, targets_to_purge))})"))
        
        # Purge Users?
        # session.exec(text(f"DELETE FROM \"user\" WHERE tenant_id IN ({','.join(map(str, tenant_ids))})"))
        
    else:
        # --- FULL WIPE STRATEGY ---
        tables_str = ", ".join(table_names)
        # Fix for User Table quotes
        safe_tables = []
        for t in table_names:
            if t == "user":
                safe_tables.append('"user"')
            else:
                safe_tables.append(t)
        tables_str = ", ".join(safe_tables)
        
        session.exec(text(f"TRUNCATE TABLE {tables_str} RESTART IDENTITY CASCADE"))
    
    session.commit()
    
    # 2. Restore Files (Screenshots)
    # If partial, we just overwrite.
    # If full, we should probably wipe dir?
    if backup_type == "full":
        if os.path.exists(SCREENSHOT_DIR):
            shutil.rmtree(SCREENSHOT_DIR)
        os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    
    # 3. Read Zip & Insert
    with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
        # Restore Screenshots
        for member in zf.namelist():
            if member.startswith("screenshots/"):
                rel_path = member[len("screenshots/"):]
                if not rel_path: continue
                target_path = os.path.join(SCREENSHOT_DIR, rel_path)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "wb") as f:
                    f.write(zf.read(member))
                    
        # Restore Database
        for model in MODELS:
            table_name = model.__tablename__
            filename = f"data/{table_name}.json"
            
            if filename in zf.namelist():
                json_data = json.loads(zf.read(filename))
                
                for item in json_data:
                    # filtering needed?
                    # The backup already filtered the data. checking tenant_id here is duplicate but safe.
                    # Just add them.
                    
                    # Merge Strategy:
                    # If ID exists (from another tenant not wiped?), we have a collision.
                    # Since we use global auto-inc IDs, importing from another system might cause clashes.
                    # BUT: We purged the specific tenant data. 
                    # If this is "same system restore", IDs match holes.
                    # If this is "cross system import", we might need to NULL the IDs and let them regenerate?
                    # For now, we assume "Restore" means bringing back state, preserving IDs.
                    
                    # If full backup -> Table empty -> No clash.
                    # If partial -> We deleted these IDs -> No clash.
                    # Unless UUIDs or similar. We use Int.
                    
                    db_obj = model.model_validate(item)
                    session.add(db_obj)
                    
        session.commit()
        
    # Reset Sequences
    # Only needed if IDs were manually inserted (which they were)
    for model in MODELS:
        table_name = model.__tablename__
        if hasattr(model, "id"):
             max_id = session.exec(text(f"SELECT MAX(id) FROM {table_name}")).first()
             if max_id:
                 seq_name = f"{table_name}_id_seq"
                 try:
                    session.exec(text(f"SELECT setval('{seq_name}', {max_id}, true)"))
                 except Exception:
                     pass
                     
    session.commit()
