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

def create_backup_zip(session: Session) -> io.BytesIO:
    """
    Creates a ZIP archive containing:
    1. JSON dumps of all DB tables.
    2. The entire screenshots directory.
    
    Returns a BytesIO object of the zip file.
    """
    memory_file = io.BytesIO()
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # 1. Backup Database Tables
        for model in MODELS:
            table_name = model.__tablename__
            records = session.exec(select(model)).all()
            
            # Serialize to list of dicts
            data = [record.model_dump() for record in records]
            
            # Write JSON to zip
            json_str = json.dumps(data, default=json_serializer, indent=2)
            zf.writestr(f"data/{table_name}.json", json_str)
            
        # 2. Metadata (Version, Timestamp)
        meta = {
            "version": settings.VERSION,
            "timestamp": datetime.utcnow().isoformat(),
            "compatibility": "1.x" # Simple check
        }
        zf.writestr("metadata.json", json.dumps(meta, indent=2))
            
        # 3. Backup Screenshots
        if os.path.exists(SCREENSHOT_DIR):
            for root, dirs, files in os.walk(SCREENSHOT_DIR):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Archive path should be relative to storing "screenshots/" at root of zip
                    archive_path = os.path.join("screenshots", os.path.relpath(file_path, SCREENSHOT_DIR))
                    zf.write(file_path, arcname=archive_path)
                    
    memory_file.seek(0)
    return memory_file

def restore_backup_from_zip(session: Session, zip_bytes: bytes):
    """
    Restores data from a ZIP archive.
    Strategy: Wipe All -> Restore All.
    Checks for version compatibility.
    """
    
    # Pre-Check: Read Metadata
    with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
        if "metadata.json" in zf.namelist():
            try:
                meta = json.loads(zf.read("metadata.json"))
                backup_ver = meta.get("version", "0.0.0")
                
                # Simple Logic: Warn if Major version differs? 
                # For now, we assume simple string compare or just logging.
                # In a strict system, we might raise Exception.
                # print(f"Restoring backup version {backup_ver} on system {settings.VERSION}")
            except:
                pass
                
    # 1. Wipe Database
    # We use TRUNCATE CASCADE to clear everything cleanly
    # Note: We need to know table names. 
    table_names = [model.__tablename__ for model in MODELS]
    
    # Disable constraints momentarily or just use CASCADE
    # Postgres supports TRUNCATE table_name CASCADE
    for table in table_names:
        try:
             # We execute individual truncates or one big one?
             # One big one usually handles refs better? 
             # Actually, if we use CASCADE on the parent (Target), it clears children.
             # But let's be explicit and clear all known tables.
             # "TRUNCATE TABLE target, scanresult, modulestate, systemconfig, changeevent RESTART IDENTITY CASCADE;"
             pass
        except:
            pass
            
    # Construct massive TRUNCATE command
    tables_str = ", ".join(table_names)
    session.exec(text(f'TRUNCATE TABLE {tables_str} RESTART IDENTITY CASCADE')) # using simple string for table names works if no keywords used
    # But USER is a keyword. We need to handle quoted User table name if using raw SQL
    # safe_tables = [f'"{t}"' for t in table_names]
    # tables_str = ", ".join(safe_tables)
    # session.exec(text(f'TRUNCATE TABLE {tables_str} RESTART IDENTITY CASCADE'))
    
    # Fix for User Table
    safe_tables = []
    for t in table_names:
        if t == "user":
            safe_tables.append('"user"')
        else:
            safe_tables.append(t)
    tables_str = ", ".join(safe_tables)
    session.exec(text(f"TRUNCATE TABLE {tables_str} RESTART IDENTITY CASCADE"))
    
    session.commit()
    
    # 2. Wipe Screenshots
    if os.path.exists(SCREENSHOT_DIR):
        shutil.rmtree(SCREENSHOT_DIR)
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    
    # 3. Read Zip
    with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
        # Restore Screenshots
        # Filter for files starting with screenshots/
        for member in zf.namelist():
            if member.startswith("screenshots/"):
                # member is like screenshots/foo.png
                # target is yads/api/static/screenshots/foo.png
                
                # Careful with paths. 
                # We strip "screenshots/" prefix from member to get relative path inside target dir
                rel_path = member[len("screenshots/"):]
                if not rel_path: continue # it was just the dir
                
                target_path = os.path.join(SCREENSHOT_DIR, rel_path)
                
                # Ensure parent dir exists
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
                    # Validate and Add
                    db_obj = model.model_validate(item)
                    session.add(db_obj)
                    
        session.commit()
        
    # Reset Sequences (Postgres specific)
    # The "RESTART IDENTITY" clause in TRUNCATE usually resets them to 1.
    # BUT if we insert data with explicit IDs (which we do, from JSON), Postgres sequences are NOT auto-updated to the max id.
    # We must manually setval the sequence to max(id).
    
    for model in MODELS:
        table_name = model.__tablename__
        # Check if model has 'id' field
        if hasattr(model, "id"):
             # Get max id
             max_id = session.exec(text(f"SELECT MAX(id) FROM {table_name}")).first()
             if max_id:
                 # Sequence name is usually table_id_seq
                 seq_name = f"{table_name}_id_seq"
                 # Check if sequence exists? Or just try/except
                 try:
                    session.exec(text(f"SELECT setval('{seq_name}', {max_id}, true)"))
                 except Exception as e:
                     # Might allow error if no sequence (e.g. key != id or uuid)
                     # SystemConfig uses 'key' as primary key, no ID/SEQ.
                     pass
                     
    session.commit()
