"""
Storage Analytics Router

Provides disk usage monitoring across screenshot folders, logs, scan artifacts,
and database with cleanup recommendations and actions.
"""

import os
import shutil
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, Depends, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from sqlmodel import Session, select, func, text
from pydantic import BaseModel

from yads.database import get_session, engine
from yads.auth.deps import PlatformAdminChecker
from yads.models import User, ScanResult, Target, Tenant
from yads.config import settings
from fastapi.templating import Jinja2Templates

logger = logging.getLogger("yads.storage")

router = APIRouter(prefix="/storage", tags=["storage"])
templates = Jinja2Templates(directory="yads/api/templates")
templates.env.globals['settings'] = settings


def get_all_tenants():
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants


# =============================================================================
# Helper Functions
# =============================================================================

def format_bytes(size: int) -> str:
    """Format bytes into human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def get_folder_stats(path: str) -> Dict[str, Any]:
    """Get statistics for a folder including size, file count, and age info."""
    stats = {
        "path": path,
        "exists": False,
        "total_size": 0,
        "file_count": 0,
        "oldest_file": None,
        "newest_file": None,
        "files_older_than_30d": 0,
        "size_older_than_30d": 0,
        "files_older_than_90d": 0,
        "size_older_than_90d": 0,
    }

    if not os.path.exists(path):
        return stats

    stats["exists"] = True
    now = datetime.now()
    thirty_days_ago = now - timedelta(days=30)
    ninety_days_ago = now - timedelta(days=90)

    oldest_time = None
    newest_time = None

    try:
        for root, dirs, files in os.walk(path):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    file_stat = os.stat(filepath)
                    file_size = file_stat.st_size
                    file_mtime = datetime.fromtimestamp(file_stat.st_mtime)

                    stats["total_size"] += file_size
                    stats["file_count"] += 1

                    if oldest_time is None or file_mtime < oldest_time:
                        oldest_time = file_mtime
                    if newest_time is None or file_mtime > newest_time:
                        newest_time = file_mtime

                    if file_mtime < thirty_days_ago:
                        stats["files_older_than_30d"] += 1
                        stats["size_older_than_30d"] += file_size

                    if file_mtime < ninety_days_ago:
                        stats["files_older_than_90d"] += 1
                        stats["size_older_than_90d"] += file_size

                except (OSError, IOError):
                    continue

        stats["oldest_file"] = oldest_time.isoformat() if oldest_time else None
        stats["newest_file"] = newest_time.isoformat() if newest_time else None

    except Exception as e:
        logger.error(f"Error scanning folder {path}: {e}")

    return stats


def get_database_stats(session: Session) -> Dict[str, Any]:
    """Get database storage statistics."""
    stats = {
        "total_scan_results": 0,
        "scan_results_size_estimate": 0,
        "targets_count": 0,
        "tenants_count": 0,
        "oldest_scan": None,
        "scans_older_than_30d": 0,
        "scans_older_than_90d": 0,
    }

    try:
        # Count scan results
        stats["total_scan_results"] = session.exec(
            select(func.count(ScanResult.id))
        ).one()

        # Count targets
        stats["targets_count"] = session.exec(
            select(func.count(Target.id))
        ).one()

        # Count tenants
        stats["tenants_count"] = session.exec(
            select(func.count(Tenant.id))
        ).one()

        # Get oldest scan
        oldest = session.exec(
            select(ScanResult.scanned_at)
            .order_by(ScanResult.scanned_at.asc())
            .limit(1)
        ).first()
        if oldest:
            stats["oldest_scan"] = oldest.isoformat()

        # Count old scans
        thirty_days_ago = datetime.now() - timedelta(days=30)
        ninety_days_ago = datetime.now() - timedelta(days=90)

        stats["scans_older_than_30d"] = session.exec(
            select(func.count(ScanResult.id))
            .where(ScanResult.scanned_at < thirty_days_ago)
        ).one()

        stats["scans_older_than_90d"] = session.exec(
            select(func.count(ScanResult.id))
            .where(ScanResult.scanned_at < ninety_days_ago)
        ).one()

        # Estimate size (rough: count * avg row size)
        # This is a rough estimate; actual size depends on JSONB data
        avg_row_size = 5000  # 5KB average per scan result
        stats["scan_results_size_estimate"] = stats["total_scan_results"] * avg_row_size

        # Try to get actual table size if PostgreSQL
        try:
            result = session.exec(text(
                "SELECT pg_total_relation_size('scanresult') as size"
            )).first()
            if result:
                stats["scan_results_size_estimate"] = result[0]
        except Exception:
            pass  # Fall back to estimate

    except Exception as e:
        logger.error(f"Error getting database stats: {e}")

    return stats


def generate_cleanup_recommendations(
    folder_stats: Dict[str, Dict],
    db_stats: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Generate cleanup recommendations based on storage analysis."""
    recommendations = []

    # Screenshots older than 90 days
    screenshots = folder_stats.get("screenshots", {})
    if screenshots.get("files_older_than_90d", 0) > 0:
        size = screenshots.get("size_older_than_90d", 0)
        count = screenshots.get("files_older_than_90d", 0)
        recommendations.append({
            "id": "screenshots_90d",
            "category": "Screenshots",
            "severity": "medium" if size > 100 * 1024 * 1024 else "low",
            "title": f"Delete {count} screenshots older than 90 days",
            "description": f"These screenshots are over 90 days old and can likely be safely removed.",
            "space_reclaimable": size,
            "space_reclaimable_formatted": format_bytes(size),
            "action": "delete_old_screenshots",
            "params": {"days": 90}
        })

    # Screenshots older than 30 days (if significant)
    if screenshots.get("size_older_than_30d", 0) > 500 * 1024 * 1024:  # > 500MB
        size = screenshots.get("size_older_than_30d", 0)
        count = screenshots.get("files_older_than_30d", 0)
        recommendations.append({
            "id": "screenshots_30d",
            "category": "Screenshots",
            "severity": "low",
            "title": f"Consider deleting {count} screenshots older than 30 days",
            "description": f"You have significant screenshot storage from over 30 days ago.",
            "space_reclaimable": size,
            "space_reclaimable_formatted": format_bytes(size),
            "action": "delete_old_screenshots",
            "params": {"days": 30}
        })

    # Log files
    logs = folder_stats.get("logs", {})
    if logs.get("total_size", 0) > 100 * 1024 * 1024:  # > 100MB
        size = logs.get("total_size", 0)
        recommendations.append({
            "id": "logs_large",
            "category": "Logs",
            "severity": "medium",
            "title": "Log files exceed 100MB",
            "description": "Consider rotating or archiving old log files.",
            "space_reclaimable": size,
            "space_reclaimable_formatted": format_bytes(size),
            "action": "rotate_logs",
            "params": {}
        })

    # Old log files
    if logs.get("files_older_than_30d", 0) > 10:
        size = logs.get("size_older_than_30d", 0)
        count = logs.get("files_older_than_30d", 0)
        recommendations.append({
            "id": "logs_old",
            "category": "Logs",
            "severity": "low",
            "title": f"Delete {count} log files older than 30 days",
            "description": "Old log files can be safely removed to free up space.",
            "space_reclaimable": size,
            "space_reclaimable_formatted": format_bytes(size),
            "action": "delete_old_logs",
            "params": {"days": 30}
        })

    # Database scan results
    if db_stats.get("scans_older_than_90d", 0) > 1000:
        count = db_stats.get("scans_older_than_90d", 0)
        # Estimate ~5KB per scan result
        size_estimate = count * 5000
        recommendations.append({
            "id": "db_scans_90d",
            "category": "Database",
            "severity": "medium",
            "title": f"Archive {count} scan results older than 90 days",
            "description": "Consider exporting and removing old scan results to improve database performance.",
            "space_reclaimable": size_estimate,
            "space_reclaimable_formatted": format_bytes(size_estimate),
            "action": "archive_old_scans",
            "params": {"days": 90}
        })

    # Backup folder
    backups = folder_stats.get("backups", {})
    if backups.get("file_count", 0) > 5:
        old_count = backups.get("files_older_than_30d", 0)
        if old_count > 3:
            size = backups.get("size_older_than_30d", 0)
            recommendations.append({
                "id": "backups_old",
                "category": "Backups",
                "severity": "low",
                "title": f"Remove {old_count} old backup files",
                "description": "Keep only recent backups to save space.",
                "space_reclaimable": size,
                "space_reclaimable_formatted": format_bytes(size),
                "action": "delete_old_backups",
                "params": {"keep_count": 3}
            })

    return recommendations


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("/", response_class=HTMLResponse)
async def storage_analytics_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker())
):
    """Main storage analytics dashboard page."""
    # Define paths to monitor
    base_path = os.getenv("APP_PATH", "/app")

    paths = {
        "screenshots": os.path.join(settings.STATIC_DIR, "screenshots"),
        "logs": os.getenv("LOG_DIR", os.path.join(base_path, "logs")),
        "backups": os.path.join(base_path, "data", "backups"),
        "nuclei_templates": os.path.expanduser("~/nuclei-templates"),
    }

    # Get folder stats
    folder_stats = {}
    for name, path in paths.items():
        folder_stats[name] = get_folder_stats(path)

    # Get database stats
    db_stats = get_database_stats(session)

    # Generate recommendations
    recommendations = generate_cleanup_recommendations(folder_stats, db_stats)

    # Calculate totals
    total_file_storage = sum(s.get("total_size", 0) for s in folder_stats.values())
    total_files = sum(s.get("file_count", 0) for s in folder_stats.values())
    total_reclaimable = sum(r.get("space_reclaimable", 0) for r in recommendations)

    return templates.TemplateResponse("storage_analytics.html", {
        "request": request,
        "user": user,
        "folder_stats": folder_stats,
        "db_stats": db_stats,
        "recommendations": recommendations,
        "total_file_storage": total_file_storage,
        "total_file_storage_formatted": format_bytes(total_file_storage),
        "total_files": total_files,
        "total_reclaimable": total_reclaimable,
        "total_reclaimable_formatted": format_bytes(total_reclaimable),
        "format_bytes": format_bytes,
    })


@router.get("/api/stats")
async def get_storage_stats(
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker())
):
    """Get storage statistics as JSON."""
    base_path = os.getenv("APP_PATH", "/app")

    paths = {
        "screenshots": os.path.join(settings.STATIC_DIR, "screenshots"),
        "logs": os.getenv("LOG_DIR", os.path.join(base_path, "logs")),
        "backups": os.path.join(base_path, "data", "backups"),
        "nuclei_templates": os.path.expanduser("~/nuclei-templates"),
    }

    folder_stats = {name: get_folder_stats(path) for name, path in paths.items()}
    db_stats = get_database_stats(session)
    recommendations = generate_cleanup_recommendations(folder_stats, db_stats)

    return {
        "folder_stats": folder_stats,
        "db_stats": db_stats,
        "recommendations": recommendations
    }


class CleanupRequest(BaseModel):
    action: str
    params: Dict[str, Any] = {}
    confirm: bool = False


@router.post("/cleanup")
async def execute_cleanup(
    request: CleanupRequest,
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker())
):
    """Execute a cleanup action."""
    if not request.confirm:
        raise HTTPException(status_code=400, detail="Confirmation required")

    action = request.action
    params = request.params
    result = {"success": False, "message": "", "deleted_count": 0, "freed_space": 0}

    try:
        if action == "delete_old_screenshots":
            days = params.get("days", 90)
            result = _delete_old_files(
                os.path.join(settings.STATIC_DIR, "screenshots"),
                days
            )

        elif action == "delete_old_logs":
            days = params.get("days", 30)
            log_dir = os.getenv("LOG_DIR", "/app/logs")
            result = _delete_old_files(log_dir, days)

        elif action == "rotate_logs":
            log_dir = os.getenv("LOG_DIR", "/app/logs")
            result = _rotate_logs(log_dir)

        elif action == "delete_old_backups":
            keep_count = params.get("keep_count", 3)
            backup_dir = os.path.join(os.getenv("APP_PATH", "/app"), "data", "backups")
            result = _delete_old_backups(backup_dir, keep_count)

        elif action == "archive_old_scans":
            days = params.get("days", 90)
            result = _archive_old_scans(session, days)

        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {action}")

        logger.info(f"Cleanup action '{action}' executed by {user.username}: {result}")
        return result

    except Exception as e:
        logger.error(f"Cleanup action '{action}' failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _delete_old_files(folder_path: str, days: int) -> Dict[str, Any]:
    """Delete files older than specified days."""
    if not os.path.exists(folder_path):
        return {"success": True, "message": "Folder does not exist", "deleted_count": 0, "freed_space": 0}

    cutoff = datetime.now() - timedelta(days=days)
    deleted_count = 0
    freed_space = 0

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                file_stat = os.stat(filepath)
                file_mtime = datetime.fromtimestamp(file_stat.st_mtime)

                if file_mtime < cutoff:
                    file_size = file_stat.st_size
                    os.remove(filepath)
                    deleted_count += 1
                    freed_space += file_size
            except (OSError, IOError) as e:
                logger.warning(f"Could not delete {filepath}: {e}")

    return {
        "success": True,
        "message": f"Deleted {deleted_count} files older than {days} days",
        "deleted_count": deleted_count,
        "freed_space": freed_space,
        "freed_space_formatted": format_bytes(freed_space)
    }


def _rotate_logs(log_dir: str) -> Dict[str, Any]:
    """Compress and rotate log files."""
    import gzip

    if not os.path.exists(log_dir):
        return {"success": True, "message": "Log directory does not exist", "deleted_count": 0, "freed_space": 0}

    compressed_count = 0
    freed_space = 0

    for file in os.listdir(log_dir):
        if file.endswith('.log') and not file.endswith('.gz'):
            filepath = os.path.join(log_dir, file)
            try:
                file_stat = os.stat(filepath)
                if file_stat.st_size > 10 * 1024 * 1024:  # > 10MB
                    # Compress the file
                    with open(filepath, 'rb') as f_in:
                        with gzip.open(filepath + '.gz', 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)

                    original_size = file_stat.st_size
                    compressed_size = os.path.getsize(filepath + '.gz')
                    os.remove(filepath)

                    compressed_count += 1
                    freed_space += (original_size - compressed_size)
            except Exception as e:
                logger.warning(f"Could not rotate {filepath}: {e}")

    return {
        "success": True,
        "message": f"Compressed {compressed_count} log files",
        "deleted_count": compressed_count,
        "freed_space": freed_space,
        "freed_space_formatted": format_bytes(freed_space)
    }


def _delete_old_backups(backup_dir: str, keep_count: int) -> Dict[str, Any]:
    """Delete old backups, keeping only the most recent ones."""
    if not os.path.exists(backup_dir):
        return {"success": True, "message": "Backup directory does not exist", "deleted_count": 0, "freed_space": 0}

    # Get all backup files sorted by modification time
    backups = []
    for file in os.listdir(backup_dir):
        if file.endswith(('.zip', '.enc')):
            filepath = os.path.join(backup_dir, file)
            backups.append((filepath, os.path.getmtime(filepath), os.path.getsize(filepath)))

    # Sort by modification time, newest first
    backups.sort(key=lambda x: x[1], reverse=True)

    # Delete old backups
    deleted_count = 0
    freed_space = 0

    for filepath, mtime, size in backups[keep_count:]:
        try:
            os.remove(filepath)
            deleted_count += 1
            freed_space += size
        except Exception as e:
            logger.warning(f"Could not delete backup {filepath}: {e}")

    return {
        "success": True,
        "message": f"Deleted {deleted_count} old backups, kept {min(keep_count, len(backups))} most recent",
        "deleted_count": deleted_count,
        "freed_space": freed_space,
        "freed_space_formatted": format_bytes(freed_space)
    }


def _archive_old_scans(session: Session, days: int) -> Dict[str, Any]:
    """Delete scan results older than specified days."""
    cutoff = datetime.now() - timedelta(days=days)

    try:
        # Count before delete
        count = session.exec(
            select(func.count(ScanResult.id))
            .where(ScanResult.scanned_at < cutoff)
        ).one()

        if count == 0:
            return {"success": True, "message": "No old scans to delete", "deleted_count": 0, "freed_space": 0}

        # Delete old scans
        session.exec(
            text(f"DELETE FROM scanresult WHERE scanned_at < :cutoff"),
            {"cutoff": cutoff}
        )
        session.commit()

        # Estimate freed space (~5KB per scan)
        freed_space = count * 5000

        return {
            "success": True,
            "message": f"Deleted {count} scan results older than {days} days",
            "deleted_count": count,
            "freed_space": freed_space,
            "freed_space_formatted": format_bytes(freed_space)
        }

    except Exception as e:
        session.rollback()
        raise e


@router.get("/api/disk-usage")
async def get_disk_usage(user: User = Depends(PlatformAdminChecker())):
    """Get overall disk usage for the application volume."""
    try:
        app_path = os.getenv("APP_PATH", "/app")
        usage = shutil.disk_usage(app_path)

        return {
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent_used": round((usage.used / usage.total) * 100, 1),
            "total_formatted": format_bytes(usage.total),
            "used_formatted": format_bytes(usage.used),
            "free_formatted": format_bytes(usage.free),
        }
    except Exception as e:
        logger.error(f"Error getting disk usage: {e}")
        return {"error": str(e)}
