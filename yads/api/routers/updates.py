"""
One-Click Updates API Router

Provides endpoints for:
- Checking for updates
- Starting the update process
- Monitoring update progress
- Cancelling updates
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlmodel import Session

from yads.database import get_session
from yads.auth.deps import PlatformAdminChecker
from yads.models import User
from yads.core.updater import get_update_manager, UpdateStatus

import logging

logger = logging.getLogger("yads.api.updates")

router = APIRouter(prefix="/api/updates", tags=["Updates"])


@router.get("/status")
async def get_update_status(user: User = Depends(PlatformAdminChecker())):
    """
    Get the current update status.

    Returns the current state of the update process including:
    - Current version
    - Latest available version (if checked)
    - Update status (idle, checking, available, downloading, etc.)
    - Progress percentage
    - Any error messages
    """
    manager = get_update_manager()
    return JSONResponse(content=manager.get_state_dict())


@router.post("/check")
async def check_for_updates(
    force: bool = False,
    user: User = Depends(PlatformAdminChecker())
):
    """
    Check for available updates.

    Args:
        force: Force a fresh check (bypass cache).

    Returns:
        Update availability status and version info.
    """
    manager = get_update_manager()

    try:
        available, version_info = manager.check_for_updates(force_check=force)

        return JSONResponse(content={
            "available": available,
            "current_version": manager.state.current_version,
            "latest_version": manager.state.latest_version,
            "changelog": manager.state.changelog or [],
            "status": manager.state.status.value,
            "message": manager.state.message
        })

    except Exception as e:
        logger.error(f"Update check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/start")
async def start_update(
    channel: str = "stable",
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker())
):
    """
    Start the update process.

    This will:
    1. Pause the scan queue
    2. Wait for active tasks to complete
    3. Pull the latest Docker image
    4. Trigger a graceful restart

    The process runs asynchronously - use /status to monitor progress.

    Args:
        channel: Target channel ('stable' or 'beta'). Defaults to 'stable'.

    Returns:
        Initial update status.
    """
    manager = get_update_manager()

    # Validate channel
    if channel not in ["stable", "beta"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid channel. Must be 'stable' or 'beta'."
        )

    # Check if we're already updating
    if manager.state.status in [UpdateStatus.DOWNLOADING, UpdateStatus.PREPARING, UpdateStatus.RESTARTING]:
        raise HTTPException(
            status_code=409,
            detail=f"Update already in progress: {manager.state.status.value}"
        )

    # Check if update is available
    if manager.state.status not in [UpdateStatus.AVAILABLE, UpdateStatus.IDLE, UpdateStatus.FAILED, UpdateStatus.UP_TO_DATE]:
        # Run a check first
        available, _ = manager.check_for_updates()
        if not available:
            raise HTTPException(
                status_code=400,
                detail="No update available. Run /check first."
            )

    # Validate that the requested channel has an update
    if channel == "beta" and not manager.state.beta_available and not manager.state.beta_version:
        raise HTTPException(
            status_code=400,
            detail="No beta version available."
        )
    if channel == "stable" and not manager.state.stable_available and not manager.state.stable_version:
        raise HTTPException(
            status_code=400,
            detail="No stable version available."
        )

    # Determine target version for logging
    target_version = manager.state.beta_version if channel == "beta" else manager.state.stable_version

    # Start update in background (non-blocking for quick response)
    import threading

    def run_update():
        try:
            # Need a new session for the background thread
            from yads.database import engine
            from sqlmodel import Session as DBSession
            with DBSession(engine) as bg_session:
                manager.start_update(session=bg_session, target_channel=channel)
        except Exception as e:
            logger.error(f"Background update failed: {e}")

    update_thread = threading.Thread(target=run_update, daemon=True)
    update_thread.start()

    logger.info(f"Update process started by user: {user.username} (channel: {channel}, version: {target_version})")

    return JSONResponse(content={
        "message": f"Update to {channel} channel started",
        "status": UpdateStatus.PREPARING.value,
        "channel": channel,
        "target_version": target_version,
        "note": "Monitor progress at /api/updates/status"
    })


@router.post("/cancel")
async def cancel_update(
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker())
):
    """
    Cancel an in-progress update.

    Only works during the preparation or download phases.
    Cannot cancel once restart has begun.

    Returns:
        Cancellation status.
    """
    manager = get_update_manager()

    if manager.state.status == UpdateStatus.RESTARTING:
        raise HTTPException(
            status_code=400,
            detail="Cannot cancel update during restart phase"
        )

    if manager.cancel_update(session=session):
        logger.info(f"Update cancelled by user: {user.username}")
        return JSONResponse(content={
            "message": "Update cancelled",
            "status": manager.state.status.value
        })
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel update in state: {manager.state.status.value}"
        )


@router.get("/changelog")
async def get_changelog(user: User = Depends(PlatformAdminChecker())):
    """
    Get the changelog for the latest version.

    Returns:
        List of changes in the latest version.
    """
    manager = get_update_manager()

    # Check for updates to populate changelog if not already done
    if not manager.state.changelog:
        manager.check_for_updates()

    return JSONResponse(content={
        "current_version": manager.state.current_version,
        "latest_version": manager.state.latest_version,
        "changelog": manager.state.changelog or []
    })


@router.get("/version")
async def get_version():
    """
    Get the current YADS version.

    This endpoint is public (no auth required) for health checks.

    Returns:
        Current version string.
    """
    manager = get_update_manager()
    return JSONResponse(content={
        "version": manager.state.current_version,
        "status": "running"
    })
