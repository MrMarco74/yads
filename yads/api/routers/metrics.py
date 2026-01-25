"""
Prometheus Metrics Router

Provides /metrics endpoint for Prometheus scraping.
Supports three authentication modes:
- none: No authentication (for internal/trusted networks)
- token: Bearer token authentication (recommended for external access)
- user: User session authentication (reuses existing YADS auth)
"""

import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from yads.config import settings
from yads.core.metrics import get_metrics

logger = logging.getLogger("yads.api.metrics")

router = APIRouter(prefix="/metrics", tags=["metrics"])

# Optional bearer token security
bearer_security = HTTPBearer(auto_error=False)


def _get_token_from_db() -> Optional[str]:
    """Get metrics token from database (SystemConfig)."""
    try:
        from sqlmodel import Session
        from yads.database import engine
        from yads.models import SystemConfig

        with Session(engine) as session:
            config = session.get(SystemConfig, "METRICS_TOKEN")
            if config:
                return config.value
    except Exception as e:
        logger.debug(f"Could not load METRICS_TOKEN from DB: {e}")

    return None


def _verify_token(token: str) -> bool:
    """Verify the provided token against configured token."""
    # First check environment variable
    expected_token = settings.METRICS_TOKEN

    # Then check database
    if not expected_token:
        expected_token = _get_token_from_db()

    if not expected_token:
        logger.warning("METRICS_TOKEN not configured but token auth mode is enabled")
        return False

    return secrets.compare_digest(token, expected_token)


async def verify_metrics_access(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_security)
):
    """
    Verify access to metrics endpoint based on configured auth mode.

    Auth modes:
    - none: Allow all requests
    - token: Require valid bearer token
    - user: Require valid user session
    """
    if not settings.METRICS_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Metrics endpoint is disabled"
        )

    auth_mode = settings.METRICS_AUTH_MODE.lower()

    if auth_mode == "none":
        # No authentication required
        return True

    elif auth_mode == "token":
        # Bearer token authentication
        if not credentials:
            raise HTTPException(
                status_code=401,
                detail="Bearer token required",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if not _verify_token(credentials.credentials):
            raise HTTPException(
                status_code=403,
                detail="Invalid metrics token"
            )

        return True

    elif auth_mode == "user":
        # User session authentication
        try:
            from yads.auth.deps import get_current_active_user
            from yads.database import get_session

            # Get session from request state or create new
            session = next(get_session())
            try:
                user = await get_current_active_user(request, session)
                if user:
                    return True
            finally:
                session.close()

        except Exception as e:
            logger.debug(f"User auth failed for metrics: {e}")

        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    else:
        logger.warning(f"Unknown METRICS_AUTH_MODE: {auth_mode}")
        raise HTTPException(
            status_code=500,
            detail=f"Invalid metrics auth mode: {auth_mode}"
        )


@router.get(
    "",
    summary="Prometheus Metrics",
    description="Returns metrics in Prometheus exposition format",
    response_class=Response,
    responses={
        200: {
            "description": "Metrics in Prometheus text format",
            "content": {"text/plain": {}}
        },
        401: {"description": "Authentication required"},
        403: {"description": "Invalid token"},
        503: {"description": "Metrics disabled"}
    }
)
async def get_prometheus_metrics(
    _: bool = Depends(verify_metrics_access)
):
    """
    Prometheus metrics endpoint.

    Returns metrics in Prometheus exposition format for scraping.
    Authentication is controlled by METRICS_AUTH_MODE setting.

    Example scrape config:
    ```yaml
    scrape_configs:
      - job_name: 'yads'
        static_configs:
          - targets: ['yads-api:8000']
        metrics_path: /metrics
        # For token auth:
        authorization:
          type: Bearer
          credentials: your-token-here
    ```
    """
    metrics = get_metrics()

    content = metrics.generate_metrics()

    return Response(
        content=content,
        media_type=metrics.CONTENT_TYPE if hasattr(metrics, 'CONTENT_TYPE') else "text/plain; version=0.0.4; charset=utf-8"
    )


@router.get(
    "/health",
    summary="Metrics Health Check",
    description="Check if metrics collection is enabled and working"
)
async def metrics_health():
    """
    Health check for metrics subsystem.

    Returns the current status of the metrics collection system.
    """
    metrics = get_metrics()

    return {
        "enabled": metrics.enabled,
        "initialized": metrics._initialized,
        "auth_mode": settings.METRICS_AUTH_MODE,
        "include_tenant_labels": settings.METRICS_INCLUDE_TENANT_LABELS,
        "poll_interval_seconds": settings.METRICS_POLL_INTERVAL
    }
