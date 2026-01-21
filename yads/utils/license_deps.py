from fastapi import Request, HTTPException, status, Depends
from yads.config import settings
from yads.core.license import license_manager
import logging

logger = logging.getLogger(__name__)

def require_feature(feature_name: str):
    """
    Dependency check for Licensed Features.
    - GET Requests (HTML): allowed even if unlicensed (sets ghost flag).
    - API/Data Requests: blocked (403) if unlicensed.
    """
    async def _check(request: Request):
        license_key = settings.LICENSE_KEY
        has_access = False
        
        if license_key:
            has_access = license_manager.has_feature(license_key, feature_name)
        
        # Attach license status to request state
        if not hasattr(request.state, "license_features"):
            request.state.license_features = {}
        request.state.license_features[feature_name] = has_access

        if has_access:
            return True

        # Soft Block Logic
        # If it's a GET request for a page (Accept: text/html), allow it (Ghost Mode)
        accept = request.headers.get("accept", "")
        if request.method == "GET" and "text/html" in accept:
            return False
            
        # Otherwise (POST, PUT, DELETE, or JSON fetch), strictly block
        logger.warning(f"Blocked access to unlicensed feature '{feature_name}' for {request.client.host}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Feature '{feature_name}' is not enabled in your license."
        )

    return _check
