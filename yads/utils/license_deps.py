from fastapi import HTTPException, Depends, status
from sqlmodel import Session, select
from yads.core.license import license_manager
from yads.database import get_session
from yads.models import SystemConfig

def require_feature(feature_name: str):
    def _check(session: Session = Depends(get_session)):
        lc = session.exec(select(SystemConfig).where(SystemConfig.key == "license_key")).first()
        if not lc or not lc.value:
             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="License Missing")
        
        if not license_manager.has_feature(lc.value, feature_name):
             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Feature '{feature_name}' not enabled in your license.")
    return _check
