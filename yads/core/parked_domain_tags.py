"""
Maps catchall_detector's matched parking/placeholder signature ids to
filter-friendly Target tags, and applies them.

Reuses the existing Target.tags (JSONB) read-modify-write-commit pattern
already used by api/routers/tags.py's add_tag — duplicated here rather
than imported, since this runs from a Celery worker task (no FastAPI
Depends-injected session) and routers shouldn't be imported into worker
code.
"""

from typing import Dict, Optional

from sqlmodel import Session

from yads.models import Target

PARKED_TAG_MAP: Dict[str, str] = {
    "sedo": "sedoparking",
    "godaddy_parked": "godaddy-parked",
    "bodis": "bodis-parked",
    "parkingcrew": "parkingcrew-parked",
    "afternic": "afternic-parked",
    "dan_com": "dan-parked",
    "hugedomains": "hugedomains-parked",
    "generic_for_sale": "parked-for-sale",
    # Default hosting/server splash pages are catch-all, not commercially
    # "parked" — tagged generically rather than inventing a per-vendor tag
    # for every Apache/nginx/IIS default page.
    "apache_ubuntu_default": "placeholder-page",
    "apache_default": "placeholder-page",
    "nginx_default": "placeholder-page",
    "iis_default": "placeholder-page",
    "cpanel_default": "placeholder-page",
    "plesk_default": "placeholder-page",
    "generic_placeholder": "placeholder-page",
    "ionos_default": "placeholder-page",
    "strato_default": "placeholder-page",
    "hetzner_default": "placeholder-page",
}


def tag_parked_domain(session: Session, target_id: int, matched_signature: Optional[str]) -> None:
    """Append the tag mapped from matched_signature to the target, if not already present."""
    tag = PARKED_TAG_MAP.get(matched_signature, "parked")
    target = session.get(Target, target_id)
    if target and tag not in (target.tags or []):
        new_tags = list(target.tags or [])
        new_tags.append(tag)
        target.tags = new_tags
        session.add(target)
        session.commit()
