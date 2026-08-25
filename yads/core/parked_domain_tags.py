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

# Commercial-parking signatures all consolidate onto one provider-neutral
# "parked" tag. The tag names the *state* (a registered domain resolving to a
# monetization/for-sale landing page), not the vendor hosting it — provider
# attribution, when needed, lives in ScanResult.data.detection_method, not in
# the primary filter tag. This deliberately avoids the per-vendor tag sprawl
# (sedoparking / bodis-parked / godaddy-parked / ...) that made the targets
# table impossible to filter by "is this parked?".
PARKED_TAG_MAP: Dict[str, str] = {
    "sedo": "parked",
    "godaddy_parked": "parked",
    "bodis": "parked",
    "parkingcrew": "parked",
    "afternic": "parked",
    "dan_com": "parked",
    "hugedomains": "parked",
    "generic_for_sale": "parked",
    # Default hosting/server splash pages are catch-all, not commercially
    # "parked" — a live server showing a default page is a distinct signal,
    # so these keep their own tag rather than collapsing into "parked".
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


# NS-based detection (Layer 0) passes matched_signature as "ns:<provider>",
# e.g. "ns:sedoparking.com". DNS-delegated parking is the same state as HTTP-
# signature parking, so it consolidates onto the same "parked" tag. The map is
# kept (rather than deleted in favour of the fallback) so that recognising a
# known parking nameserver stays explicit and greppable, even though every
# entry currently resolves to "parked".
PARKED_NS_TAG_MAP: Dict[str, str] = {
    "sedoparking.com": "parked",
    "bodis.com": "parked",
    "parkingcrew.net": "parked",
    "afternic.com": "parked",
    "dan.com": "parked",
    "hugedomains.com": "parked",
    "cashparking.com": "parked",
    "domaincntrol.com": "parked",
}


def tag_parked_domain(session: Session, target_id: int, matched_signature: Optional[str]) -> None:
    """Append the tag mapped from matched_signature to the target, if not already present."""
    if matched_signature and matched_signature.startswith("ns:"):
        provider = matched_signature[3:]
        tag = PARKED_NS_TAG_MAP.get(provider, "parked")
    else:
        tag = PARKED_TAG_MAP.get(matched_signature, "parked")
    target = session.get(Target, target_id)
    if target and tag not in (target.tags or []):
        new_tags = list(target.tags or [])
        new_tags.append(tag)
        target.tags = new_tags
        session.add(target)
        session.commit()
