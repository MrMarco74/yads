"""
Shared SSRF validation for tenant/admin-supplied outbound URLs (integration
webhooks, SearXNG, etc.). Framework-agnostic (raises plain ValueError) so it
can be imported from both API routers (yads/api/routers/*.py) and scanner
modules (yads/modules/*.py) without an inverted dependency between the two
layers -- previously this lived only in yads/api/routers/integrations.py.
"""
from urllib.parse import urlparse

# Cloud metadata endpoints that must never be reachable via admin/tenant-supplied URLs
BLOCKED_INTEGRATION_HOSTS: frozenset = frozenset({
    "169.254.169.254",           # AWS / GCP / Azure instance metadata
    "metadata.google.internal",
    "169.254.170.2",             # AWS ECS task metadata
    "100.100.100.200",           # Alibaba Cloud metadata
})


def validate_integration_url(url: str, field: str = "URL") -> None:
    """Reject non-http(s) schemes and known cloud metadata hosts. Raises ValueError."""
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Integration {field} must use http or https scheme.")
    hostname = (parsed.hostname or "").lower()
    if hostname in BLOCKED_INTEGRATION_HOSTS:
        raise ValueError(f"Integration {field} hostname is not allowed: {hostname}")
