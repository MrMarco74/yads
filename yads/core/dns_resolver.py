"""Single place where yads builds dnspython resolvers.

In production YADS_DNS_SERVER points at yads-resolver (CoreDNS forwarding
over DNS-over-TLS), so scan lookups share a few TCP connections instead of
opening one UDP flow (= one router NAT entry) per query. Lookups that must
hit a specific server (authoritative NS, admin-configured custom DNS) pass
`nameservers` explicitly.

There is deliberately no fallback to the system resolver when the
configured server is down: that would silently re-flood the NAT table.
If YADS_DNS_SERVER is set but contains no valid nameserver, ValueError is raised.
"""
import os
from typing import List, Optional, Tuple

import dns.resolver

DNS_SERVER_ENV = "YADS_DNS_SERVER"


def _env_nameservers() -> Tuple[Optional[str], List[str]]:
    """Parse YADS_DNS_SERVER environment variable.

    Returns (raw_value, parsed_list) where:
    - raw_value is None if env var not set, otherwise the full string value
    - parsed_list is the list of nameservers (empty if env not set)
    """
    raw = os.environ.get(DNS_SERVER_ENV)
    if raw is None:
        return (None, [])
    parsed = [s.strip() for s in raw.split(",") if s.strip()]
    return (raw, parsed)


def make_resolver(
    *,
    timeout: float = 2.0,
    lifetime: float = 5.0,
    nameservers: Optional[List[str]] = None,
) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = lifetime

    # Determine which nameservers to use
    if nameservers:  # Non-empty explicit list
        chosen = nameservers
    else:
        # No explicit list, check environment
        raw, env_servers = _env_nameservers()
        if raw is not None and not env_servers:
            # Env var is set but contains no valid nameserver
            raise ValueError(
                f"YADS_DNS_SERVER is set but contains no nameserver (got '{raw}')"
            )
        chosen = env_servers

    if chosen:
        resolver.nameservers = list(chosen)
    return resolver
