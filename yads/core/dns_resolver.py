"""Single place where yads builds dnspython resolvers.

In production YADS_DNS_SERVER points at yads-resolver (CoreDNS forwarding
over DNS-over-TLS), so scan lookups share a few TCP connections instead of
opening one UDP flow (= one router NAT entry) per query. Lookups that must
hit a specific server (authoritative NS, admin-configured custom DNS) pass
`nameservers` explicitly.

There is deliberately no fallback to the system resolver when the
configured server is down: that would silently re-flood the NAT table.
"""
import os
from typing import List, Optional

import dns.resolver

DNS_SERVER_ENV = "YADS_DNS_SERVER"


def _env_nameservers() -> List[str]:
    raw = os.environ.get(DNS_SERVER_ENV, "")
    return [s.strip() for s in raw.split(",") if s.strip()]


def make_resolver(
    *,
    timeout: float = 2.0,
    lifetime: float = 5.0,
    nameservers: Optional[List[str]] = None,
) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    chosen = nameservers or _env_nameservers()
    if chosen:
        resolver.nameservers = list(chosen)
    return resolver
