"""
Wildcard-DNS detection shared by subdomain enumeration, auto-target creation
and inventory cleanup.

Parking providers and domain resellers (GoDaddy, Bodis/ParkingCrew, Sedo, ...)
answer *every* label under a parked zone. Any wordlist guess, CT/passive-DNS
name or recursively re-discovered subdomain then "resolves", so without a
reliable wildcard check each scan of such a zone adds hundreds of bogus
targets, which get scanned and add more. A name is treated as a wildcard
artifact when its answer is indistinguishable from what a random label under
its immediate parent zone returns (shared IP or same CNAME target).
"""

import concurrent.futures
import threading
import uuid
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import dns.resolver
import tldextract

# Random labels probed per zone. More than one, so a single timeout can no
# longer disable filtering for the whole zone.
WILDCARD_PROBES = 3
# Attempts per lookup before a name counts as unresolvable due to errors.
LOOKUP_RETRIES = 2


@dataclass(frozen=True)
class WildcardProfile:
    status: str  # "none" | "wildcard" | "unknown" (every probe errored)
    ips: frozenset = frozenset()
    cnames: frozenset = frozenset()

    @property
    def is_wildcard(self) -> bool:
        return self.status == "wildcard"


def lookup(resolver, name: str) -> Tuple[str, frozenset, str]:
    """Resolve A for *name*: ("ok", ips, cname) | ("nodata"|"nx"|"err", {}, "")."""
    for _ in range(LOOKUP_RETRIES):
        try:
            answer = resolver.resolve(name, "A")
        except dns.resolver.NXDOMAIN:
            return "nx", frozenset(), ""
        except dns.resolver.NoAnswer:
            return "nodata", frozenset(), ""
        except Exception:
            continue
        canonical = getattr(answer, "canonical_name", None)
        cname = canonical.to_text().rstrip(".").lower() if canonical is not None else ""
        return "ok", frozenset(str(r) for r in answer), (cname if cname != name.lower() else "")
    return "err", frozenset(), ""


def probe_wildcard(zone: str, resolver, probes: int = WILDCARD_PROBES) -> WildcardProfile:
    """Probe random labels under *zone* to learn its wildcard answer, if any."""
    ips, cnames, answered, errors = set(), set(), 0, 0
    for _ in range(probes):
        status, answer_ips, cname = lookup(resolver, f"{uuid.uuid4().hex[:12]}.{zone}")
        if status == "ok":
            answered += 1
            ips |= answer_ips
            if cname:
                cnames.add(cname)
        elif status == "err":
            errors += 1
    if answered:
        return WildcardProfile("wildcard", frozenset(ips), frozenset(cnames))
    if errors == probes:
        return WildcardProfile("unknown")
    return WildcardProfile("none")


def is_wildcard_answer(ips: Iterable[str], cname: str, profile: WildcardProfile) -> bool:
    """True if an answer is indistinguishable from the zone's wildcard answer."""
    if not profile.is_wildcard:
        return False
    if cname and cname in profile.cnames:
        return True
    return any(ip in profile.ips for ip in ips)


def parent_zone(domain: str) -> str:
    return domain.split(".", 1)[1] if "." in domain else ""


class WildcardCache:
    """Per-zone wildcard profiles, probed once and shared across threads."""

    def __init__(self, resolver):
        self.resolver = resolver
        self._profiles: Dict[str, WildcardProfile] = {}
        self._lock = threading.Lock()

    def profile(self, zone: str) -> WildcardProfile:
        with self._lock:
            cached = self._profiles.get(zone)
        if cached is not None:
            return cached
        profile = probe_wildcard(zone, self.resolver)
        with self._lock:
            return self._profiles.setdefault(zone, profile)

    def is_artifact(self, domain: str, ips: Optional[Iterable[str]] = None, cname: str = "") -> bool:
        """True if *domain* only exists because its parent zone is a wildcard.

        Pass *ips* (and *cname*) when the answer is already known; otherwise the
        name is resolved here. Unresolvable names are not artifacts.
        """
        zone = parent_zone(domain.lower())
        if not zone or zone == tldextract.extract(domain).suffix:
            return False
        if ips is None:
            status, ips, cname = lookup(self.resolver, domain)
            if status != "ok":
                return False
        return is_wildcard_answer(ips, cname, self.profile(zone))


def find_wildcard_artifacts(domains: Iterable[str], cache: WildcardCache, workers: int = 20) -> List[str]:
    """Subset of *domains* that are wildcard-DNS artifacts (resolved in parallel)."""
    domains = list(domains)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        flags = list(pool.map(cache.is_artifact, domains))
    return [d for d, artifact in zip(domains, flags) if artifact]
