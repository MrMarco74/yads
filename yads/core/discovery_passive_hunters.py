"""
Passive discovery hunters — safe, zero-impact techniques for finding related domains.

Each hunter returns a list of (domain, signal_name) tuples.
No active probing, no login attempts, no vulnerability scanning.
Only public APIs and passive DNS are queried.
"""

import base64
import json
import logging
import re
import struct
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple

logger = logging.getLogger("yads-discovery")

_UA = "YADS Discovery Scanner (passive recon; +https://yads-security.com)"
_DOMAIN_RE = re.compile(r"https?://([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)", re.I)
_VALID_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def _is_valid_domain(s: str) -> bool:
    return bool(_VALID_DOMAIN_RE.match(s)) and len(s) <= 253


def _http_get(url: str, timeout: int = 10, extra_headers: Optional[dict] = None) -> Optional[str]:
    try:
        headers = {"User-Agent": _UA}
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 — URL built from validated target domain, never user-supplied directly
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        logger.debug(f"[Hunter] GET {url}: {e}")
        return None


def _http_get_json(url: str, timeout: int = 10, extra_headers: Optional[dict] = None):
    raw = _http_get(url, timeout=timeout, extra_headers=extra_headers)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return None


# ── SPF Traversal ──────────────────────────────────────────────────────────────

def spf_traversal(domain: str, max_lookups: int = 10) -> List[Tuple[str, str]]:
    """
    Recursively follow SPF include:/redirect= chains.
    Returns (referenced_domain, 'spf_host') for every host authorised to send mail.
    Safe: DNS queries only.
    """
    try:
        import dns.resolver
    except ImportError:
        logger.warning("[Hunter SPF] dnspython not available")
        return []

    results: List[Tuple[str, str]] = []
    visited: set = set()
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.lifetime = 5

    def _parse(d: str):
        if d in visited or len(visited) >= max_lookups:
            return
        visited.add(d)
        try:
            for rdata in resolver.resolve(d, "TXT"):
                txt = str(rdata).strip('"')
                if not txt.startswith("v=spf1"):
                    continue
                for tok in txt.split():
                    tok = tok.lstrip("+-~?")
                    if tok.startswith("include:"):
                        inc = tok[8:]
                        if _is_valid_domain(inc):
                            results.append((inc, "spf_host"))
                            _parse(inc)
                    elif tok.startswith("redirect="):
                        red = tok[9:]
                        if _is_valid_domain(red):
                            results.append((red, "spf_host"))
                            _parse(red)
                    elif tok.startswith("a:") and _is_valid_domain(tok[2:]):
                        results.append((tok[2:], "spf_host"))
                    elif tok.startswith("mx:") and _is_valid_domain(tok[3:]):
                        results.append((tok[3:], "spf_host"))
        except Exception as e:
            logger.debug(f"[Hunter SPF] {d}: {e}")

    _parse(domain)
    return results


# ── Wayback Machine CDX API ────────────────────────────────────────────────────

def wayback_cdx(domain: str) -> List[Tuple[str, str]]:
    """
    Query Wayback Machine CDX API for all historically archived URLs.
    Extracts unique subdomains that were once reachable.
    Safe: read-only public API, no rate limit for reasonable queries.
    """
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{urllib.parse.quote(domain)}/*"
        "&output=json&fl=original&collapse=urlkey&limit=500&matchType=domain"
    )
    data = _http_get_json(url, timeout=25)
    if not data or not isinstance(data, list):
        return []

    results: List[Tuple[str, str]] = []
    seen: set = set()
    for row in data[1:]:  # row[0] is the header ["original"]
        try:
            original = row[0] if isinstance(row, list) else str(row)
            host = urllib.parse.urlparse(original).hostname or ""
            host = host.lower()
            if host and host != domain and host.endswith("." + domain) and host not in seen:
                seen.add(host)
                results.append((host, "wayback_subdomain"))
        except Exception:
            continue

    return results


# ── VirusTotal Passive DNS ─────────────────────────────────────────────────────

def virustotal_passive_dns(domain: str, api_key: str) -> List[Tuple[str, str]]:
    """
    Fetch historical subdomains from VirusTotal's passive DNS database.
    Safe: read-only API, uses tenant's existing VT key.
    """
    if not api_key:
        return []

    results: List[Tuple[str, str]] = []
    seen: set = set()
    cursor = None

    for _ in range(3):  # max 3 pages (40 × 3 = 120 results)
        url = (
            f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}/subdomains"
            f"?limit=40{('&cursor=' + urllib.parse.quote(cursor)) if cursor else ''}"
        )
        data = _http_get_json(url, timeout=15, extra_headers={"x-apikey": api_key})
        if not data or "data" not in data:
            break
        for item in data["data"]:
            sub = item.get("id", "").lower().strip()
            if sub and sub not in seen and _is_valid_domain(sub):
                seen.add(sub)
                results.append((sub, "vt_passive_dns"))

        cursor = data.get("meta", {}).get("cursor")
        if not cursor:
            break

    return results


# ── SRV Record Enumeration ─────────────────────────────────────────────────────

_SRV_RECORDS = [
    "_autodiscover._tcp", "_autoconfig._tcp",
    "_http._tcp", "_https._tcp",
    "_sip._tcp", "_sip._udp", "_sips._tcp",
    "_xmpp-server._tcp", "_xmpp-client._tcp",
    "_caldav._tcp", "_caldavs._tcp",
    "_carddav._tcp", "_carddavs._tcp",
    "_imap._tcp", "_imaps._tcp",
    "_pop3._tcp", "_pop3s._tcp",
    "_submission._tcp", "_smtps._tcp",
    "_ldap._tcp", "_kerberos._tcp",
    "_vpn._tcp", "_ipp._tcp", "_ipps._tcp",
    "_matrix._tcp", "_turn._tcp", "_stun._tcp",
]


def srv_enumeration(domain: str) -> List[Tuple[str, str]]:
    """
    Probe common SRV record prefixes and collect referenced hostnames.
    Reveals mail, VoIP, calendar, directory and other infrastructure.
    Safe: DNS queries only, no TCP connections opened.
    """
    try:
        import dns.resolver
    except ImportError:
        return []

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.lifetime = 3

    results: List[Tuple[str, str]] = []
    seen: set = set()

    for prefix in _SRV_RECORDS:
        fqdn = f"{prefix}.{domain}"
        try:
            for rdata in resolver.resolve(fqdn, "SRV"):
                target = str(rdata.target).rstrip(".").lower()
                if target and target != domain and target not in seen and _is_valid_domain(target):
                    seen.add(target)
                    results.append((target, "srv_record"))
        except Exception:
            pass

    return results


# ── CORS / CSP Header Mining ───────────────────────────────────────────────────

def cors_csp_headers(domain: str) -> List[Tuple[str, str]]:
    """
    Fetch the HTTP response headers of the root page and extract
    explicitly trusted origins from CORS and CSP headers.
    A domain listed in ACAO or CSP is guaranteed to be trusted by the
    target — strong signal for relatedness.
    Safe: single GET request, no auth, no crawling.
    """
    headers_dict: dict = {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=8) as resp:  # nosec B310 — scanner probes target domain over http/https
                headers_dict = dict(resp.headers)
                break
        except Exception:
            continue

    if not headers_dict:
        return []

    results: List[Tuple[str, str]] = []
    seen: set = set()

    def _extract(header_value: str, signal: str):
        for match in _DOMAIN_RE.finditer(header_value):
            host = match.group(1).lower()
            if host and host != domain and host not in seen and _is_valid_domain(host):
                seen.add(host)
                results.append((host, signal))

    _extract(headers_dict.get("Access-Control-Allow-Origin", ""), "cors_trusted_origin")
    _extract(headers_dict.get("Content-Security-Policy", ""), "cors_trusted_origin")
    _extract(headers_dict.get("Content-Security-Policy-Report-Only", ""), "cors_trusted_origin")
    _extract(headers_dict.get("Link", ""), "sitemap_reference")

    return results


# ── Robots.txt + Sitemap Domain Extraction ─────────────────────────────────────

def robots_sitemap(domain: str) -> List[Tuple[str, str]]:
    """
    Parse /robots.txt for Sitemap directives, then traverse linked sitemaps.
    Extracts external domain references — often reveals CDNs, shops, or related portals.
    Safe: standard public GET requests, max 5 sitemaps.
    """
    results: List[Tuple[str, str]] = []
    seen: set = set()
    sitemap_urls: List[str] = []

    # Fetch robots.txt
    robots = (
        _http_get(f"https://{domain}/robots.txt", timeout=8) or
        _http_get(f"http://{domain}/robots.txt", timeout=8)
    )
    if robots:
        for line in robots.splitlines():
            if line.lower().startswith("sitemap:"):
                su = line.split(":", 1)[1].strip()
                if su:
                    sitemap_urls.append(su)

    # Common sitemap paths as fallback
    for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"):
        sitemap_urls.append(f"https://{domain}{path}")

    # Process sitemaps (limit to 5 to avoid infinite traversal)
    for smap_url in sitemap_urls[:5]:
        content = _http_get(smap_url, timeout=10)
        if not content:
            continue
        for match in _DOMAIN_RE.finditer(content):
            host = match.group(1).lower()
            if host and host != domain and host not in seen and _is_valid_domain(host):
                seen.add(host)
                results.append((host, "sitemap_reference"))

    return results


# ── Favicon Hash → Shodan ─────────────────────────────────────────────────────

def _murmur3_32(data: bytes) -> int:
    """MurmurHash3 32-bit — matches Shodan's favicon fingerprint format."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h1 = 0
    length = len(data)
    rounded = length & 0xFFFFFFFC

    for i in range(0, rounded, 4):
        k1 = struct.unpack_from("<I", data, i)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    remainder = length & 3
    k1 = 0
    if remainder >= 3:
        k1 ^= data[rounded + 2] << 16
    if remainder >= 2:
        k1 ^= data[rounded + 1] << 8
    if remainder >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Return as signed 32-bit (Shodan format)
    return struct.unpack("<i", struct.pack("<I", h1))[0]


def favicon_shodan(domain: str, api_key: str) -> List[Tuple[str, str]]:
    """
    1. Download the site's favicon.
    2. Compute its MurmurHash3 (Shodan's favicon fingerprint).
    3. Search Shodan for all other hosts with the same favicon.
    Reveals staging servers, admin panels, and related services using the
    same codebase — even when they have no DNS relation to the seed domain.
    Safe: read-only Shodan API, no active probing of discovered hosts.
    """
    if not api_key:
        return []

    # Fetch favicon
    favicon_data: Optional[bytes] = None
    for path in ("/favicon.ico", "/favicon.png", "/static/favicon.ico", "/assets/favicon.ico"):
        try:
            req = urllib.request.Request(f"https://{domain}{path}", headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=8) as r:  # nosec B310 — scanner fetches favicon from target domain
                raw = r.read()
                if len(raw) > 64:  # discard empty/error responses
                    favicon_data = raw
                    break
        except Exception:
            continue

    if not favicon_data:
        return []

    # Shodan expects base64 with newlines (encodebytes), then hashes that string
    b64_bytes = base64.encodebytes(favicon_data)
    fhash = _murmur3_32(b64_bytes)
    logger.info(f"[Hunter Favicon] {domain}: favicon_hash={fhash}")

    results: List[Tuple[str, str]] = []
    seen: set = set()

    try:
        url = (
            f"https://api.shodan.io/shodan/host/search"
            f"?key={urllib.parse.quote(api_key)}"
            f"&query={urllib.parse.quote(f'http.favicon.hash:{fhash}')}"
        )
        data = _http_get_json(url, timeout=20)
        if data and "matches" in data:
            for match in data["matches"]:
                for hostname in match.get("hostnames", []):
                    h = hostname.lower().strip()
                    if h and h != domain and h not in seen and _is_valid_domain(h):
                        seen.add(h)
                        results.append((h, "favicon_match"))
    except Exception as e:
        logger.debug(f"[Hunter Favicon Shodan] {domain}: {e}")

    return results


# ── Convenience: run all hunters ──────────────────────────────────────────────

def run_all_passive_hunters(
    domain: str,
    virustotal_api_key: str = "",
    shodan_api_key: str = "",
) -> List[Tuple[str, str]]:
    """
    Run every passive hunter for a given domain and return deduplicated results.
    API-key-dependent hunters are skipped when keys are absent.
    """
    all_results: List[Tuple[str, str]] = []
    seen: set = set()

    hunters = [
        ("SPF traversal",     lambda: spf_traversal(domain)),
        ("Wayback CDX",       lambda: wayback_cdx(domain)),
        ("SRV enumeration",   lambda: srv_enumeration(domain)),
        ("CORS/CSP headers",  lambda: cors_csp_headers(domain)),
        ("Robots/Sitemap",    lambda: robots_sitemap(domain)),
    ]
    if virustotal_api_key:
        hunters.append(("VirusTotal passive DNS", lambda: virustotal_passive_dns(domain, virustotal_api_key)))
    if shodan_api_key:
        hunters.append(("Favicon Shodan",  lambda: favicon_shodan(domain, shodan_api_key)))

    for name, fn in hunters:
        try:
            found = fn()
            for d, sig in found:
                d = d.lower().strip()
                key = (d, sig)
                if key not in seen:
                    seen.add(key)
                    all_results.append((d, sig))
            logger.info(f"[Hunter] {name}: {len(found)} candidates for {domain}")
        except Exception as e:
            logger.warning(f"[Hunter] {name} failed for {domain}: {e}")

    return all_results
