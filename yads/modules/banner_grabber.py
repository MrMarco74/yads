"""
Service Fingerprinting & Banner Grabbing (#38)

Probes open ports via TCP connects, reads service banners, identifies
software versions, and flags dangerous service exposures.
"""
import logging
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from sqlmodel import select

from yads.core.base import BaseScannerModule

logger = logging.getLogger("yads-worker")

# Ports to always probe (common attack surface)
DEFAULT_PORTS = [
    21, 22, 23, 25, 80, 110, 143, 389, 443, 445,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
]

# Probes to send per port (port → bytes to send, or None to just read)
PORT_PROBES: Dict[int, Optional[bytes]] = {
    21:    None,          # FTP sends banner first
    22:    None,          # SSH sends banner first
    23:    None,          # Telnet sends banner first
    25:    None,          # SMTP sends greeting first
    80:    b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    110:   None,          # POP3 greeting
    143:   None,          # IMAP greeting
    389:   None,          # LDAP - try no probe
    443:   b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    3306:  None,          # MySQL handshake
    3389:  None,          # RDP
    5432:  None,          # PostgreSQL
    5900:  None,          # VNC
    6379:  b"PING\r\n",  # Redis
    8080:  b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    8443:  b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    8888:  b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    9200:  b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n",  # Elasticsearch
    27017: b"\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10serverStatus\x00\x01\x00\x00\x00\x00",
}

# Severity by service class
DANGEROUS_PORTS = {
    23:    ("telnet_exposed",    "high",     "Telnet service exposed — plaintext credentials", -20),
    5900:  ("vnc_exposed",      "high",     "VNC service exposed without known encryption", -15),
    3389:  ("rdp_exposed",      "medium",   "RDP exposed to internet — risk of brute-force", -10),
}

# Version regex patterns: (pattern, service_label)
VERSION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"SSH-[\d.]+-OpenSSH_([\d.]+)", re.I),  "OpenSSH"),
    (re.compile(r"SSH-[\d.]+-dropbear_([\d.]+)", re.I), "Dropbear SSH"),
    (re.compile(r"220[- ].*?(proftpd|vsftpd|filezilla|pure-ftpd)[^\r\n]*([\d.]+)", re.I), "FTP"),
    (re.compile(r"220[- ].*?esmtp (postfix|exim|sendmail|exchange)[^\r\n]*([\d.]+)?", re.I), "SMTP"),
    (re.compile(r"Server:\s*([\w./\- ]+)", re.I),           "HTTP Server"),
    (re.compile(r"X-Powered-By:\s*([\w./\- ]+)", re.I),     "HTTP X-Powered-By"),
    (re.compile(r"\+PONG", re.I),                           "Redis (no auth)"),
    (re.compile(r"NOAUTH|WRONGPASS", re.I),                 "Redis (auth required)"),
    (re.compile(r"MongoDB",  re.I),                         "MongoDB"),
    (re.compile(r"Elasticsearch", re.I),                    "Elasticsearch"),
    (re.compile(r"MySQL.*?(\d+\.\d+\.\d+)", re.I),          "MySQL"),
    (re.compile(r"PostgreSQL", re.I),                       "PostgreSQL"),
]

# Outdated version thresholds
OUTDATED_VERSIONS: Dict[str, Tuple[str, str, int]] = {
    # service_label: (min_safe_version, finding_id, score_penalty)
    "OpenSSH":   ("8.0", "outdated_openssh",   -8),
    "MySQL":     ("8.0", "outdated_mysql",      -8),
}


def _parse_version(version_str: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", version_str)
    return tuple(int(p) for p in parts[:3])


def _grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Connect to port and return up to 1024 bytes as string, or None on failure."""
    probe = PORT_PROBES.get(port)
    if isinstance(probe, bytes) and b"%s" in probe:
        probe = probe.replace(b"%s", host.encode("idna", errors="ignore"))

    use_tls = port in (443, 8443)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        if probe:
            sock.sendall(probe)

        banner = sock.recv(1024)
        sock.close()
        return banner.decode("utf-8", errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


def _analyze_banner(port: int, banner: str) -> Dict[str, Any]:
    """Extract service info and findings from a banner."""
    info = {"port": port, "banner": banner[:300], "service": None, "version": None, "findings": []}

    # Check dangerous port exposures first
    if port in DANGEROUS_PORTS:
        finding_id, sev, title, penalty = DANGEROUS_PORTS[port]
        info["findings"].append({
            "id": finding_id,
            "title": title,
            "severity": sev,
            "score_penalty": penalty,
            "detail": f"Port {port} open: {banner[:80]}",
        })

    # Redis unauthenticated check
    if port == 6379 and "+PONG" in banner:
        info["service"] = "Redis"
        info["findings"].append({
            "id": "unauth_redis",
            "title": "Redis accessible without authentication",
            "severity": "critical",
            "score_penalty": -30,
            "detail": "Redis responded to PING without authentication",
        })
    elif port == 6379 and "NOAUTH" in banner:
        info["service"] = "Redis (auth required)"

    # Elasticsearch unauthenticated
    if port == 9200 and "Elasticsearch" in banner and '"version"' in banner:
        info["service"] = "Elasticsearch"
        info["findings"].append({
            "id": "unauth_elasticsearch",
            "title": "Elasticsearch accessible without authentication",
            "severity": "high",
            "score_penalty": -20,
            "detail": "Elasticsearch cluster info exposed over HTTP",
        })

    # MongoDB unauthenticated (simple heuristic: connected and got a response)
    if port == 27017 and banner:
        info["service"] = "MongoDB"
        info["findings"].append({
            "id": "unauth_mongodb",
            "title": "MongoDB may be accessible without authentication",
            "severity": "high",
            "score_penalty": -20,
            "detail": "MongoDB port responded — verify authentication is enforced",
        })

    # FTP anonymous
    if port == 21 and banner and "230" in banner:
        info["findings"].append({
            "id": "ftp_anonymous",
            "title": "FTP anonymous login may be allowed",
            "severity": "medium",
            "score_penalty": -10,
            "detail": f"FTP responded with code 230 (login OK): {banner[:80]}",
        })

    # Version pattern matching
    for pattern, label in VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            if not info["service"]:
                info["service"] = label
            version_str = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
            if version_str and not info["version"]:
                info["version"] = version_str

            # Always flag version disclosure as info
            if version_str and label not in ("Redis (no auth)", "Redis (auth required)"):
                info["findings"].append({
                    "id": f"version_disclosure_{port}",
                    "title": f"Version disclosure on port {port}: {label} {version_str}",
                    "severity": "info",
                    "score_penalty": 0,
                    "detail": f"Service banner reveals: {label} {version_str}",
                })

            # Check for outdated version
            if label in OUTDATED_VERSIONS and version_str:
                min_ver, finding_id, penalty = OUTDATED_VERSIONS[label]
                current = _parse_version(version_str)
                min_safe = _parse_version(min_ver)
                if current and current < min_safe:
                    info["findings"].append({
                        "id": finding_id,
                        "title": f"Outdated {label} {version_str} (< {min_ver})",
                        "severity": "medium",
                        "score_penalty": penalty,
                        "detail": f"Upgrade {label} from {version_str} to at least {min_ver}",
                    })
            break  # First matching pattern wins for service identification

    return info


class BannerGrabber(BaseScannerModule):
    """
    Probes common ports, grabs service banners, identifies versions.
    Reads latest nmap result to focus on known-open ports.
    """

    @property
    def module_name(self) -> str:
        return "banner_grabber"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        from yads.models import ScanResult

        # Determine ports to probe: nmap results + defaults
        ports_to_probe = set(DEFAULT_PORTS)
        if target_id and self.db:
            try:
                latest_nmap = (
                    self.db.query(ScanResult)
                    .filter(ScanResult.target_id == target_id, ScanResult.module_name == "nmap_scanner")
                    .order_by(ScanResult.scanned_at.desc())
                    .first()
                )
                if latest_nmap and latest_nmap.data:
                    for p in latest_nmap.data.get("open_ports", []):
                        # nmap stores {port: int, ...} or just port numbers
                        if isinstance(p, dict):
                            ports_to_probe.add(p.get("port", 0))
                        elif isinstance(p, int):
                            ports_to_probe.add(p)
            except Exception:
                pass

        # Filter to reasonable range
        ports_to_probe = {p for p in ports_to_probe if 1 <= p <= 65535}

        logger.info(f"[BannerGrabber] Probing {len(ports_to_probe)} ports on {target}")

        # Parallel banner grabbing (max 10 concurrent, 3s timeout each)
        open_services = []
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(_grab_banner, target, port): port for port in sorted(ports_to_probe)}
            for future in as_completed(futures):
                port = futures[future]
                banner = future.result()
                if banner:
                    service_info = _analyze_banner(port, banner)
                    open_services.append(service_info)

        # Sort by port
        open_services.sort(key=lambda x: x["port"])

        # Collect all findings, deduplicate by id
        all_findings = []
        seen_ids = set()
        for svc in open_services:
            for f in svc.get("findings", []):
                key = f["id"]
                if key not in seen_ids:
                    seen_ids.add(key)
                    all_findings.append(f)

        # Calculate score
        score = 100
        for f in all_findings:
            score += f.get("score_penalty", 0)
        score = max(0, min(100, score))

        # Severity summary
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        return {
            "services": open_services,
            "findings": all_findings,
            "summary": {
                "open_services": len(open_services),
                "findings_count": len(all_findings),
                "score": score,
                **sev_counts,
            },
        }
