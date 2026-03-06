import requests
import logging
import socket
from typing import Any, Dict, List, Optional
import urllib3
from yads.core.base import BaseScannerModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PortScanner(BaseScannerModule):
    """
    Enhanced Port Scanner.
    Scans for a curated list of interesting ports using standard socket connections.
    Performs specific HTTP probes on web ports to gather server information.
    """
    @property
    def module_name(self) -> str:
        return "port_scanner"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.port_scanner")
        
        # Curated list of ports to scan
        self.INTERESTING_PORTS = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            8000: "HTTP-Alt",
            8008: "HTTP-Alt",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            8888: "HTTP-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB"
        }
        
        # Ports that should trigger a full HTTP request probe
        self.WEB_PORTS = [80, 443, 8000, 8008, 8080, 8443, 8888, 9200]

    WEB_PROBE_PORTS = {80: "HTTP", 443: "HTTPS"}

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        if getattr(self, "quick_mode", False):
            return self._run_quick_web_probe(target)

        results = {
            "open_ports": [],
            "is_active": False,
            "scanned_ports": list(self.INTERESTING_PORTS.keys()),
        }

        self.logger.info(f"Starting Full Port Scan for {target}...")

        # Resolve target first to avoid repeated lookups
        try:
            target_ip = socket.gethostbyname(target)
            self.logger.debug(f"Resolved {target} to {target_ip}")
        except socket.gaierror:
            self.logger.warning(f"Could not resolve hostname: {target}")
            return results

        timeout = 1.5

        for port, service_label in self.INTERESTING_PORTS.items():
            is_open = False
            banner = None
            
            # 1. Socket Check
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target_ip, port))
                    if result == 0:
                        is_open = True
            except Exception as e:
                self.logger.debug(f"Socket error on port {port}: {e}")
                continue

            if is_open:
                results["is_active"] = True
                port_info = {
                    "port": port,
                    "service": service_label,
                    "banner": None
                }
                
                # 2. Web Probe (if applicable)
                if port in self.WEB_PORTS:
                    web_info = self._probe_web(target, port)
                    if web_info:
                        port_info["banner"] = web_info.get("server")  # Use Server header as banner
                        port_info["http_status"] = web_info.get("status")
                
                # 3. Simple Banner Grab for non-web (optional, simple read)
                elif port in [21, 22, 25]: # FTP, SSH, SMTP usually send banner on connect
                     try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(timeout)
                            s.connect((target_ip, port))
                            # Receive up to 1024 bytes
                            banner_bytes = s.recv(1024)
                            port_info["banner"] = banner_bytes.decode('utf-8', errors='ignore').replace('\x00', '').strip()
                     except Exception:
                         pass

                results["open_ports"].append(port_info)
                self.logger.info(f"Found open port: {port} ({service_label})")

        return results

    def _probe_web(self, target: str, port: int) -> Dict[str, Any]:
        """
        Probes a port with HTTP/HTTPS to check for web servers.
        """
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{target}:{port}"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; YADS/1.9; +http://yads.local)"
        }
        
        try:
            resp = requests.get(url, timeout=3, allow_redirects=False, headers=headers, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
            return {
                "status": resp.status_code,
                "server": resp.headers.get("Server")
            }
        except Exception:
            # Fallback: Try HTTPS on standard HTTP ports if HTTP fails (and vice versa?)
            # For now keep naive.
            return None

    def _run_quick_web_probe(self, target: str) -> Dict[str, Any]:
        """
        Lightweight probe: one HEAD request each to http:// and https://.
        No socket scanning, no banner grab. Only determines if a web server responds.
        """
        self.logger.info(f"Quick Web Probe for {target}...")
        results = {
            "open_ports": [],
            "is_active": False,
            "scanned_ports": [80, 443],
            "quick": True,
        }
        headers = {"User-Agent": "Mozilla/5.0 (compatible; YADS/1.9; +http://yads.local)"}
        for scheme, port in (("http", 80), ("https", 443)):
            try:
                resp = requests.head(
                    f"{scheme}://{target}",
                    timeout=3,
                    allow_redirects=False,
                    headers=headers,
                    verify=False,  # nosec B501
                )
                results["is_active"] = True
                results["open_ports"].append({
                    "port": port,
                    "service": scheme.upper(),
                    "http_status": resp.status_code,
                    "banner": resp.headers.get("Server"),
                })
                self.logger.info(f"Quick probe {scheme}://{target} → {resp.status_code}")
            except Exception as e:
                self.logger.debug(f"Quick probe {scheme}://{target} failed: {e}")
        return results
