
import logging
import subprocess
import shutil
import socket
import requests
import defusedxml.ElementTree as ET
from typing import Any, Dict, List, Optional
import os
import tempfile
import urllib3
from yads.core.base import BaseScannerModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Curated fallback port list (used when nmap is not installed)
_FALLBACK_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}
_FALLBACK_WEB_PORTS = {80, 443, 8080, 8443, 9200}
_FALLBACK_BANNER_PORTS = {21, 22, 25}


class NmapScanner(BaseScannerModule):
    """
    Stealth Nmap Scanner.
    Executes Nmap with evasion flags (-sS, -T2, -D, etc.) to scan ports without triggering alarms.
    Falls back to socket-based scanning when the nmap binary is not installed.
    """
    @property
    def module_name(self) -> str:
        return "nmap_scanner"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads-worker")

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        results = {
            "open_ports": [],
            "method": "unknown",
            "is_active": False,
            "raw_output": "",
            "error": None
        }

        if not shutil.which("nmap"):
            self.logger.warning(
                "Nmap binary not found — falling back to socket-based scanning. "
                "Install nmap for stealth/evasion capabilities."
            )
            return self._socket_fallback_scan(target)

        self.logger.info(f"Starting stealth Nmap scan for {target}...")
        
        try:
            nmap_results = self._stealth_nmap_scan(target)
            results["open_ports"] = nmap_results["ports"]
            results["raw_output"] = nmap_results["raw"]
            results["method"] = "nmap_stealth"
            
            # Detect Resolution Failure or "No targets specified"
            raw_out = nmap_results.get("raw", "")
            if "Failed to resolve" in raw_out:
                results["error"] = "DNS Resolution Failed"
                self.logger.error(f"Nmap failed to resolve target: {target}")
            elif "WARNING: No targets were specified" in raw_out:
                results["error"] = "No targets specified (Check DNS/Connectivity)"
                self.logger.error(f"Nmap reported no targets for: {target}")
            elif not nmap_results.get("ports") and "Nmap done: 0 IP addresses" in raw_out:
                 # If no ports found but nmap finished, it's technically success, 
                 # but we want to be sure it wasn't a silent network failure.
                 results["is_active"] = False
            elif nmap_results["ports"]:
                results["is_active"] = True
                
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {e}")
            results["error"] = str(e)
            
        return results

    def _stealth_nmap_scan(self, target: str) -> Dict[str, Any]:
        """
        Executes Nmap with evasion flags.
        Flags:
        -sS: SYN Scan (Stealth) - requires root/capabilities.
        -T2: Polite timing
        --scan-delay 500ms
        -D RND:5: Random Decoys
        -n: No DNS
        --top-ports 1000
        --stats-every 5s: Progress reporting
        """
        
        # Check for root/capabilities
        is_root = os.geteuid() == 0
        
        # Create temp file for XML output
        fd, temp_xml = tempfile.mkstemp(suffix=".xml")
        os.close(fd) # Close file descriptor, we just need path
        
        try:
            # -oX output to temp file
            # stdout will be used for interactive status (if nmap sends it there with -v or if we just read it)
            # Actually --stats-every sent to stdout/stderr depending.
            cmd = ["nmap", "-n", "--top-ports", "1000", "-oX", temp_xml, "--stats-every", "5s"]
            
            if is_root:
                # Full Stealth Mode
                # Reduced delay from 500ms -> 200ms to allow completion within 1h for 1000 ports
                cmd.extend(["-sS", "-T2", "--scan-delay", "200ms", "-D", "RND:5"])
            else:
                # Unprivileged Mode (Connect Scan)
                cmd.extend(["-sT", "-T2", "--scan-delay", "200ms"])
                self.logger.warning("Running Nmap as non-root. Disabling SYN scan and Decoys.")

            cmd.append(target)
            
            self.logger.info(f"Executing: {' '.join(cmd)}")
            
            # Use Popen to stream output
            # Force English locale to ensure parsing works
            my_env = os.environ.copy()
            my_env["LC_ALL"] = "C"
            
            NMAP_TIMEOUT = 300  # 5 min hard cap per target — prevents blocking the full task slot

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                universal_newlines=True,
                env=my_env
            )

            try:
                stdout_data, _ = proc.communicate(timeout=NMAP_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_data, _ = proc.communicate()
                self.logger.warning(
                    f"[Nmap] Scan timed out after {NMAP_TIMEOUT}s for {target} — partial results returned"
                )
                stdout_data = (stdout_data or "") + f"\n[YADS] Nmap terminated after {NMAP_TIMEOUT}s timeout"

            raw_output_lines = []
            for line in stdout_data.splitlines():
                line = line.strip()
                if not line:
                    continue
                raw_output_lines.append(line)
                if ("About" in line and "% done" in line) or "Stats:" in line:
                    self.logger.info(f"[Nmap] {line}")
                elif "Scanning" in line or "Starting Nmap" in line:
                    self.logger.info(f"[Nmap] {line}")
            
            if proc.returncode != 0:
                raise Exception(f"Nmap exited with {proc.returncode}")
                
            # Parse XML Result from File
            ports = []
            raw_xml = ""
            try:
                with open(temp_xml, 'r', encoding='utf-8') as f:
                    raw_xml = f.read()
                    
                root = ET.fromstring(raw_xml)
                for host in root.findall("host"):
                    ports_elem = host.find("ports")
                    if ports_elem:
                        for port in ports_elem.findall("port"):
                            state_el = port.find("state")
                            if state_el is not None and state_el.get("state") == "open":
                                port_id = port.get("portid")
                                proto = port.get("protocol")
                                
                                service_el = port.find("service")
                                service_name = service_el.get("name") if service_el is not None else "unknown"
                                product = service_el.get("product", "") if service_el is not None else ""
                                version = service_el.get("version", "") if service_el is not None else ""
                                full_product = f"{product} {version}".strip()

                                ports.append({
                                    "port": int(port_id),
                                    "protocol": proto,
                                    "service": service_name,
                                    "product": full_product
                                })
            except ET.ParseError as e:
                self.logger.error(f"Failed to parse Nmap XML for {target}: {e}")
                # If XML is empty or invalid, it might be due to a crash or early exit
                if not raw_output_lines:
                     raw_output_lines.append(f"Error: XML Parse Error ({e}) - No stdout captured")
            except Exception as e:
                 self.logger.error(f"Error reading nmap results for {target}: {e}")
                 raw_output_lines.append(f"Error: {str(e)}")
            
            # Combine output safely
            final_raw = "\n".join(raw_output_lines)
            if raw_xml:
                 final_raw += "\n\n--- XML REPORT ---\n" + raw_xml

            return {"ports": ports, "raw": final_raw}
            
        finally:
            # Cleanup
            if os.path.exists(temp_xml):
                os.remove(temp_xml)

    # ------------------------------------------------------------------
    # Socket fallback — used when nmap binary is not installed
    # ------------------------------------------------------------------

    def _socket_fallback_scan(self, target: str) -> Dict[str, Any]:
        """
        Lightweight socket-based port scan used when nmap is not available.
        Scans a curated list of common ports. No stealth/evasion — plain TCP connect.
        """
        results: Dict[str, Any] = {
            "open_ports": [],
            "method": "socket_fallback",
            "is_active": False,
            "raw_output": "[YADS] nmap not installed — using socket fallback (limited, no stealth)",
            "error": None,
        }

        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            results["error"] = f"DNS resolution failed: {e}"
            return results

        timeout = 1.5
        open_lines: List[str] = []

        for port, service_name in _FALLBACK_PORTS.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    if sock.connect_ex((target_ip, port)) != 0:
                        continue
            except Exception:
                continue

            results["is_active"] = True
            port_info: Dict[str, Any] = {
                "port": port,
                "protocol": "tcp",
                "service": service_name,
                "product": "",
            }

            # Web probe
            if port in _FALLBACK_WEB_PORTS:
                proto = "https" if port in {443, 8443} else "http"
                try:
                    resp = requests.get(
                        f"{proto}://{target}:{port}",
                        timeout=3,
                        allow_redirects=False,
                        headers={"User-Agent": "YADS-Security-Scanner (+https://yads-security.com)"},
                        verify=False,  # nosec B501 — intentional: scanner probes unknown certs
                    )
                    server = resp.headers.get("Server", "")
                    if server:
                        port_info["product"] = server
                except Exception:
                    pass

            # Banner grab for protocol ports
            elif port in _FALLBACK_BANNER_PORTS:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        s.connect((target_ip, port))
                        banner = s.recv(256).decode("utf-8", errors="ignore").strip()
                        if banner:
                            port_info["product"] = banner[:120]
                except Exception:
                    pass

            results["open_ports"].append(port_info)
            open_lines.append(f"{port}/tcp  open  {service_name}")
            self.logger.info(f"[socket-fallback] open port: {port} ({service_name})")

        if open_lines:
            results["raw_output"] += "\n" + "\n".join(open_lines)

        return results
