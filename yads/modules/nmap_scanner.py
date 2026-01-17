
import logging
import subprocess
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
import os
from yads.core.base import BaseScannerModule

class NmapScanner(BaseScannerModule):
    """
    Stealth Nmap Scanner.
    Executes Nmap with evasion flags (-sS, -T2, -D, etc.) to scan ports without triggering alarms.
    """
    @property
    def module_name(self) -> str:
        return "nmap_scanner"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads-worker")

    def run_scan(self, target: str) -> Dict[str, Any]:
        results = {
            "open_ports": [],
            "method": "unknown",
            "is_active": False,
            "raw_output": "",
            "error": None
        }
        
        if not shutil.which("nmap"):
            self.logger.error("Nmap binary not found. Please install 'nmap'.")
            results["error"] = "Nmap binary not found"
            return results

        self.logger.info(f"Starting stealth Nmap scan for {target}...")
        
        try:
            nmap_results = self._stealth_nmap_scan(target)
            results["open_ports"] = nmap_results["ports"]
            results["raw_output"] = nmap_results["raw"]
            results["method"] = "nmap_stealth"
            
            # Detect Resolution Failure
            if "Failed to resolve" in nmap_results["raw"]:
                results["error"] = "DNS Resolution Failed"
                self.logger.error(f"Nmap failed to resolve target: {target}")
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
        """
        
        # Check for root/capabilities
        is_root = os.geteuid() == 0
        
        cmd = ["nmap", "-n", "--top-ports", "1000", "-oX", "-"]
        
        if is_root:
            # Full Stealth Mode
            cmd.extend(["-sS", "-T2", "--scan-delay", "500ms", "-D", "RND:5"])
        else:
            # Unprivileged Mode (Connect Scan)
            cmd.extend(["-sT", "-T2", "--scan-delay", "500ms"])
            self.logger.warning("Running Nmap as non-root. Disabling SYN scan and Decoys.")

        cmd.append(target)
        
        self.logger.info(f"Executing: {' '.join(cmd)}")
        
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(timeout=900) # 15 min timeout (T2 is slow)
        
        if proc.returncode != 0:
            raise Exception(f"Nmap exited with {proc.returncode}: {stderr}")
            
        # Parse XML
        ports = []
        try:
            root = ET.fromstring(stdout)
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
            self.logger.error(f"Failed to parse Nmap XML: {e}")
            # fall through to return raw
            
        return {"ports": ports, "raw": stdout}
