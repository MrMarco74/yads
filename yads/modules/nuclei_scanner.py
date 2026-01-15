
import logging
import subprocess
import shutil
import json
import os
from typing import Any, Dict, List
from yads.core.base import BaseScannerModule

class NucleiScanner(BaseScannerModule):
    """
    Active Vulnerability Scanner using Nuclei.
    Requires 'nuclei' binary to be installed.
    """
    @property
    def module_name(self) -> str:
        return "nuclei_scanner"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads-worker")

    def run_scan(self, target: str) -> Dict[str, Any]:
        results = {
            "findings": [],
            "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0},
            "raw_output": "",
            "error": None,
            "version": None
        }
        
        if not shutil.which("nuclei"):
            self.logger.error("Nuclei binary not found. Please install projectdiscovery/nuclei.")
            results["error"] = "Nuclei binary not found"
            return results

        self.logger.info(f"Starting Nuclei scan for {target}...")
        
        # Prepare target URL (ensure protocol)
        target_url = target
        if not target_url.startswith("http"):
             # We assume https preferred, but nuclei can handle hostnames too usually.
             # Better to give it the hostname and let it decide? Or probe?
             # If we give 'example.com', nuclei usually probes.
             pass
        
        # Command Structure
        # -json: JSON output line by line
        # -silent: No banner
        # -nc: No colors (easier to parse if strict)
        # -as: Automatic scan (optional, but good) -> Removed for predictability, sticking to default logic.
        cmd = ["nuclei", "-u", target_url, "-j", "-silent", "-nc"]
        
        # Flags for optimization?
        # Maybe limit rate?
        # cmd.extend(["-rate-limit", "150"]) 
        
        self.logger.info(f"Executing: {' '.join(cmd)}")
        
        try:
            # 20 minutes timeout - Nuclei can be long if many templates
            self.logger.info(f"Command started: {' '.join(cmd)}")
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate(timeout=1200) 
            self.logger.info(f"Command finished. Return code: {proc.returncode}") 
            
            results["raw_output"] = stdout # Save full JSON lines dump
            
            # Parse Findings
            for line in stdout.splitlines():
                if not line.strip(): continue
                try:
                    finding = json.loads(line)
                    
                    # Extract key info
                    info = finding.get("info", {})
                    severity = info.get("severity", "unknown").lower()
                    
                    # Update stats
                    if severity in results["stats"]:
                        results["stats"][severity] += 1
                    else:
                        results["stats"]["unknown"] += 1
                        
                    clean_finding = {
                        "template_id": finding.get("template-id"),
                        "name": info.get("name"),
                        "severity": severity,
                        "type": finding.get("type"),
                        "matched_at": finding.get("matched-at"),
                        "matcher_name": finding.get("matcher-name"),
                        "description": info.get("description"),
                        "curl_command": finding.get("curl-command")
                    }
                    results["findings"].append(clean_finding)
                    
                except json.JSONDecodeError:
                    pass
            
            # Sort findings by severity (Critical -> Low)
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
            results["findings"].sort(key=lambda x: severity_order.get(x["severity"], 99))
            
            self.logger.info(f"Nuclei Scan Completed. Stats: {results['stats']}")
            
            if proc.returncode != 0:
                self.logger.warning(f"Nuclei exited with code {proc.returncode}. Stderr: {stderr}")
                if not results["findings"]:
                     results["error"] = f"Nuclei Error: {stderr}"

        except subprocess.TimeoutExpired:
            proc.kill()
            results["error"] = "Scan timed out (20mins)"
            self.logger.error("Nuclei scan timed out.")
        except Exception as e:
            self.logger.error(f"Nuclei Execution Failed: {e}")
            results["error"] = str(e)
            
        return results
