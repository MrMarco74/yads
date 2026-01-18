
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

        # ----------------------------------------------------
        # Get Tenant Context for Nuclei Pro Key
        # ----------------------------------------------------
        from yads.models import Target, Tenant
        from sqlmodel import select
        
        nuclei_key = None
        # We need to find the tenant for this target.
        # Assumption: 'target' argument is just a string URL/Domain.
        # In a real worker, we might have the target_id passed or we can query by domain.
        
        if self.db:
             # Try to find target by domain (exact match logic for now)
             # Strip protocol for domain matching if needed, but Target.domain is usually just domain
             domain_part = target.replace("https://", "").replace("http://", "").split("/")[0]
             
             # Try exact match first
             db_target = self.db.exec(select(Target).where(Target.domain == domain_part)).first()
             if not db_target:
                 # Try finding by looking if target contains domain? 
                 # For now, simplistic lookup. A better way would be passing target_id to run_scan, 
                 # but BaseScannerModule interface uses string.
                 pass
             
             if db_target and db_target.tenant_id:
                 tenant = self.db.get(Tenant, db_target.tenant_id)
                 if tenant and tenant.nuclei_api_key:
                     nuclei_key = tenant.nuclei_api_key
                     self.logger.info(f"Using Nuclei Pro API Key for Tenant: {tenant.name}")

        self.logger.info(f"Starting Nuclei scan for {target}...")
        
        # Prepare target URL (ensure protocol)
        target_url = target
        if not target_url.startswith("http"):
             pass
        
        # Command Structure
        # -json: JSON output line by line
        # -silent: No banner
        # -nc: No colors (easier to parse if strict)
        cmd = ["nuclei", "-u", target_url, "-j", "-silent", "-nc"]
        
        # Inject Key if present
        env_vars = os.environ.copy()
        if nuclei_key:
            # Option 1: Env Var (Preferred)
            env_vars["PDCP_API_KEY"] = nuclei_key
            # Option 2: CLI Flag (less secure in process list)
            # cmd.extend(["-auth-key", nuclei_key]) 
        
        self.logger.info(f"Executing: {' '.join(cmd)}")
        
        try:
            # 20 minutes timeout - Nuclei can be long if many templates
            self.logger.info(f"Command started: {' '.join(cmd)}")
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env_vars)
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
