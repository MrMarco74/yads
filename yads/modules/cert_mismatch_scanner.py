"""
Subdomain Certificate Mismatch Scanner (Task #35)
===================================================
Checks if the TLS certificate presented by a host matches the domain.
Detects: wrong CN/SAN, expired certs, self-signed certs, wrong issuer.
"""
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 8


class CertMismatchScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "cert_mismatch"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger.info(f"[CertMismatch] Checking {target}")
        result = self._check_cert(target)
        logger.info(f"[CertMismatch] Done for {target} — valid={result['valid']}")
        return result

    def _check_cert(self, domain: str) -> Dict[str, Any]:
        ctx = ssl.create_default_context()

        try:
            with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return self._analyze_cert(domain, cert, valid_chain=True)
        except ssl.CertificateError as e:
            # Certificate validation failed — try getting the cert anyway
            mismatched = self._get_cert_without_validation(domain)
            mismatched["valid"] = False
            mismatched["findings"].insert(0, {
                "issue": f"Certificate validation error: {str(e)[:200]}",
                "severity": "high",
            })
            return mismatched
        except ssl.SSLError as e:
            return {
                "valid": None,
                "domain": domain,
                "reachable": False,
                "error": str(e)[:200],
                "cert_info": {},
                "findings": [{"issue": f"TLS error: {str(e)[:200]}", "severity": "high"}],
            }
        except (OSError, ConnectionRefusedError, socket.timeout):
            return {
                "valid": None,
                "domain": domain,
                "reachable": False,
                "error": "Port 443 not reachable",
                "cert_info": {},
                "findings": [],
            }

    def _analyze_cert(self, domain: str, cert: Dict, valid_chain: bool) -> Dict:
        findings = []
        cert_info = {}

        # Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        cert_info["subject_cn"] = subject.get("commonName", "")
        cert_info["issuer"] = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "")

        # SANs
        sans = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                sans.append(san_value)
        cert_info["sans"] = sans

        # Expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                cert_info["expires"] = exp_dt.isoformat()
                days_left = (exp_dt - datetime.now(timezone.utc)).days
                cert_info["days_until_expiry"] = days_left
                if days_left < 0:
                    findings.append({"issue": f"Certificate expired {abs(days_left)} days ago", "severity": "critical"})
                elif days_left < 14:
                    findings.append({"issue": f"Certificate expires in {days_left} days", "severity": "high"})
                elif days_left < 30:
                    findings.append({"issue": f"Certificate expires in {days_left} days", "severity": "medium"})
            except Exception:
                pass

        # Domain match check
        if not self._domain_matches(domain, cert_info["subject_cn"], sans):
            findings.append({
                "issue": f"Certificate CN/SAN does not match domain '{domain}'. CN='{cert_info['subject_cn']}', SANs={sans[:5]}",
                "severity": "high",
            })

        # Self-signed check
        if cert_info["issuer"] == subject.get("organizationName", ""):
            findings.append({"issue": "Certificate appears to be self-signed", "severity": "medium"})

        return {
            "valid": valid_chain and len([f for f in findings if f["severity"] in ("high", "critical")]) == 0,
            "domain": domain,
            "reachable": True,
            "cert_info": cert_info,
            "findings": findings,
        }

    def _get_cert_without_validation(self, domain: str) -> Dict:
        """Get cert info even if chain is invalid."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    result = self._analyze_cert(domain, cert, valid_chain=False)
                    result["reachable"] = True
                    return result
        except Exception as e:
            return {
                "valid": False,
                "domain": domain,
                "reachable": False,
                "error": str(e)[:200],
                "cert_info": {},
                "findings": [],
            }

    @staticmethod
    def _domain_matches(domain: str, cn: str, sans: List[str]) -> bool:
        """Check if domain matches CN or SANs, including wildcard."""
        all_names = sans if sans else [cn]
        for name in all_names:
            if name.startswith("*."):
                # Wildcard: *.example.com matches sub.example.com
                wildcard_base = name[2:]  # example.com
                if domain == wildcard_base:
                    return True
                if domain.endswith("." + wildcard_base) and "." not in domain[: domain.index("." + wildcard_base)]:
                    return True
            elif name.lower() == domain.lower():
                return True
        return False
