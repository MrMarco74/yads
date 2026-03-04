"""
Compliance Framework Scorers

Multi-framework compliance scoring system supporting:
- SOC2 (Service Organization Control 2)
- GDPR (General Data Protection Regulation)
- PCI-DSS (Payment Card Industry Data Security Standard)
- HIPAA (Health Insurance Portability and Accountability Act)
- ISO 27001 (Information Security Management)

Each framework implements specific control mappings and scoring logic.
"""

from typing import List, Dict, Any, Tuple
from abc import ABC, abstractmethod


class BaseComplianceFramework(ABC):
    """Abstract base class for compliance framework scorers."""

    @property
    @abstractmethod
    def framework_id(self) -> str:
        """Unique identifier for the framework (e.g., 'soc2', 'gdpr')"""
        pass

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Human-readable name for the framework"""
        pass

    @property
    @abstractmethod
    def controls(self) -> List[Dict[str, Any]]:
        """
        List of control definitions.
        Each control dict contains:
        - id: Control identifier (e.g., 'CC6.1')
        - name: Control name
        - description: What the control checks
        - scanner_source: Which scanner module provides data
        - deduction: Points deducted if control fails
        - check_func: Name of the check method
        """
        pass

    def calculate_score(self, target_data: Dict[int, Dict], target_map: Dict[int, str]) -> Dict[str, Any]:
        """
        Calculate compliance score for the framework.

        Args:
            target_data: {target_id: {module_name: data}}
            target_map: {target_id: domain}

        Returns:
            {
                "score": int,
                "grade": str,
                "passing_controls": int,
                "failing_controls": int,
                "findings": List[Dict],
                "detailed_breakdown": Dict
            }
        """
        if not target_data:
            return {
                "score": 100,
                "grade": "A",
                "passing_controls": len(self.controls),
                "failing_controls": 0,
                "findings": [],
                "detailed_breakdown": {}
            }

        current_score = 100
        findings = []
        breakdown = {}
        passing = 0
        failing = 0

        for control in self.controls:
            check_method = getattr(self, control['check_func'], None)
            if not check_method:
                continue

            deduction, control_findings = check_method(target_data, target_map)

            status = "PASS" if deduction == 0 else "FAIL"
            if deduction == 0:
                passing += 1
            else:
                failing += 1
                current_score -= deduction

            # Add structured findings
            for finding in control_findings:
                findings.append({
                    "control_id": control['id'],
                    "control_name": control['name'],
                    "framework": self.framework_id,
                    "description": finding,
                    "severity": self._get_severity(deduction),
                    "deduction": deduction
                })

            breakdown[control['id']] = {
                "name": control['name'],
                "description": control['description'],
                "status": status,
                "deduction": deduction,
                "issues": control_findings
            }

        current_score = max(0, int(current_score))
        grade = self._get_grade(current_score)

        return {
            "score": current_score,
            "grade": grade,
            "passing_controls": passing,
            "failing_controls": failing,
            "findings": findings,
            "detailed_breakdown": breakdown
        }

    def _get_grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        return "F"

    def _get_severity(self, deduction: int) -> str:
        if deduction >= 20:
            return "critical"
        elif deduction >= 10:
            return "high"
        elif deduction >= 5:
            return "medium"
        return "low"

    DEPRECATED_TLS = ["TLSv1.0", "TLSv1.1"]
    SPF_VERSION = "v=spf1"

    # =========================================================================
    # Common Check Helpers
    # =========================================================================

    def _common_ssl_check(self, data, target_map, expired_deduction=20, weak_deduction=10, deprec_deduction=5, max_total=25) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            if not ssl: continue
            d, r = self._process_ssl_target(ssl, target_map[tid], expired_deduction, weak_deduction, deprec_deduction)
            deduction += d
            reasons.extend(r)
        return min(deduction, max_total), reasons

    def _process_ssl_target(self, ssl, target, exp_d, weak_d, deprec_d) -> Tuple[int, List[str]]:
        d, r = 0, []
        if ssl.get("expired"):
            d += exp_d
            r.append(f"Expired SSL certificate on {target}")
        elif ssl.get("grade") in ["F", "T", "M"]:
            d += weak_d
            r.append(f"Weak SSL configuration on {target}")
        v = ssl.get("tls_version", "")
        if v in self.DEPRECATED_TLS:
            d += deprec_d
            r.append(f"Deprecated TLS version ({v}) on {target}")
        return d, r

    def _common_cves_check(self, data, target_map, crit_points=15, high_points=5, max_total=20) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            web = modules.get("web_analyzer") or modules.get("cve_scanner")
            if not web: continue
            d, r = self._process_cve_target(web, target_map[tid], crit_points, high_points)
            deduction += d
            reasons.extend(r)
        return min(deduction, max_total), reasons

    def _process_cve_target(self, web, target, crit_p, high_p) -> Tuple[int, List[str]]:
        crit, high, reasons = 0, 0, []
        for cve in web.get("cves", []):
            try:
                s = float(cve.get("cvss", 0))
                if s >= 9.0:
                    crit += 1
                    if crit <= 3: reasons.append(f"Critical CVE ({cve.get('id')}) on {target}")
                elif s >= 7.0: high += 1
            except (TypeError, ValueError): pass
        d = (crit_p if crit else 0) + (high_p if high else 0)
        return d, reasons

    def _common_headers_check(self, data, target_map, required_headers=None, max_total=10) -> Tuple[int, List[str]]:
        if not required_headers: required_headers = {"strict-transport-security": 2, "content-security-policy": 2, "x-frame-options": 1, "x-content-type-options": 1}
        deduction, reasons = 0, []
        for tid, modules in data.items():
            web = modules.get("web_analyzer")
            if not web: continue
            keys = [k.lower() for k in web.get("http_headers", {}).keys()]
            for h, points in required_headers.items():
                if h not in keys:
                    deduction += points
                    reasons.append(f"Missing {h.upper()} on {target_map[tid]}")
        return min(deduction, max_total), reasons

    def _common_secrets_check(self, data, target_map, max_total=25) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            nuclei = modules.get("nuclei_scanner")
            if not nuclei: continue
            for f in nuclei.get("findings", []):
                name = f.get("name", "").lower()
                if any(kw in name for kw in ["secret", "api key", "token", "credential", "password"]):
                    if f.get("severity", "").lower() in ["critical", "high"]:
                        deduction += 25
                        reasons.append(f"Exposed secret: {f.get('name')} on {target_map[tid]}")
        return min(deduction, max_total), reasons

    def _common_buckets_check(self, data, target_map, max_total=25) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            infra = modules.get("infrastructure_scanner") or modules.get("cloud_scanner")
            if not infra: continue
            for b in (infra.get("buckets", []) or infra.get("assets", [])):
                if b.get("status") == "Public" or b.get("public"):
                    deduction += 25
                    reasons.append(f"Public cloud storage exposed on {target_map[tid]}")
                    break
        return min(deduction, max_total), reasons

    def _common_ports_check(self, data, target_map, risky_ports, error_points=10, port_points=5, max_total=15) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            pm = modules.get("port_scanner") or modules.get("nmap_scanner")
            if not pm: continue
            if pm.get("error"):
                deduction += error_points
                reasons.append(f"Port scan error on {target_map[tid]}: {pm['error']}")
                continue
            for p in pm.get("open_ports", []):
                pn = p if isinstance(p, int) else p.get("port", 0)
                if pn in risky_ports:
                    deduction += port_points
                    reasons.append(f"Risky port {pn} open on {target_map[tid]}")
        return min(deduction, max_total), reasons

    def _common_email_check(self, data, target_map, spf_points=2, dmarc_points=3, dkim_points=0, max_total=5) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            dns = modules.get("dns_scanner") or modules.get("subdomain_scanner")
            if not dns: continue
            d, r = self._process_email_target(dns, target_map[tid], spf_points, dmarc_points, dkim_points)
            deduction += d
            reasons.extend(r)
        return min(deduction, max_total), reasons

    def _process_email_target(self, dns, target, spf_p, dmarc_p, dkim_p) -> Tuple[int, List[str]]:
        d, r = 0, []
        recs = dns.get("records", {})
        txts = recs.get("TXT", [])
        txt_content = " ".join(str(i) for i in txts).lower()
        if self.SPF_VERSION not in txt_content:
            d += spf_p
            r.append(f"Missing SPF record on {target}")
        if not (any("_dmarc" in str(i).lower() for i in txts) or recs.get("DMARC") or "v=dmarc" in txt_content):
            d += dmarc_p
            r.append(f"Missing DMARC record on {target}")
        if dkim_p and not any("dkim" in str(i).lower() for i in txts):
            d += dkim_p
            r.append(f"Missing DKIM on {target}")
        return d, r


class SOC2Scorer(BaseComplianceFramework):
    """
    SOC2 Trust Services Criteria compliance scorer.
    Focuses on Security, Availability, Processing Integrity,
    Confidentiality, and Privacy.
    """

    @property
    def framework_id(self) -> str:
        return "soc2"

    @property
    def framework_name(self) -> str:
        return "SOC2"

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "CC6.1",
                "name": "Logical Access Security",
                "description": "SSL/TLS encryption and certificate validity",
                "scanner_source": "ssl_scanner",
                "deduction": 20,
                "check_func": "_check_ssl"
            },
            {
                "id": "CC6.6",
                "name": "Vulnerability Management",
                "description": "No critical or high vulnerabilities",
                "scanner_source": "web_analyzer",
                "deduction": 15,
                "check_func": "_check_cves"
            },
            {
                "id": "CC6.7",
                "name": "Security Headers",
                "description": "HSTS, CSP, and other security headers",
                "scanner_source": "web_analyzer",
                "deduction": 10,
                "check_func": "_check_headers"
            },
            {
                "id": "CC6.8",
                "name": "Data Protection",
                "description": "No exposed cloud storage buckets",
                "scanner_source": "infrastructure_scanner",
                "deduction": 25,
                "check_func": "_check_buckets"
            },
            {
                "id": "CC7.1",
                "name": "Network Security",
                "description": "No risky open ports",
                "scanner_source": "port_scanner",
                "deduction": 10,
                "check_func": "_check_open_ports"
            },
            {
                "id": "CC7.2",
                "name": "Email Security",
                "description": "SPF and DMARC records configured",
                "scanner_source": "dns_scanner",
                "deduction": 5,
                "check_func": "_check_email_security"
            },
            {
                "id": "CC8.1",
                "name": "Secrets Management",
                "description": "No exposed secrets or credentials",
                "scanner_source": "nuclei_scanner",
                "deduction": 25,
                "check_func": "_check_secrets"
            }
        ]

    def _check_ssl(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_ssl_check(data, target_map, expired_deduction=20, weak_deduction=10, deprec_deduction=5, max_total=25)

    def _check_cves(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_cves_check(data, target_map, crit_points=15, high_points=5, max_total=20)

    def _check_headers(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_headers_check(data, target_map, max_total=10)

    def _check_buckets(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_buckets_check(data, target_map, max_total=25)

    def _check_open_ports(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_ports_check(data, target_map, risky_ports=[21, 23, 25, 3306, 5432, 3389], max_total=15)

    def _check_email_security(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_email_check(data, target_map, spf_points=2, dmarc_points=3, max_total=5)

    def _check_secrets(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_secrets_check(data, target_map, max_total=25)


class GDPRScorer(BaseComplianceFramework):
    """
    GDPR (General Data Protection Regulation) compliance scorer.
    Focuses on data protection, encryption, and privacy controls.
    """

    @property
    def framework_id(self) -> str:
        return "gdpr"

    @property
    def framework_name(self) -> str:
        return "GDPR"

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "ART25",
                "name": "Data Protection by Design",
                "description": "HTTPS enforcement for all services",
                "scanner_source": "ssl_scanner",
                "deduction": 20,
                "check_func": "_check_https_enforcement"
            },
            {
                "id": "ART32.1a",
                "name": "Encryption of Personal Data",
                "description": "TLS 1.2+ with strong ciphers",
                "scanner_source": "ssl_scanner",
                "deduction": 15,
                "check_func": "_check_encryption"
            },
            {
                "id": "ART32.1b",
                "name": "Confidentiality Measures",
                "description": "HSTS and secure cookies",
                "scanner_source": "web_analyzer",
                "deduction": 10,
                "check_func": "_check_confidentiality"
            },
            {
                "id": "ART32.2",
                "name": "Risk Assessment",
                "description": "No critical vulnerabilities",
                "scanner_source": "web_analyzer",
                "deduction": 20,
                "check_func": "_check_vulnerabilities"
            },
            {
                "id": "ART33",
                "name": "Breach Notification Readiness",
                "description": "No credential leaks detected",
                "scanner_source": "nuclei_scanner",
                "deduction": 25,
                "check_func": "_check_credential_leaks"
            },
            {
                "id": "ART34",
                "name": "Data Minimization",
                "description": "No exposed sensitive files",
                "scanner_source": "content_discovery",
                "deduction": 15,
                "check_func": "_check_sensitive_files"
            }
        ]

    def _check_https_enforcement(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            web = modules.get("web_analyzer")
            if not ssl or ssl.get("error"):
                deduction += 20
                reasons.append(f"No HTTPS available on {target_map[tid]}")
                continue
            if ssl.get("expired"):
                deduction += 15
                reasons.append(f"Expired SSL certificate on {target_map[tid]}")
            if web:
                h = web.get("http_headers", {})
                if "strict-transport-security" not in [k.lower() for k in h.keys()]:
                    deduction += 5
                    reasons.append(f"HTTPS not enforced via HSTS on {target_map[tid]}")
        return min(deduction, 20), reasons

    def _check_encryption(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            if not ssl: continue
            ver = ssl.get("tls_version", "")
            if ver in self.DEPRECATED_TLS:
                deduction += 10
                reasons.append(f"Weak TLS version ({ver}) on {target_map[tid]}")
            weak_c = [c for c in ssl.get("ciphers", []) if any(w in str(c).upper() for w in ["RC4", "DES", "MD5", "NULL"])]
            if weak_c:
                deduction += 5
                reasons.append(f"Weak ciphers detected on {target_map[tid]}")
        return min(deduction, 15), reasons

    def _check_confidentiality(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            web = modules.get("web_analyzer")
            if not web: continue
            h = web.get("http_headers", {})
            keys = [k.lower() for k in h.keys()]
            if "strict-transport-security" not in keys:
                deduction += 3
                reasons.append(f"Missing HSTS on {target_map[tid]}")
            if any(not c.get("secure") for c in web.get("cookies", [])):
                deduction += 2
                reasons.append(f"Insecure cookie on {target_map[tid]}")
            if "x-content-type-options" not in keys:
                deduction += 2
                reasons.append(f"Missing X-Content-Type-Options on {target_map[tid]}")
        return min(deduction, 10), reasons

    def _check_vulnerabilities(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_cves_check(data, target_map, crit_points=10, high_points=5, max_total=20)

    def _check_credential_leaks(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            nuclei = modules.get("nuclei_scanner")
            if not nuclei: continue
            for f in nuclei.get("findings", []):
                name = f.get("name", "").lower()
                if any(kw in name for kw in ["credential", "password", "leak", "exposed"]):
                    deduction += 25
                    reasons.append(f"Potential credential leak: {f.get('name')} on {target_map[tid]}")
        return min(deduction, 25), reasons

    def _check_sensitive_files(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        pats = [".env", "config.json", "database.yml", ".git", "backup", ".sql", "dump"]
        for tid, modules in data.items():
            cnt = modules.get("content_discovery")
            if not cnt: continue
            for path in (cnt.get("discovered", []) or cnt.get("paths", [])):
                pl = str(path).lower() if isinstance(path, str) else str(path.get("path", "")).lower()
                if any(p in pl for p in pats):
                    deduction += 10
                    reasons.append(f"Sensitive file exposed: {pl} on {target_map[tid]}")
                    break
        return min(deduction, 15), reasons


class PCIDSSScorer(BaseComplianceFramework):
    """
    PCI-DSS (Payment Card Industry Data Security Standard) compliance scorer.
    Focuses on cardholder data protection and secure networks.
    """

    @property
    def framework_id(self) -> str:
        return "pci_dss"

    @property
    def framework_name(self) -> str:
        return "PCI-DSS"

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "REQ2.3",
                "name": "Strong Cryptography",
                "description": "TLS 1.2+ with no weak ciphers",
                "scanner_source": "ssl_scanner",
                "deduction": 25,
                "check_func": "_check_strong_tls"
            },
            {
                "id": "REQ4.1",
                "name": "Data Transmission Encryption",
                "description": "All data encrypted in transit",
                "scanner_source": "ssl_scanner",
                "deduction": 20,
                "check_func": "_check_transmission_encryption"
            },
            {
                "id": "REQ6.2",
                "name": "Vulnerability Management",
                "description": "No critical or high CVEs",
                "scanner_source": "web_analyzer",
                "deduction": 20,
                "check_func": "_check_cves"
            },
            {
                "id": "REQ1.1",
                "name": "Firewall Configuration",
                "description": "No risky database/management ports",
                "scanner_source": "port_scanner",
                "deduction": 20,
                "check_func": "_check_firewall_ports"
            },
            {
                "id": "REQ8.2",
                "name": "Authentication Controls",
                "description": "No default credentials detected",
                "scanner_source": "nuclei_scanner",
                "deduction": 25,
                "check_func": "_check_default_credentials"
            },
            {
                "id": "REQ11.2",
                "name": "Vulnerability Scanning",
                "description": "No active exploits detected",
                "scanner_source": "nuclei_scanner",
                "deduction": 20,
                "check_func": "_check_active_exploits"
            }
        ]

    def _check_strong_tls(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_ssl_check(data, target_map, expired_deduction=10, weak_deduction=10, deprec_deduction=15, max_total=25)

    def _check_transmission_encryption(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            ssl, web = modules.get("ssl_scanner"), modules.get("web_analyzer")
            if not ssl or ssl.get("error"):
                deduction += 20
                reasons.append(f"No SSL/TLS available on {target_map[tid]}")
                continue
            if ssl.get("expired"):
                deduction += 10
                reasons.append(f"Expired certificate on {target_map[tid]}")
            if web:
                h = web.get("http_headers", {})
                if "strict-transport-security" not in [k.lower() for k in h.keys()]:
                    deduction += 5
                    reasons.append(f"Missing HSTS (PCI requirement) on {target_map[tid]}")
        return min(deduction, 20), reasons

    def _check_cves(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_cves_check(data, target_map, crit_points=15, high_points=10, max_total=20)

    def _check_firewall_ports(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        ports = {21: "FTP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle", 27017: "MongoDB", 6379: "Redis", 3389: "RDP", 5900: "VNC"}
        return self._common_ports_check(data, target_map, risky_ports=ports, error_points=15, port_points=10, max_total=20)

    def _check_default_credentials(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_secrets_check(data, target_map, max_total=25)

    def _check_active_exploits(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        for tid, modules in data.items():
            n = modules.get("nuclei_scanner")
            if not n: continue
            for f in n.get("findings", []):
                if f.get("severity", "").lower() in ["critical", "high"]:
                    deduction += 10
                    reasons.append(f"Active vulnerability: {f.get('name')} on {target_map[tid]}")
        return min(deduction, 20), reasons


class HIPAAScorer(BaseComplianceFramework):
    """
    HIPAA (Health Insurance Portability and Accountability Act) compliance scorer.
    Focuses on Protected Health Information (PHI) security.
    """

    @property
    def framework_id(self) -> str:
        return "hipaa"

    @property
    def framework_name(self) -> str:
        return "HIPAA"

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "164.312(e)(1)",
                "name": "Transmission Security",
                "description": "All transmissions encrypted via HTTPS",
                "scanner_source": "ssl_scanner",
                "deduction": 25,
                "check_func": "_check_transmission_security"
            },
            {
                "id": "164.312(a)(2)(iv)",
                "name": "Encryption Standard",
                "description": "Strong encryption algorithms (TLS 1.2+)",
                "scanner_source": "ssl_scanner",
                "deduction": 20,
                "check_func": "_check_encryption_standard"
            },
            {
                "id": "164.312(d)",
                "name": "Authentication Controls",
                "description": "No default or weak credentials",
                "scanner_source": "nuclei_scanner",
                "deduction": 25,
                "check_func": "_check_authentication"
            },
            {
                "id": "164.308(a)(1)(ii)(A)",
                "name": "Risk Analysis",
                "description": "No critical vulnerabilities",
                "scanner_source": "web_analyzer",
                "deduction": 20,
                "check_func": "_check_risk_analysis"
            },
            {
                "id": "164.312(a)(1)",
                "name": "Access Control",
                "description": "Database ports not publicly accessible",
                "scanner_source": "port_scanner",
                "deduction": 20,
                "check_func": "_check_access_control"
            },
            {
                "id": "164.310(d)(1)",
                "name": "Data Disposal",
                "description": "No exposed backups or data dumps",
                "scanner_source": "content_discovery",
                "deduction": 25,
                "check_func": "_check_data_disposal"
            }
        ]

    def _check_transmission_security(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_ssl_check(data, target_map, expired_deduction=15, deprec_deduction=0, weak_deduction=0, max_total=25)

    def _check_encryption_standard(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_ssl_check(data, target_map, expired_deduction=0, deprec_deduction=15, weak_deduction=5, max_total=20)

    def _check_authentication(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_secrets_check(data, target_map, max_total=25)

    def _check_risk_analysis(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_cves_check(data, target_map, crit_points=15, high_points=5, max_total=20)

    def _check_access_control(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        r = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
        return self._common_ports_check(data, target_map, risky_ports=r, port_points=15, max_total=20)

    def _check_data_disposal(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        pats = ["backup", ".sql", "dump", ".bak", "export", "phi", "patient", "medical"]
        deduction, reasons = 0, []
        for tid, modules in data.items():
            cnt = modules.get("content_discovery")
            if not cnt: continue
            for path in (cnt.get("discovered", []) or cnt.get("paths", [])):
                pl = str(path).lower() if isinstance(path, str) else str(path.get("path", "")).lower()
                if any(p in pl for p in pats):
                    deduction += 15
                    reasons.append(f"HIPAA violation: Exposed data file {pl} on {target_map[tid]}")
                    break
        return min(deduction, 25), reasons


class ISO27001Scorer(BaseComplianceFramework):
    """
    ISO 27001 (Information Security Management) compliance scorer.
    Focuses on comprehensive security controls.
    """

    @property
    def framework_id(self) -> str:
        return "iso27001"

    @property
    def framework_name(self) -> str:
        return "ISO 27001"

    @property
    def controls(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "A.12.6.1",
                "name": "Technical Vulnerability Management",
                "description": "Timely patching of vulnerabilities",
                "scanner_source": "web_analyzer",
                "deduction": 20,
                "check_func": "_check_vulnerability_management"
            },
            {
                "id": "A.13.1.1",
                "name": "Network Security",
                "description": "Proper network segmentation",
                "scanner_source": "port_scanner",
                "deduction": 15,
                "check_func": "_check_network_security"
            },
            {
                "id": "A.14.1.2",
                "name": "Secure Communications",
                "description": "TLS/SSL properly configured",
                "scanner_source": "ssl_scanner",
                "deduction": 20,
                "check_func": "_check_secure_communications"
            },
            {
                "id": "A.13.2.1",
                "name": "Email Security Policies",
                "description": "SPF, DKIM, and DMARC configured",
                "scanner_source": "dns_scanner",
                "deduction": 10,
                "check_func": "_check_email_policies"
            },
            {
                "id": "A.14.2.5",
                "name": "Security Headers",
                "description": "Web security headers implemented",
                "scanner_source": "web_analyzer",
                "deduction": 10,
                "check_func": "_check_security_headers"
            },
            {
                "id": "A.8.2.3",
                "name": "Asset Classification",
                "description": "No public cloud storage exposure",
                "scanner_source": "cloud_scanner",
                "deduction": 20,
                "check_func": "_check_asset_classification"
            },
            {
                "id": "A.9.4.3",
                "name": "Access Management",
                "description": "No exposed admin interfaces",
                "scanner_source": "content_discovery",
                "deduction": 15,
                "check_func": "_check_access_management"
            }
        ]

    def _check_vulnerability_management(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_cves_check(data, target_map, crit_points=15, high_points=5, max_total=20)

    def _check_network_security(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_ports_check(data, target_map, risky_ports=[21, 23, 3389, 5900, 22], port_points=10, max_total=15)

    def _check_secure_communications(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_ssl_check(data, target_map, expired_deduction=15, weak_deduction=10, deprec_deduction=10, max_total=20)

    def _check_email_policies(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_email_check(data, target_map, spf_points=3, dmarc_points=4, dkim_points=3, max_total=10)

    def _check_security_headers(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_headers_check(data, target_map, max_total=10)

    def _check_asset_classification(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        return self._common_buckets_check(data, target_map, max_total=20)

    def _check_access_management(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction, reasons = 0, []
        pats = ["admin", "phpmyadmin", "wp-admin", "manager", "console", "dashboard", "cpanel"]
        for tid, modules in data.items():
            cnt = modules.get("content_discovery")
            if not cnt: continue
            for path in (cnt.get("discovered", []) or cnt.get("paths", [])):
                pl = str(path).lower() if isinstance(path, str) else str(path.get("path", "")).lower()
                if any(p in pl for p in pats):
                    deduction += 10
                    reasons.append(f"Exposed admin interface: {pl} on {target_map[tid]}")
                    break
        return min(deduction, 15), reasons


# Framework registry for easy access
FRAMEWORKS = {
    "soc2": SOC2Scorer,
    "gdpr": GDPRScorer,
    "pci_dss": PCIDSSScorer,
    "hipaa": HIPAAScorer,
    "iso27001": ISO27001Scorer
}

def get_framework_scorer(framework_id: str) -> BaseComplianceFramework:
    """Get a framework scorer instance by ID."""
    scorer_class = FRAMEWORKS.get(framework_id.lower())
    if not scorer_class:
        raise ValueError(f"Unknown framework: {framework_id}")
    return scorer_class()

def get_all_frameworks() -> List[Dict[str, str]]:
    """Get list of all available frameworks."""
    return [
        {"id": "soc2", "name": "SOC2", "description": "Service Organization Control 2"},
        {"id": "gdpr", "name": "GDPR", "description": "General Data Protection Regulation"},
        {"id": "pci_dss", "name": "PCI-DSS", "description": "Payment Card Industry Data Security Standard"},
        {"id": "hipaa", "name": "HIPAA", "description": "Health Insurance Portability and Accountability Act"},
        {"id": "iso27001", "name": "ISO 27001", "description": "Information Security Management"}
    ]
