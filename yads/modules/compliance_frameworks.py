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
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            if not ssl:
                continue

            if ssl.get("expired"):
                deduction += 20
                reasons.append(f"Expired SSL certificate on {target_map[tid]}")
            elif ssl.get("grade") in ["F", "T", "M"]:
                deduction += 10
                reasons.append(f"Weak SSL configuration on {target_map[tid]}")

            # Check TLS version
            tls_version = ssl.get("tls_version", "")
            if tls_version and tls_version in ["TLSv1.0", "TLSv1.1"]:
                deduction += 5
                reasons.append(f"Deprecated TLS version ({tls_version}) on {target_map[tid]}")

        return min(deduction, 25), reasons

    def _check_cves(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            web = modules.get("web_analyzer") or modules.get("cve_scanner")
            if not web:
                continue

            cves = web.get("cves", [])
            critical_count = 0
            high_count = 0

            for cve in cves:
                try:
                    score = float(cve.get("cvss", 0))
                    if score >= 9.0:
                        critical_count += 1
                        if critical_count <= 3:
                            reasons.append(f"Critical CVE ({cve.get('id')}) on {target_map[tid]}")
                    elif score >= 7.0:
                        high_count += 1
                except:
                    pass

            if critical_count > 0:
                deduction += 15
            if high_count > 0:
                deduction += 5

        return min(deduction, 20), reasons

    def _check_headers(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            web = modules.get("web_analyzer")
            if not web:
                continue

            headers = web.get("http_headers", {})
            keys = [k.lower() for k in headers.keys()]

            if "strict-transport-security" not in keys:
                deduction += 2
                reasons.append(f"Missing HSTS on {target_map[tid]}")

            if "content-security-policy" not in keys:
                deduction += 2
                reasons.append(f"Missing CSP on {target_map[tid]}")

            if "x-frame-options" not in keys:
                deduction += 1
                reasons.append(f"Missing X-Frame-Options on {target_map[tid]}")

            if "x-content-type-options" not in keys:
                deduction += 1
                reasons.append(f"Missing X-Content-Type-Options on {target_map[tid]}")

        return min(deduction, 10), reasons

    def _check_buckets(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            infra = modules.get("infrastructure_scanner") or modules.get("cloud_scanner")
            if not infra:
                continue

            buckets = infra.get("buckets", []) or infra.get("assets", [])
            for b in buckets:
                if b.get("status") == "Public" or b.get("public"):
                    deduction += 25
                    reasons.append(f"Public cloud storage exposed on {target_map[tid]}")
                    break

        return min(deduction, 25), reasons

    def _check_open_ports(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []
        risky_ports = [21, 23, 25, 3306, 5432, 3389]

        for tid, modules in data.items():
            port_mod = modules.get("port_scanner") or modules.get("nmap_scanner")
            if not port_mod:
                continue

            # Flag errors as failures for conservative scoring
            if port_mod.get("error"):
                deduction += 10
                reasons.append(f"Port scan error on {target_map[tid]}: {port_mod['error']}")
                continue

            ports = port_mod.get("open_ports", [])
            for p in ports:
                port_num = p if isinstance(p, int) else p.get("port", 0)
                if port_num in risky_ports:
                    deduction += 5
                    reasons.append(f"Risky port {port_num} open on {target_map[tid]}")

        return min(deduction, 15), reasons

    def _check_email_security(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            dns = modules.get("dns_scanner") or modules.get("subdomain_scanner")
            if not dns:
                continue

            records = dns.get("records", {})
            txt_records = records.get("TXT", [])
            txt_content = " ".join(str(r) for r in txt_records).lower()

            has_spf = "v=spf1" in txt_content
            has_dmarc = any("_dmarc" in str(r).lower() for r in txt_records) or records.get("DMARC")

            if not has_spf:
                deduction += 2
                reasons.append(f"Missing SPF record on {target_map[tid]}")

            if not has_dmarc:
                deduction += 3
                reasons.append(f"Missing DMARC record on {target_map[tid]}")

        return min(deduction, 5), reasons

    def _check_secrets(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            nuclei = modules.get("nuclei_scanner")
            if not nuclei:
                continue

            findings = nuclei.get("findings", [])
            for finding in findings:
                severity = finding.get("severity", "").lower()
                name = finding.get("name", "").lower()

                if any(kw in name for kw in ["secret", "api key", "token", "credential", "password"]):
                    if severity in ["critical", "high"]:
                        deduction += 25
                        reasons.append(f"Exposed secret: {finding.get('name')} on {target_map[tid]}")

        return min(deduction, 25), reasons


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
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            web = modules.get("web_analyzer")

            # Check if SSL is present
            if not ssl or ssl.get("error"):
                deduction += 20
                reasons.append(f"No HTTPS available on {target_map[tid]}")
                continue

            if ssl.get("expired"):
                deduction += 15
                reasons.append(f"Expired SSL certificate on {target_map[tid]}")

            # Check HSTS for enforcement
            if web:
                headers = web.get("http_headers", {})
                keys = [k.lower() for k in headers.keys()]
                if "strict-transport-security" not in keys:
                    deduction += 5
                    reasons.append(f"HTTPS not enforced via HSTS on {target_map[tid]}")

        return min(deduction, 20), reasons

    def _check_encryption(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            if not ssl:
                continue

            tls_version = ssl.get("tls_version", "")
            if tls_version in ["TLSv1.0", "TLSv1.1"]:
                deduction += 10
                reasons.append(f"Weak TLS version ({tls_version}) on {target_map[tid]}")

            # Check for weak ciphers
            ciphers = ssl.get("ciphers", [])
            weak_ciphers = [c for c in ciphers if any(w in str(c).upper() for w in ["RC4", "DES", "MD5", "NULL"])]
            if weak_ciphers:
                deduction += 5
                reasons.append(f"Weak ciphers detected on {target_map[tid]}")

        return min(deduction, 15), reasons

    def _check_confidentiality(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            web = modules.get("web_analyzer")
            if not web:
                continue

            headers = web.get("http_headers", {})
            keys = [k.lower() for k in headers.keys()]

            if "strict-transport-security" not in keys:
                deduction += 3
                reasons.append(f"Missing HSTS on {target_map[tid]}")

            # Check cookies for secure flag
            cookies = web.get("cookies", [])
            for cookie in cookies:
                if not cookie.get("secure"):
                    deduction += 2
                    reasons.append(f"Insecure cookie on {target_map[tid]}")
                    break

            if "x-content-type-options" not in keys:
                deduction += 2
                reasons.append(f"Missing X-Content-Type-Options on {target_map[tid]}")

        return min(deduction, 10), reasons

    def _check_vulnerabilities(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            web = modules.get("web_analyzer")
            nuclei = modules.get("nuclei_scanner")

            # Check CVEs
            if web:
                cves = web.get("cves", [])
                for cve in cves:
                    try:
                        score = float(cve.get("cvss", 0))
                        if score >= 9.0:
                            deduction += 10
                            reasons.append(f"Critical vulnerability ({cve.get('id')}) on {target_map[tid]}")
                        elif score >= 7.0:
                            deduction += 5
                    except:
                        pass

            # Check Nuclei findings
            if nuclei:
                findings = nuclei.get("findings", [])
                for f in findings:
                    if f.get("severity", "").lower() == "critical":
                        deduction += 10
                        reasons.append(f"Critical finding: {f.get('name')} on {target_map[tid]}")

        return min(deduction, 20), reasons

    def _check_credential_leaks(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            nuclei = modules.get("nuclei_scanner")
            if not nuclei:
                continue

            findings = nuclei.get("findings", [])
            for finding in findings:
                name = finding.get("name", "").lower()
                if any(kw in name for kw in ["credential", "password", "leak", "exposed"]):
                    deduction += 25
                    reasons.append(f"Potential credential leak: {finding.get('name')} on {target_map[tid]}")

        return min(deduction, 25), reasons

    def _check_sensitive_files(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        sensitive_patterns = [".env", "config.json", "database.yml", ".git", "backup", ".sql", "dump"]

        for tid, modules in data.items():
            content = modules.get("content_discovery")
            if not content:
                continue

            discovered = content.get("discovered", []) or content.get("paths", [])
            for path in discovered:
                path_lower = str(path).lower() if isinstance(path, str) else str(path.get("path", "")).lower()
                for pattern in sensitive_patterns:
                    if pattern in path_lower:
                        deduction += 10
                        reasons.append(f"Sensitive file exposed: {path_lower} on {target_map[tid]}")
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
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            if not ssl:
                continue

            tls_version = ssl.get("tls_version", "")
            if tls_version in ["TLSv1.0", "TLSv1.1"]:
                deduction += 15
                reasons.append(f"PCI-DSS violation: {tls_version} not allowed on {target_map[tid]}")

            # Check for weak ciphers
            ciphers = ssl.get("ciphers", [])
            weak_patterns = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
            for cipher in ciphers:
                cipher_str = str(cipher).upper()
                for pattern in weak_patterns:
                    if pattern in cipher_str:
                        deduction += 10
                        reasons.append(f"Weak cipher {pattern} on {target_map[tid]}")
                        break

        return min(deduction, 25), reasons

    def _check_transmission_encryption(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            web = modules.get("web_analyzer")

            if not ssl or ssl.get("error"):
                deduction += 20
                reasons.append(f"No SSL/TLS available on {target_map[tid]}")
                continue

            if ssl.get("expired"):
                deduction += 10
                reasons.append(f"Expired certificate on {target_map[tid]}")

            # HSTS is mandatory for PCI
            if web:
                headers = web.get("http_headers", {})
                keys = [k.lower() for k in headers.keys()]
                if "strict-transport-security" not in keys:
                    deduction += 5
                    reasons.append(f"Missing HSTS (PCI requirement) on {target_map[tid]}")

        return min(deduction, 20), reasons

    def _check_cves(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            web = modules.get("web_analyzer")
            if not web:
                continue

            cves = web.get("cves", [])
            for cve in cves:
                try:
                    score = float(cve.get("cvss", 0))
                    if score >= 9.0:
                        deduction += 15
                        reasons.append(f"Critical CVE ({cve.get('id')}) - PCI non-compliant on {target_map[tid]}")
                    elif score >= 7.0:
                        deduction += 10
                        reasons.append(f"High CVE ({cve.get('id')}) on {target_map[tid]}")
                except:
                    pass

        return min(deduction, 20), reasons

    def _check_firewall_ports(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []
        # Database and management ports that should not be publicly accessible
        pci_risky_ports = {
            21: "FTP",
            23: "Telnet",
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            1521: "Oracle",
            27017: "MongoDB",
            6379: "Redis",
            3389: "RDP",
            5900: "VNC"
        }

        for tid, modules in data.items():
            port_mod = modules.get("port_scanner") or modules.get("nmap_scanner")
            if not port_mod:
                continue

            # Flag errors as failures for conservative scoring
            if port_mod.get("error"):
                deduction += 15
                reasons.append(f"Port scan error on {target_map[tid]}: {port_mod['error']}")
                continue

            ports = port_mod.get("open_ports", [])
            for p in ports:
                port_num = p if isinstance(p, int) else p.get("port", 0)
                if port_num in pci_risky_ports:
                    deduction += 10
                    reasons.append(f"PCI violation: {pci_risky_ports[port_num]} port {port_num} exposed on {target_map[tid]}")

        return min(deduction, 20), reasons

    def _check_default_credentials(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            nuclei = modules.get("nuclei_scanner")
            if not nuclei:
                continue

            findings = nuclei.get("findings", [])
            for finding in findings:
                name = finding.get("name", "").lower()
                if any(kw in name for kw in ["default", "credential", "admin:admin", "root:root"]):
                    deduction += 25
                    reasons.append(f"Default credentials detected: {finding.get('name')} on {target_map[tid]}")

        return min(deduction, 25), reasons

    def _check_active_exploits(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            nuclei = modules.get("nuclei_scanner")
            if not nuclei:
                continue

            findings = nuclei.get("findings", [])
            for finding in findings:
                severity = finding.get("severity", "").lower()
                if severity in ["critical", "high"]:
                    deduction += 10
                    reasons.append(f"Active vulnerability: {finding.get('name')} on {target_map[tid]}")

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
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")

            if not ssl or ssl.get("error"):
                deduction += 25
                reasons.append(f"HIPAA violation: No encryption on {target_map[tid]}")
                continue

            if ssl.get("expired"):
                deduction += 15
                reasons.append(f"Expired SSL certificate on {target_map[tid]}")

        return min(deduction, 25), reasons

    def _check_encryption_standard(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            if not ssl:
                continue

            tls_version = ssl.get("tls_version", "")
            if tls_version in ["TLSv1.0", "TLSv1.1"]:
                deduction += 15
                reasons.append(f"HIPAA violation: Weak TLS ({tls_version}) on {target_map[tid]}")

            # Check key length
            key_size = ssl.get("key_size", 0)
            if key_size and key_size < 2048:
                deduction += 5
                reasons.append(f"Weak key size ({key_size} bits) on {target_map[tid]}")

        return min(deduction, 20), reasons

    def _check_authentication(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            nuclei = modules.get("nuclei_scanner")
            if not nuclei:
                continue

            findings = nuclei.get("findings", [])
            for finding in findings:
                name = finding.get("name", "").lower()
                if any(kw in name for kw in ["default", "credential", "password", "weak auth"]):
                    deduction += 25
                    reasons.append(f"HIPAA violation: {finding.get('name')} on {target_map[tid]}")

        return min(deduction, 25), reasons

    def _check_risk_analysis(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            web = modules.get("web_analyzer")
            nuclei = modules.get("nuclei_scanner")

            if web:
                cves = web.get("cves", [])
                for cve in cves:
                    try:
                        score = float(cve.get("cvss", 0))
                        if score >= 9.0:
                            deduction += 15
                            reasons.append(f"Critical risk: {cve.get('id')} on {target_map[tid]}")
                        elif score >= 7.0:
                            deduction += 5
                    except:
                        pass

            if nuclei:
                findings = nuclei.get("findings", [])
                critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
                if critical_count > 0:
                    deduction += 10
                    reasons.append(f"{critical_count} critical findings on {target_map[tid]}")

        return min(deduction, 20), reasons

    def _check_access_control(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []
        # Healthcare databases and EHR system ports
        hipaa_restricted_ports = {
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            1521: "Oracle",
            27017: "MongoDB",
            6379: "Redis",
            9200: "Elasticsearch"
        }

        for tid, modules in data.items():
            port_mod = modules.get("port_scanner") or modules.get("nmap_scanner")
            if not port_mod:
                continue

            ports = port_mod.get("open_ports", [])
            for p in ports:
                port_num = p if isinstance(p, int) else p.get("port", 0)
                if port_num in hipaa_restricted_ports:
                    deduction += 15
                    reasons.append(f"HIPAA violation: {hipaa_restricted_ports[port_num]} ({port_num}) exposed on {target_map[tid]}")

        return min(deduction, 20), reasons

    def _check_data_disposal(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        sensitive_patterns = ["backup", ".sql", "dump", ".bak", "export", "phi", "patient", "medical"]

        for tid, modules in data.items():
            content = modules.get("content_discovery")
            if not content:
                continue

            discovered = content.get("discovered", []) or content.get("paths", [])
            for path in discovered:
                path_lower = str(path).lower() if isinstance(path, str) else str(path.get("path", "")).lower()
                for pattern in sensitive_patterns:
                    if pattern in path_lower:
                        deduction += 15
                        reasons.append(f"HIPAA violation: Exposed data file {path_lower} on {target_map[tid]}")
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
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            web = modules.get("web_analyzer")
            nuclei = modules.get("nuclei_scanner")

            if web:
                cves = web.get("cves", [])
                critical_count = 0
                high_count = 0

                for cve in cves:
                    try:
                        score = float(cve.get("cvss", 0))
                        if score >= 9.0:
                            critical_count += 1
                        elif score >= 7.0:
                            high_count += 1
                    except:
                        pass

                if critical_count > 0:
                    deduction += 15
                    reasons.append(f"{critical_count} critical CVEs on {target_map[tid]}")
                if high_count > 0:
                    deduction += 5

            if nuclei:
                findings = nuclei.get("findings", [])
                critical = [f for f in findings if f.get("severity", "").lower() == "critical"]
                if critical:
                    deduction += 10
                    reasons.append(f"{len(critical)} critical Nuclei findings on {target_map[tid]}")

        return min(deduction, 20), reasons

    def _check_network_security(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []
        risky_ports = [21, 23, 3389, 5900, 22]  # Including SSH for public-facing checks

        for tid, modules in data.items():
            port_mod = modules.get("port_scanner") or modules.get("nmap_scanner")
            if not port_mod:
                continue

            ports = port_mod.get("open_ports", [])
            risky_found = []
            for p in ports:
                port_num = p if isinstance(p, int) else p.get("port", 0)
                if port_num in risky_ports:
                    risky_found.append(port_num)

            if risky_found:
                deduction += 10
                reasons.append(f"Risky ports {risky_found} exposed on {target_map[tid]}")

        return min(deduction, 15), reasons

    def _check_secure_communications(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            if not ssl:
                continue

            if ssl.get("expired"):
                deduction += 15
                reasons.append(f"Expired certificate on {target_map[tid]}")

            tls_version = ssl.get("tls_version", "")
            if tls_version in ["TLSv1.0", "TLSv1.1"]:
                deduction += 10
                reasons.append(f"Deprecated TLS ({tls_version}) on {target_map[tid]}")

            grade = ssl.get("grade", "")
            if grade in ["F", "T"]:
                deduction += 10
                reasons.append(f"Poor SSL grade ({grade}) on {target_map[tid]}")

        return min(deduction, 20), reasons

    def _check_email_policies(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            dns = modules.get("dns_scanner") or modules.get("subdomain_scanner")
            if not dns:
                continue

            records = dns.get("records", {})
            txt_records = records.get("TXT", [])
            txt_content = " ".join(str(r) for r in txt_records).lower()

            has_spf = "v=spf1" in txt_content
            has_dmarc = "v=dmarc" in txt_content or any("_dmarc" in str(r).lower() for r in txt_records)
            has_dkim = any("dkim" in str(r).lower() for r in txt_records)

            if not has_spf:
                deduction += 3
                reasons.append(f"Missing SPF on {target_map[tid]}")

            if not has_dmarc:
                deduction += 4
                reasons.append(f"Missing DMARC on {target_map[tid]}")

            if not has_dkim:
                deduction += 3
                reasons.append(f"Missing DKIM on {target_map[tid]}")

        return min(deduction, 10), reasons

    def _check_security_headers(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        required_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options"
        ]

        for tid, modules in data.items():
            web = modules.get("web_analyzer")
            if not web:
                continue

            headers = web.get("http_headers", {})
            keys = [k.lower() for k in headers.keys()]

            missing = [h for h in required_headers if h not in keys]
            if missing:
                deduction += min(len(missing) * 2, 10)
                reasons.append(f"Missing headers {missing} on {target_map[tid]}")

        return min(deduction, 10), reasons

    def _check_asset_classification(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        for tid, modules in data.items():
            cloud = modules.get("cloud_scanner") or modules.get("infrastructure_scanner")
            if not cloud:
                continue

            assets = cloud.get("assets", []) or cloud.get("buckets", [])
            for asset in assets:
                if asset.get("public") or asset.get("status") == "Public":
                    deduction += 20
                    reasons.append(f"Public cloud asset on {target_map[tid]}")
                    break

        return min(deduction, 20), reasons

    def _check_access_management(self, data: Dict[int, Dict], target_map: Dict[int, str]) -> Tuple[int, List[str]]:
        deduction = 0
        reasons = []

        admin_patterns = ["admin", "phpmyadmin", "wp-admin", "manager", "console", "dashboard", "cpanel"]

        for tid, modules in data.items():
            content = modules.get("content_discovery")
            if not content:
                continue

            discovered = content.get("discovered", []) or content.get("paths", [])
            for path in discovered:
                path_lower = str(path).lower() if isinstance(path, str) else str(path.get("path", "")).lower()
                for pattern in admin_patterns:
                    if pattern in path_lower:
                        deduction += 10
                        reasons.append(f"Exposed admin interface: {path_lower} on {target_map[tid]}")
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
