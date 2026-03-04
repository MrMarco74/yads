"""
Post-Quantum Cryptography (PQC) Static Analyzer and Dependency Checker
"""
import ast
import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class VulnerabilityReport:
    """
    Unified vulnerability report with CVSS-style scoring.
    """
    tool: str                          
    package_or_file: str               
    vuln_id: str                      
    severity: str                      
    cvss_score: float = 0.0            
    description: str = ""
    fix_available: str = ""           
    line: Optional[int] = None
    snippet: str = ""
    consensus: int = 0

# PQC Vulnerable Algorithm Regexes (for string searching if AST fails)
PQC_VULN_PATTERNS = {
    "PQC-RSA": re.compile(r'\b(?:RSA|rsa)\b'),
    "PQC-ECC": re.compile(r'\b(?:ECDSA|ECDH|P-256|P-384|secp256k1)\b', re.IGNORECASE),
    "PQC-DH": re.compile(r'\b(?:DH|DHE|Diffie-Hellman)\b', re.IGNORECASE),
    "PQC-AES128": re.compile(r'\bAES-128\b', re.IGNORECASE),
    "WEAK-HASH": re.compile(r'\b(?:MD5|SHA-1|SHA1)\b', re.IGNORECASE),
}

# Hardcoded PEM blocks
PEM_BLOCK_PATTERN = re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----')


class PQCStaticAnalyzer:
    """Analyzes Python files for PQC-vulnerable cryptography usage."""
    
    def scan_file(self, filepath: Path) -> List[VulnerabilityReport]:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
            
        reports = []
        lines = content.splitlines()

        # 1. Regex scanning for string patterns
        self._scan_lines_for_patterns(lines, filepath, reports)

        # 2. AST parsing for Imports
        self._scan_ast_imports(content, lines, filepath, reports)
            
        return reports

    def _scan_lines_for_patterns(self, lines: List[str], filepath: Path, reports: List[VulnerabilityReport]):
        """Helper to scan raw lines via regex to reduce cognitive complexity."""
        for i, line in enumerate(lines, 1):
            if not line.strip() or line.strip().startswith("#"):
                continue
                
            if PEM_BLOCK_PATTERN.search(line):
                reports.append(self._create_report(filepath, "PQC-HARDCODED-KEY", "critical", 9.8, 
                                "Hardcoded Private Key found.", "Remove key from code. Use a secure vault.", i, line))

            if PQC_VULN_PATTERNS["PQC-AES128"].search(line):
                reports.append(self._create_report(filepath, "PQC-AES128", "high", 7.5, 
                                "AES-128 is vulnerable to Grover's algorithm (effective 64-bit security).", "Upgrade to AES-256.", i, line))

            if PQC_VULN_PATTERNS["WEAK-HASH"].search(line):
                reports.append(self._create_report(filepath, "WEAK-HASH", "medium", 5.3, 
                                "Weak legacy hashing algorithm (MD5/SHA-1) detected.", "Upgrade to SHA-256 or SHA-3.", i, line))

    def _scan_ast_imports(self, content: str, lines: List[str], filepath: Path, reports: List[VulnerabilityReport]):
        """Helper to scan AST for vulnerable imports."""
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self._check_import(alias.name, node.lineno, filepath, lines, reports)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self._check_import(node.module, node.lineno, filepath, lines, reports)
        except SyntaxError:
            pass # fallback to regex only

    def _create_report(self, filepath: Path, vuln_id: str, severity: str, cvss: float, desc: str, fix: str, line_no: int, snippet: str) -> VulnerabilityReport:
        return VulnerabilityReport(
            tool="pqc-sast",
            package_or_file=str(filepath),
            vuln_id=vuln_id,
            severity=severity,
            cvss_score=cvss,
            description=desc,
            fix_available=fix,
            line=line_no,
            snippet=snippet.strip()[:100]
        )

    def _check_import(self, module_name: str, line_no: int, filepath: Path, lines: List[str], reports: List[VulnerabilityReport]):
        snippet = lines[line_no-1].strip() if 0 < line_no <= len(lines) else ""
        if module_name in ["rsa", "M2Crypto", "cryptography.hazmat.primitives.asymmetric.rsa", "OpenSSL"]:
            reports.append(self._create_report(filepath, "PQC-RSA", "high", 7.5, 
                            f"RSA/classical cryptography imported '{module_name}'. Vulnerable to Shor's algorithm.", 
                            "Migrate to Post-Quantum algorithms (e.g. ML-KEM, ML-DSA).", line_no, snippet))
        elif module_name in ["cryptography.hazmat.primitives.asymmetric.ec", "ecdsa"]:
             reports.append(self._create_report(filepath, "PQC-ECC", "high", 7.5, 
                            f"Elliptic Curve Cryptography imported '{module_name}'. Vulnerable to Shor's algorithm.", 
                            "Migrate to Post-Quantum algorithms (e.g. ML-DSA).", line_no, snippet))
        elif module_name in ["cryptography.hazmat.primitives.asymmetric.dh"]:
             reports.append(self._create_report(filepath, "PQC-DH", "high", 7.5, 
                            f"Diffie-Hellman imported '{module_name}'. Vulnerable to Shor's algorithm.", 
                            "Migrate to Post-Quantum algorithms (e.g. ML-KEM).", line_no, snippet))
            
class PQCDependencyScanner:
    """Analyzes requirements.txt for outdated libraries lacking PQC support."""
    
    def scan_requirements(self, filepath: Path) -> List[VulnerabilityReport]:
        reports = []
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
            
        for i, line in enumerate(content.splitlines(), 1):
            line_clean = line.strip().lower()
            if not line_clean or line_clean.startswith("#"):
                continue
            self._analyze_dependency_line(line_clean, line, i, filepath, reports)

        return reports
        
    def _create_report(self, filepath: Path, vuln_id: str, severity: str, cvss: float, desc: str, fix: str, line_no: int, snippet: str) -> VulnerabilityReport:
        return VulnerabilityReport(
            tool="pqc-deps",
            package_or_file=str(filepath),
            vuln_id=vuln_id,
            severity=severity,
            cvss_score=cvss,
            description=desc,
            fix_available=fix,
            line=line_no,
            snippet=snippet.strip()[:100]
        )

    def _analyze_dependency_line(self, line_clean: str, original_line: str, curr_line: int, filepath: Path, reports: List[VulnerabilityReport]):
        """Helper to reduce cognitive complexity of dependency parsing."""
        if "cryptography" in line_clean:
            match = re.search(r'cryptography\s*(==|<=|<)\s*(\d+)\.', line_clean)
            if match and int(match.group(2)) < 42:
                reports.append(self._create_report(filepath, "PQC-DEP-CRYPTOGRAPHY", "high", 7.5, 
                                f"Outdated 'cryptography' package (v{match.group(2)}.x). Minimum v42.0.0 required for ML-KEM / ML-DSA support.", 
                                "Upgrade to cryptography >= 42.0.0", curr_line, original_line))
        
        elif line_clean.startswith("pyopenssl"):
            reports.append(self._create_report(filepath, "PQC-DEP-PYOPENSSL", "medium", 5.0, 
                            "pyOpenSSL detected. Ensure it wraps a PQC-compatible BoringSSL or LibreSSL 4.x backend.", 
                            "Verify native TLS library supports FIPS 203/204.", curr_line, original_line))
            
        elif line_clean.startswith("requests") or line_clean.startswith("httpx"):
            reports.append(self._create_report(filepath, "PQC-DEP-HTTPCLIENT", "info", 0.0, 
                            f"HTTP client '{line_clean}' detected. Ensure the underlying TLS library supports hybrid X25519Kyber768.", 
                            "Use modern system OpenSSL 3.x with PQC providers enabled.", curr_line, original_line))
