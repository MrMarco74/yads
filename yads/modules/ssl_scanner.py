import ssl
import socket
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

class SSLScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "ssl_scanner"

    # ---------------------------------------------------------------------------
    # YADS TLS Baseline
    # ---------------------------------------------------------------------------

    # PQC Hybrid Key Exchange Groups (NIST FIPS 203 ML-KEM + classical hybrid)
    # Nmap / OpenSSL report these in kex_group or cipher name (lowercase, with or without underscore)
    PQC_HYBRID_GROUPS = [
        # ML-KEM (NIST FIPS 203 – formerly Kyber) — IANA-standardised
        "x25519mlkem768",       # Primary recommendation
        "x25519_mlkem768",
        "secp256r1mlkem768",
        "secp256r1_mlkem768",
        "x448mlkem1024",        # High security
        "x448_mlkem1024",
        "secp384r1mlkem1024",   # High security
        "secp384r1_mlkem1024",
        # Older draft names (Kyber pre-standardisation) — still deployed
        "x25519_kyber768",
        "x25519kyber768",
        "secp256r1_kyber768",
        "p256_kyber768",
        "p384_kyber1024",
        "x25519_hqc128",
        # Standalone ML-KEM identifiers (seen in some stacks)
        "mlkem512",
        "mlkem768",
        "mlkem1024",
        "kyber512",
        "kyber768",
        "kyber1024",
        # Older p256/p384 aliases
        "p256_mlkem768",
        "p384_mlkem1024",
    ]

    # Acceptable TLS 1.3 cipher suites (AEAD-only, key exchange handled via groups above)
    BASELINE_TLS13_CIPHERS = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
    ]

    # Acceptable TLS 1.2 cipher suites (AEAD + Forward Secrecy required)
    BASELINE_TLS12_CIPHERS = [
        "ECDHE-ECDSA-AES-256-GCM-SHA384",
        "ECDHE-RSA-AES-256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES-128-GCM-SHA256",
        "ECDHE-RSA-AES-128-GCM-SHA256",
        "DHE-RSA-AES-256-GCM-SHA384",
        "DHE-RSA-AES-128-GCM-SHA256",
    ]

    # Cipher patterns that must never appear — flagged as critical
    BASELINE_FORBIDDEN_PATTERNS = [
        "RC4", "NULL", "EXPORT", "anon", "ANON",
        "DES", "3DES", "MD5", "PSK", "SRP",
    ]

    # Classical algorithms vulnerable to Shor's / Grover's algorithm
    CLASSICAL_VULNERABLE_ALGS = ["RSA", "ECDSA", "DH_", "DHE_", "ECDH_"]

    def run_scan(self, domain: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Connects to the domain on port 443 and retrieves certificate details.
        """
        results = {
            "subject": {},
            "issuer": {},
            "version": None,
            "serialNumber": None,
            "notBefore": None,
            "notAfter": None,
            "subjectAltName": [],
            "error": None
        }

        try:
            # Create a context that doesn't verify checking since we just want to grab the cert
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    pass  # Just test connectivity

        except Exception as e:
            logger.debug(f"SSL strategy 1 (CERT_NONE) failed for {domain}: {e}")

        # Strategy 2: CERT_OPTIONAL to get the dict
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL
            
            with socket.create_connection((domain, 443), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_dict = ssock.getpeercert()
                    if not cert_dict:
                        results["error"] = "No certificate presented"
                        return results
                    
                    # Parse standard fields
                    results["subject"] = dict(x[0] for x in cert_dict.get('subject', []))
                    results["issuer"] = dict(x[0] for x in cert_dict.get('issuer', []))
                    results["version"] = cert_dict.get('version')
                    results["serialNumber"] = cert_dict.get('serialNumber')
                    results["notBefore"] = cert_dict.get('notBefore')
                    results["notAfter"] = cert_dict.get('notAfter')
                    results["subjectAltName"] = cert_dict.get('subjectAltName', [])
                    # Extract org/email for CT cross-query
                    results["ct_org"] = results["subject"].get("organizationName") or results["issuer"].get("organizationName")
                    results["ct_email"] = results["subject"].get("emailAddress")
                    
        except Exception as e:
            results["error"] = str(e)

        # 3. Cipher Suite Enumeration (Greedy Strategy)
        if not results.get("error"):
            try:
                results["ciphers"] = self._enumerate_ciphers(domain)
            except Exception as e:
                logger.error(f"Cipher enumeration failed: {e}")
                results["ciphers"] = []

        # 4. PQC Readiness Assessment
        results["pqc_readiness"] = self._assess_pqc_readiness(results)

        return results

    def _assess_pqc_readiness(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assesses Post-Quantum Cryptography (PQC) readiness based on TLS version,
        ciphers, and (if supported by nmap output) key exchange groups.
        """
        ciphers = results.get("ciphers", [])
        error = results.get("error")
        
        assessment = {
            "status": "Unknown",
            "score": 0,
            "flags": [],
            "recommendations": [],
            "hybrid_groups_detected": [],
            "classical_only_ciphers": 0,
            "tls13_ciphers": 0,
        }

        if error:
            assessment["status"] = "Evaluation Failed"
            return assessment

        if not ciphers:
            assessment["status"] = "No Data"
            assessment["recommendations"].append("Run a full SSL/TLS scan to assess PQC readiness")
            return assessment

        # --- TLS 1.3 Check ---
        tls13_ciphers = [c for c in ciphers if c.get("version") == "TLSv1.3"]
        has_tls13 = len(tls13_ciphers) > 0
        assessment["tls13_ciphers"] = len(tls13_ciphers)

        # --- PQC Hybrid Group Detection ---
        # Check kex_group field (populated from Nmap kex_info) OR matches in cipher name
        hybrid_groups_found = []
        for c in ciphers:
            kex = c.get("kex_group", "").lower()
            cipher_name = c.get("name", "").lower()
            
            for group in self.PQC_HYBRID_GROUPS:
                group_lower = group.lower()
                if group_lower in kex or group_lower in cipher_name:
                    if group not in hybrid_groups_found:
                        hybrid_groups_found.append(group)

        assessment["hybrid_groups_detected"] = hybrid_groups_found
        pqc_active = len(hybrid_groups_found) > 0

        # --- Classical vulnerable algorithm check ---
        classical_count = 0
        for c in ciphers:
            name = c.get("name", "").upper()
            if any(alg in name for alg in self.CLASSICAL_VULNERABLE_ALGS):
                classical_count += 1
        assessment["classical_only_ciphers"] = classical_count

        # --- Scoring & Status Logic ---
        if pqc_active:
            assessment["status"] = "PQC Active"
            assessment["score"] = 100
            assessment["flags"].append(f"Hybrid PQC Key Exchange detected ({', '.join(hybrid_groups_found)})")
            if has_tls13:
                assessment["flags"].append("TLS 1.3 supported")
        elif has_tls13:
            assessment["status"] = "PQC Capable"
            assessment["score"] = 65
            assessment["flags"].append("TLS 1.3 supported (PQC foundation ready)")
            assessment["recommendations"].append(
                "Enable a Hybrid PQC Key Exchange group (e.g., X25519Kyber768 / X25519MLKEM768)"
            )
        else:
            assessment["status"] = "Not Ready"
            assessment["score"] = 15
            assessment["flags"].append("No TLS 1.3 support detected")
            assessment["recommendations"].append("Upgrade to TLS 1.3 as a baseline requirement for PQC")
            assessment["recommendations"].append("Plan migration away from TLS 1.2 and below")

        # --- Classical algorithm vulnerability warnings ---
        if classical_count > 0:
            assessment["flags"].append(
                f"{classical_count} cipher(s) using classical key exchange (vulnerable to Shor's algorithm)"
            )
            if pqc_active:
                # Already active but still has some classical — warn but don't penalize heavily
                assessment["recommendations"].append(
                    "Consider disabling purely classical ciphers to enforce PQC-only negotiation"
                )
            elif has_tls13:
                assessment["recommendations"].append(
                    "Plan migration to PQC-secure alternatives (ML-KEM for key exchange, ML-DSA for signatures)"
                )
        
        # --- TLS 1.2 / legacy check ---
        legacy_ciphers = [c for c in ciphers if c.get("version") in ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3"]]
        if legacy_ciphers:
            legacy_versions = list({c.get("version") for c in legacy_ciphers})
            assessment["flags"].append(f"Legacy TLS versions still supported: {', '.join(legacy_versions)}")
            if "TLSv1.0" in legacy_versions or "SSLv3" in legacy_versions:
                assessment["recommendations"].append("Disable TLS 1.0 and SSLv3 immediately — they are insecure")
                assessment["score"] = max(0, assessment["score"] - 20)

        # --- Forbidden cipher check ---
        forbidden_found = []
        for c in ciphers:
            name = c.get("name", "")
            for pattern in self.BASELINE_FORBIDDEN_PATTERNS:
                if pattern.upper() in name.upper() and name not in forbidden_found:
                    forbidden_found.append(name)
        if forbidden_found:
            assessment["flags"].append(f"Forbidden ciphers detected: {', '.join(forbidden_found)}")
            assessment["recommendations"].append("Immediately disable: " + ", ".join(forbidden_found))
            assessment["score"] = max(0, assessment["score"] - 30)

        # --- Non-baseline TLS 1.2 cipher check ---
        non_baseline_tls12 = [
            c.get("name") for c in ciphers
            if c.get("version") == "TLSv1.2"
            and c.get("name") not in self.BASELINE_TLS12_CIPHERS
            and c.get("name") not in forbidden_found
        ]
        if non_baseline_tls12:
            assessment["flags"].append(f"Non-baseline TLS 1.2 ciphers: {', '.join(non_baseline_tls12)}")
            assessment["recommendations"].append(
                "Restrict TLS 1.2 to ECDHE/DHE-AEAD ciphers only (baseline list)"
            )

        return assessment

    def _enumerate_ciphers(self, domain: str) -> List[Dict[str, str]]:
        """
        Enumerates supported cipher suites using Nmap `ssl-enum-ciphers` script.
        We fallback to greedy python strategy if nmap fails or returns nothing 
        (though Nmap is preferred for TLS 1.3 support).
        Also extracts kex_info (key exchange group) from Nmap XML for PQC detection.
        """
        import subprocess
        import defusedxml.ElementTree as ET
        import shutil
        
        found_ciphers = []
        
        # Check if nmap is available
        if not shutil.which("nmap"):
             logger.warning("Nmap not found. Falling back to simple detection.")
             return self._simple_cipher_detect(domain)

        try:
            # Run nmap
            cmd = [
                "nmap", 
                "--script", "ssl-enum-ciphers", 
                "-p", "443", 
                domain, 
                "-oX", "-"
            ]
            
            # Timeout of 60s for nmap scan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                logger.error(f"Nmap failed: {result.stderr}")
                return self._simple_cipher_detect(domain)

            # Parse XML
            root = ET.fromstring(result.stdout)
            
            # Find the script output
            script_out = root.find(".//script[@id='ssl-enum-ciphers']")
            if script_out is None:
                return self._simple_cipher_detect(domain)
            
            # Iterate tables (protocols, e.g., TLSv1.2, TLSv1.3)
            for table in script_out.findall("table"):
                protocol = table.get("key") 
                if not protocol: continue
                
                # Each protocol table has a 'ciphers' table and a 'compressors' table
                ciphers_group = None
                for child_table in table.findall("table"):
                    if child_table.get("key") == "ciphers":
                        ciphers_group = child_table
                        break
                
                if not ciphers_group:
                    continue

                # Iterate actual cipher suites
                for cipher_table in ciphers_group.findall("table"):
                    cipher_name = None
                    strength = "Unknown"
                    kex_info = ""
                    
                    # Iterate elements to find name, strength, and kex_info
                    for elem in cipher_table.findall("elem"):
                        k = elem.get("key")
                        if k == "name":
                            cipher_name = elem.text
                        elif k == "strength":
                            strength = elem.text
                        elif k == "kex_info":
                            # Nmap reports key exchange group here, e.g. "x25519", "x25519_kyber768"
                            kex_info = elem.text or ""
                    
                    # Fallback: sometimes the key IS the name (older nmap)
                    if not cipher_name:
                         cipher_name = cipher_table.get("key")

                    if not cipher_name: continue
                    
                    found_ciphers.append({
                        "name": cipher_name,
                        "version": protocol,
                        "bits": strength,
                        "kex_group": kex_info,  # Key exchange group — used for PQC detection
                    })

            if not found_ciphers:
                 return self._simple_cipher_detect(domain)

        except Exception as e:
            logger.error(f"Nmap parsing failed: {e}")
            return self._simple_cipher_detect(domain)
            
        return found_ciphers

    def _simple_cipher_detect(self, domain: str) -> List[Dict[str, str]]:
        """
        Fallback: Just gets the negotiated cipher (mostly TLS 1.3 or 1.2 best).
        """
        try:
             context = ssl.create_default_context()
             context.check_hostname = False
             context.verify_mode = ssl.CERT_NONE
             with socket.create_connection((domain, 443), timeout=3.0) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    return [{
                        "name": cipher[0],
                        "version": cipher[1],
                        "bits": str(cipher[2]),
                        "kex_group": "",  # Not available via simple stdlib detection
                    }]
        except Exception as e:
            logger.debug(f"Simple cipher detect failed for {domain}: {e}")
            return []
