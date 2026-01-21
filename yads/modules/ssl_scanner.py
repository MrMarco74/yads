import ssl
import socket
import logging
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlparse

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

class SSLScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "ssl_scanner"

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
            # Note: In a real security scanner we might want to VALIDATE it too and report errors.
            # But for "collection" we usually want to see what's there even if invalid.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # We want to see the cert even if self-signed
            
            with socket.create_connection((domain, 443), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    # We need to parse the binary cert or ask for dict form if verify_mode was CERT_REQUIRED
                    # But if CERT_NONE, getpeercert() returns empty dict unless binary_form=True.
                    # With binary_form=True we get DER.
                    # Standard library ssl doesn't easily parse DER to dict unless we use valid certs and normal mode.
                    # Let's try getting it in standard mode first? 
                    # If we use CERT_NONE, `getpeercert(False)` returns {}.
                    # So to get details for ANY cert (even invalid), we need `ssl.get_server_certificate` or parse DER.
                    # Simplify: Use standard retrieval but catch verification errors?
                    # Better: use `ssl.get_server_certificate` to get PEM then parse (still hard with just stdlib).
                    # Actually, if we want detailed fields easily with stdlib, it's best to use `cryptography` lib if available, 
                    # but let's stick to stdlib if possible or see if we can use `ctx.check_hostname = False` but `verify_mode = ssl.CERT_OPTIONAL`?
                    # Python SSL: "If cert_reqs is CERT_NONE (the default), getpeercert() returns an empty dictionary"
                    # If we switch to CERT_OPTIONAL, we might get the dict.
                    pass

        except Exception as e:
            # Retry with strategy 2: CERT_OPTIONAL
            pass

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
                    
        except Exception as e:
            results["error"] = str(e)

        # 3. Cipher Suite Enumeration (Greedy Strategy)
        if not results.get("error"):
            try:
                results["ciphers"] = self._enumerate_ciphers(domain)
            except Exception as e:
                logger.error(f"Cipher enumeration failed: {e}")
                results["ciphers"] = []

        return results

    def _enumerate_ciphers(self, domain: str) -> List[Dict[str, str]]:
        """
        Enumerates supported cipher suites using Nmap `ssl-enum-ciphers` script.
        We fallback to greedy python strategy if nmap fails or returns nothing 
        (though Nmap is preferred for TLS 1.3 support).
        """
        import subprocess
        import xml.etree.ElementTree as ET
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
            
            # Path: host > ports > port > script[id="ssl-enum-ciphers"] > table > table
            # The structure is nested tables.
            # table (key="TLSv1.3") -> table (cipher) -> elem (name)
            
            # Find the script output
            script_out = root.find(".//script[@id='ssl-enum-ciphers']")
            if script_out is None:
                return self._simple_cipher_detect(domain)
            
            # Iterate tables (protocols, e.g., TLSv1.2, TLSv1.3)
            for table in script_out.findall("table"):
                protocol = table.get("key") 
                if not protocol: continue
                
                # Each protocol table has a 'ciphers' table and a 'compressors' table
                # We want the 'ciphers' table
                ciphers_group = None
                for child_table in table.findall("table"):
                    if child_table.get("key") == "ciphers":
                        ciphers_group = child_table
                        break
                
                if not ciphers_group:
                    continue

                # Iterate actual cipher suites
                for cipher_table in ciphers_group.findall("table"):
                    # The cipher suite table itself usually doesn't have a name in 'key' in this version.
                    # It has <elem key="name">CIPHER_NAME</elem>
                    
                    cipher_name = None
                    strength = "Unknown"
                    
                    # Iterate elements to find name and strength
                    for elem in cipher_table.findall("elem"):
                        k = elem.get("key")
                        if k == "name":
                            cipher_name = elem.text
                        elif k == "strength":
                            strength = elem.text
                    
                    # Fallback: sometimes the key IS the name (older nmap), so check if we didn't find specific elem
                    if not cipher_name:
                         cipher_name = cipher_table.get("key")

                    if not cipher_name: continue
                    
                    found_ciphers.append({
                        "name": cipher_name,
                        "version": protocol,
                        "bits": strength 
                    })

            # Pass 2: If we found nothing (maybe older nmap structure?), try flat iteration but ignore 'ciphers'/'compressors' keys
            if not found_ciphers:
                 pass

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
                        "bits": str(cipher[2])
                    }]
        except:
            return []
