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

    def run_scan(self, domain: str) -> Dict[str, Any]:
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
        Enumerates supported cipher suites using a greedy strategy:
        1. Connect and see what cipher is chosen.
        2. Record it.
        3. 'Ban' it by explicitly excluding it in the next handshake.
        4. Repeat until handshake fails or no ciphers overlap.
        """
        found_ciphers = []
        banned_ciphers = []
        
        # Limit iterations to avoid infinite loops
        max_ciphers = 100 
        
        while len(found_ciphers) < max_ciphers:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Construct cipher string: "ALL:!md5:!aNULL:!eNULL" + banned
                # We start with ALL (or default) and subtract what we found.
                # "ALL" might be too broad or deprecated depending on OpenSSL version, 
                # but usually works for enumeration.
                cipher_str = "ALL:COMPLEMENTOFALL" 
                if banned_ciphers:
                    cipher_str += ":!" + ":!".join(banned_ciphers)
                
                context.set_ciphers(cipher_str)
                
                with socket.create_connection((domain, 443), timeout=3.0) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cipher_info = ssock.cipher()
                        # cipher_info is tuple: ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
                        
                        cipher_name = cipher_info[0]
                        protocol_ver = cipher_info[1]
                        
                        if cipher_name in banned_ciphers:
                            # Should not happen if logic works, but break to be safe
                            break
                            
                        found_ciphers.append({
                            "name": cipher_name,
                            "version": protocol_ver,
                            "bits": cipher_info[2]
                        })
                        banned_ciphers.append(cipher_name)
                        
            except (ssl.SSLError, socket.timeout, ConnectionRefusedError):
                # Handshake failed -> No more ciphers supported (or connection issue)
                break
            except Exception as e:
                logger.debug(f"Cipher check stopped/error: {e}")
                break
                
        return found_ciphers
