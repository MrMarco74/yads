"""
DiscoveryScannerAdapter — extracts candidate domains from ScanResult data.

Supports:
  - dns_scanner / subdomain_scanner  → subdomains + ct_related_domains
  - ssl_scanner                       → extracted_domains (SANs)
  - ct_monitor                        → new_certs names + related_domains
  - asn_scanner                       → (future: reverse PTR)
  - web_analyzer                      → tracking ID correlation (future)
"""

import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger("yads-discovery")

# Map scanner → extractor method name
_SCANNER_MAP = {
    "dns_scanner": "_from_dns",
    "subdomain_scanner": "_from_dns",
    "ssl_scanner": "_from_ssl",
    "cert_mismatch_scanner": "_from_cert_mismatch",
    "ct_monitor": "_from_ct_monitor",
    "typosquat_scanner": "_from_typosquat",
}


class DiscoveryScannerAdapter:
    def __init__(self, include_typosquats: bool = False):
        self.include_typosquats = include_typosquats

    def extract(self, module_name: str, data: Dict[str, Any]) -> List[Tuple[str, str, List[str]]]:
        """
        Returns list of (domain, source_scanner, [signal_names]).
        """
        if not data:
            return []

        if module_name == "typosquat_scanner" and not self.include_typosquats:
            return []

        method_name = _SCANNER_MAP.get(module_name)
        if not method_name:
            return []

        try:
            return getattr(self, method_name)(data)
        except Exception as e:
            logger.warning(f"[DiscoveryAdapter] Error extracting from {module_name}: {e}")
            return []

    def _from_dns(self, data: Dict) -> List[Tuple[str, str, List[str]]]:
        results = []
        # Direct subdomains
        for entry in data.get("subdomains", []):
            domain = entry.get("subdomain", "").strip().lower()
            if domain and entry.get("ips"):
                results.append((domain, "dns_scanner", ["subdomain_of_seed"]))

        # CT-related domains (same org)
        for domain in data.get("ct_related_domains", []):
            domain = domain.strip().lower()
            if domain:
                results.append((domain, "dns_scanner", ["ct_related_org"]))

        return results

    def _from_ssl(self, data: Dict) -> List[Tuple[str, str, List[str]]]:
        results = []
        for domain in data.get("extracted_domains", []):
            domain = domain.strip().lower().lstrip("*.")
            if domain:
                results.append((domain, "ssl_scanner", ["same_tls_cert_san"]))
        # Also check sans directly
        for domain in data.get("sans", []):
            domain = domain.strip().lower().lstrip("*.")
            if domain:
                existing = any(d == domain for d, _, _ in results)
                if not existing:
                    results.append((domain, "ssl_scanner", ["same_tls_cert_san"]))
        return results

    def _from_cert_mismatch(self, data: Dict) -> List[Tuple[str, str, List[str]]]:
        results = []
        cert = data.get("cert_info", {})
        for domain in cert.get("sans", []):
            domain = domain.strip().lower().lstrip("*.")
            if domain:
                results.append((domain, "cert_mismatch_scanner", ["same_tls_cert_san"]))
        return results

    def _from_ct_monitor(self, data: Dict) -> List[Tuple[str, str, List[str]]]:
        results = []
        for cert in data.get("new_certs", []):
            for name in cert.get("names", []):
                name = name.strip().lower().lstrip("*.")
                if name:
                    results.append((name, "ct_monitor", ["ct_related_org"]))
        for domain in data.get("related_domains", []):
            domain = domain.strip().lower()
            if domain:
                results.append((domain, "ct_monitor", ["ct_related_org"]))
        return results

    def _from_typosquat(self, data: Dict) -> List[Tuple[str, str, List[str]]]:
        results = []
        for entry in data.get("variations_found", []):
            domain = entry.get("domain", "").strip().lower()
            if domain:
                results.append((domain, "typosquat_scanner", ["string_similarity"]))
        return results
