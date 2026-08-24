"""
Catch-All / Parked Page Detector
=================================
Flags targets whose HTTP(S) response is a parked-domain sales page, a default
web-server splash page, a generic hosting placeholder, or a wildcard/catch-all
vhost that serves identical content regardless of hostname — i.e. the domain
resolves, but there is no real site behind it.

Three cost-ascending detection layers:
  1. Signature match (free, deterministic) — known parking/default-page markers.
  2. Vhost/wildcard content comparison (cheap, one extra request) — compares the
     target's response against a nonce subdomain of the same root domain.
  3. LLM classification (opt-in, costs money) — only for the inconclusive minority,
     gated on Tenant.catchall_llm_fallback_enabled.
"""
import asyncio
import copy
import json
import logging
import uuid
from difflib import SequenceMatcher
from typing import Any, Dict, Optional, Tuple

import requests
import tldextract
from bs4 import BeautifulSoup

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 7
BODY_TRUNCATE = 30_000
VHOST_SIMILARITY_THRESHOLD = 0.90
EMPTY_BODY_THRESHOLD = 40  # stripped visible-text length below this = "empty_body"

# (signature_id, needle) — matched case-insensitively against title+body.
# Not exhaustive; extend as real samples are seen in the field.
PARKING_SIGNATURES = [
    # Registrar / marketplace parking
    ("sedo", "sedoparking.com"),
    ("sedo", "this domain is for sale"),
    ("godaddy_parked", "this domain is parked free"),
    ("bodis", "bodis.com"),
    ("parkingcrew", "parkingcrew.net"),
    ("afternic", "buy this domain"),
    ("afternic", "afternic.com"),
    ("dan_com", "dan.com"),
    ("hugedomains", "hugedomains.com"),
    ("generic_for_sale", "domain may be for sale"),
    ("generic_for_sale", "inquire about this domain"),
    ("generic_for_sale", "this domain is available for purchase"),
    # Default web-server splash pages
    ("apache_ubuntu_default", "apache2 ubuntu default page"),
    ("apache_default", "it works!"),
    ("nginx_default", "welcome to nginx!"),
    ("iis_default", "iis windows server"),
    ("iis_default", "welcome to iis"),
    # Generic hosting placeholders
    ("cpanel_default", "future home of something quite cool"),
    ("plesk_default", "website coming soon"),
    ("generic_placeholder", "under construction"),
    ("generic_placeholder", "coming soon"),
    # German hosting-provider defaults (this tool targets the German market)
    ("ionos_default", "diese domain wurde erfolgreich eingerichtet"),
    ("strato_default", "diese seite wird demnächst"),
    ("hetzner_default", "hetzner online"),
]


class CatchallDetectorScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "catchall_detector"

    def compute_hash(self, data: Dict[str, Any]) -> str:
        """
        Exclude the LLM's free-text reasoning from the change-detection hash —
        unrelated wording drift on a rerun of an already-classified inconclusive
        page shouldn't generate a spurious ChangeEvent.
        """
        hashed = copy.deepcopy(data)
        llm = hashed.get("llm_classification")
        if isinstance(llm, dict):
            llm["reasoning"] = None
        serialized = json.dumps(hashed, sort_keys=True, ensure_ascii=False)
        import hashlib
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger.info(f"[CatchallDetector] Checking {target}")
        session = requests.Session()
        session.headers["User-Agent"] = "YADS-SecurityBot/1.0"

        fetch = self._fetch(target, session)
        if fetch is None:
            return {
                "is_catch_all": None,
                "detection_method": "unreachable",
                "matched_signature": None,
                "http_status": 0,
                "page_title": None,
                "final_url": None,
                "server_header": None,
                "vhost_comparison": None,
                "llm_classification": None,
                "error": "Both HTTPS and HTTP fetch failed",
                "findings": [],
            }

        http_status, final_url, server_header, title, text = fetch

        result: Dict[str, Any] = {
            "is_catch_all": False,
            "detection_method": "none",
            "matched_signature": None,
            "http_status": http_status,
            "page_title": title,
            "final_url": final_url,
            "server_header": server_header,
            "vhost_comparison": None,
            "llm_classification": None,
            "error": None,
            "findings": [],
        }

        # ── Layer 1: signature match ────────────────────────────────────
        haystack = f"{title or ''} {text}".lower()
        if len(text.strip()) < EMPTY_BODY_THRESHOLD:
            result["is_catch_all"] = True
            result["detection_method"] = "empty_body"
            result["findings"] = [{
                "severity": "high",
                "title": f"Domain appears to be parked ({result.get('matched_signature') or 'unclassified'})",
            }]
            return result

        for sig_id, needle in PARKING_SIGNATURES:
            if needle in haystack:
                result["is_catch_all"] = True
                result["detection_method"] = "signature"
                result["matched_signature"] = sig_id
                result["findings"] = [{
                    "severity": "high",
                    "title": f"Domain appears to be parked ({result.get('matched_signature') or 'unclassified'})",
                }]
                return result

        # ── Layer 2: vhost / wildcard content comparison ────────────────
        vhost = self._compare_vhost(target, session, text, http_status)
        result["vhost_comparison"] = vhost
        if vhost and vhost["attempted"] and vhost.get("similarity_ratio") is not None:
            if vhost["similarity_ratio"] >= VHOST_SIMILARITY_THRESHOLD and vhost["status_match"]:
                result["is_catch_all"] = True
                result["detection_method"] = "vhost_comparison"
                result["findings"] = [{
                    "severity": "high",
                    "title": f"Domain appears to be parked ({result.get('matched_signature') or 'unclassified'})",
                }]
                return result

        # ── Layer 3: LLM fallback (opt-in, only if still inconclusive) ──
        llm_result = self._classify_with_llm(target_id, title, text, http_status, server_header)
        if llm_result is not None:
            result["llm_classification"] = llm_result
            if llm_result.get("used"):
                verdict = llm_result.get("verdict")
                result["is_catch_all"] = verdict in ("parked", "catch_all")
                result["detection_method"] = "llm"
                if result["is_catch_all"]:
                    result["findings"] = [{
                        "severity": "high",
                        "title": f"Domain appears to be parked ({result.get('matched_signature') or 'unclassified'})",
                    }]

        return result

    # ------------------------------------------------------------------

    def _fetch(self, host: str, session: requests.Session) -> Optional[Tuple[int, str, Optional[str], Optional[str], str]]:
        """Try https then http. Returns (status, final_url, server_header, title, text) or None."""
        for scheme in ("https", "http"):
            try:
                resp = session.get(
                    f"{scheme}://{host}/", timeout=TIMEOUT, allow_redirects=True, verify=False
                )
                body = resp.text[:BODY_TRUNCATE]
                soup = BeautifulSoup(body, "html.parser")
                title = soup.title.string.strip() if soup.title and soup.title.string else None
                text = soup.get_text(separator=" ", strip=True)
                return (resp.status_code, resp.url, resp.headers.get("Server"), title, text)
            except Exception as e:
                logger.debug(f"[CatchallDetector] {scheme}://{host} fetch failed: {e}")
                continue
        return None

    def _compare_vhost(self, target: str, session: requests.Session, target_text: str, target_status: int) -> Dict[str, Any]:
        vhost_result: Dict[str, Any] = {
            "attempted": False,
            "nonce_host": None,
            "nonce_status": None,
            "similarity_ratio": None,
            "status_match": False,
        }
        try:
            ext = tldextract.extract(target)
            root_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None
            if not root_domain:
                return vhost_result
            nonce_host = f"{uuid.uuid4().hex[:10]}.{root_domain}"
            vhost_result["nonce_host"] = nonce_host
            vhost_result["attempted"] = True

            fetch = self._fetch(nonce_host, session)
            if fetch is None:
                # Nonce host unreachable is not evidence either way for layer 2.
                return vhost_result

            nonce_status, _url, _server, _title, nonce_text = fetch
            vhost_result["nonce_status"] = nonce_status
            vhost_result["status_match"] = (nonce_status == target_status)
            vhost_result["similarity_ratio"] = SequenceMatcher(None, target_text, nonce_text).ratio()
        except Exception as e:
            logger.debug(f"[CatchallDetector] vhost comparison failed for {target}: {e}")
        return vhost_result

    def _classify_with_llm(
        self, target_id: Optional[int], title: Optional[str], text: str, http_status: int, server_header: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        if not target_id or self.db is None:
            return None

        from yads.models import Target

        target_row = self.db.get(Target, target_id)
        tenant_id = target_row.tenant_id if target_row else None
        if not tenant_id:
            return {"used": False, "verdict": None, "confidence": None, "reasoning": None, "reason": "no_tenant"}

        from yads.models import Tenant
        tenant = self.db.get(Tenant, tenant_id)
        if not tenant or not tenant.catchall_llm_fallback_enabled:
            return {"used": False, "verdict": None, "confidence": None, "reasoning": None, "reason": "disabled"}

        from yads.core.llm_service import load_llm_config, get_page_classification

        config = load_llm_config(self.db, tenant_id)
        provider = (config.get("LLM_PROVIDER") or "disabled").strip().lower()
        if provider == "disabled" or not provider:
            return {"used": False, "verdict": None, "confidence": None, "reasoning": None, "reason": "no_llm_configured"}

        try:
            classification = asyncio.run(
                get_page_classification(title, text, http_status, server_header, config)
            )
        except Exception as e:
            logger.error(f"[CatchallDetector] LLM classification failed for target_id={target_id}: {e}")
            return {"used": False, "verdict": None, "confidence": None, "reasoning": None, "reason": "llm_error"}

        if classification is None:
            return {"used": False, "verdict": None, "confidence": None, "reasoning": None, "reason": "llm_error"}

        return {
            "used": True,
            "verdict": classification.get("verdict"),
            "confidence": classification.get("confidence"),
            "reasoning": classification.get("reasoning"),
            "reason": None,
        }
