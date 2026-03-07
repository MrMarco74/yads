"""
Security.txt Validator (RFC 9116)
===================================
Checks for presence and validity of /.well-known/security.txt
"""
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 7
PATHS = ["/.well-known/security.txt", "/security.txt"]

REQUIRED_FIELDS = {"Contact"}
RECOMMENDED_FIELDS = {"Expires", "Encryption", "Preferred-Languages", "Policy", "Acknowledgments"}


class SecurityTxtScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "security_txt"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger.info(f"[SecurityTxt] Checking {target}")
        session = requests.Session()
        session.headers["User-Agent"] = "YADS-SecurityBot/1.0"

        for scheme in ("https", "http"):
            for path in PATHS:
                url = f"{scheme}://{target}{path}"
                result = self._fetch_and_parse(url, session)
                if result["found"]:
                    logger.info(f"[SecurityTxt] Found at {url}")
                    return result

        logger.info(f"[SecurityTxt] Not found for {target}")
        return {
            "found": False,
            "url": None,
            "raw": None,
            "fields": {},
            "issues": ["security.txt not found at /.well-known/security.txt or /security.txt"],
            "score": 0,
        }

    def _fetch_and_parse(self, url: str, session: requests.Session) -> Dict:
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
            if resp.status_code != 200:
                return {"found": False}
            content_type = resp.headers.get("Content-Type", "")
            if "text/plain" not in content_type and "text/" not in content_type:
                return {"found": False}
            raw = resp.text[:4000]
            if "Contact:" not in raw and "contact:" not in raw.lower():
                return {"found": False}
        except Exception:
            return {"found": False}

        fields, issues = self._parse(raw)
        score = self._score(fields, issues)
        return {
            "found": True,
            "url": url,
            "raw": raw[:2000],
            "fields": fields,
            "issues": issues,
            "score": score,
        }

    def _parse(self, raw: str) -> tuple[Dict[str, List[str]], List[str]]:
        fields: Dict[str, List[str]] = {}
        issues: List[str] = []

        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            fields.setdefault(key, []).append(value)

        # Required fields check
        for req in REQUIRED_FIELDS:
            if req not in fields:
                issues.append(f"Missing required field: {req}")

        # Expires check
        if "Expires" in fields:
            try:
                exp_str = fields["Expires"][0]
                exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                if exp_dt < now:
                    issues.append(f"security.txt has expired ({exp_str})")
                elif (exp_dt - now).days < 30:
                    issues.append(f"security.txt expires in less than 30 days ({exp_str})")
            except Exception:
                issues.append("Expires field has invalid date format (use ISO 8601 with timezone)")
        else:
            issues.append("Missing recommended field: Expires")

        # Contact format check
        for contact in fields.get("Contact", []):
            if not (contact.startswith("mailto:") or contact.startswith("https://") or contact.startswith("tel:")):
                issues.append(f"Contact should use mailto:, https:// or tel: scheme — got: {contact[:60]}")

        return fields, issues

    def _score(self, fields: Dict, issues: List) -> int:
        score = 50  # baseline for having the file
        # Add points for recommended fields
        for rec in RECOMMENDED_FIELDS:
            if rec in fields:
                score += 8
        # Deduct for issues
        score -= len(issues) * 10
        return max(0, min(100, score))
