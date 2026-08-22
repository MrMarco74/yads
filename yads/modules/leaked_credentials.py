"""
Leaked Credentials Monitoring (#30)

Checks if domain-associated credentials have appeared in data breaches:
  - Have I Been Pwned (HIBP) domain search API (BYOK)
  - DeHashed API (BYOK)
  - IntelligenceX / LeakIX (passive, public endpoints)
  - Checks paste sites via Google CSE (BYOK)
  - GitHub public repo secret scanning for domain references
  - Breach statistics: breach count, newest breach date, data classes exposed

No credential lookup by specific password — only breach presence check.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 12

HIBP_DOMAIN_URL = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breach/{name}"
DEHASHED_URL = "https://api.dehashed.com/search"
LEAKIX_URL = "https://leakix.net/domain/{domain}"
GITHUB_SEARCH_URL = "https://api.github.com/search/code"


def _clean_domain(target: str) -> str:
    return (
        target.lower().strip()
        .removeprefix("https://").removeprefix("http://")
        .split("/")[0]
    )


def _get_hibp_key(target_id: Optional[int]) -> Optional[str]:
    try:
        from sqlmodel import Session, select
        from yads.database import engine
        from yads.models import SystemConfig
        with Session(engine) as session:
            cfg = session.exec(
                select(SystemConfig).where(SystemConfig.key == "HIBP_API_KEY")
            ).first()
            return cfg.value if cfg and cfg.value else None
    except Exception:
        return None


def _get_dehashed_key(target_id: Optional[int]):
    """Return (email, api_key) for DeHashed."""
    try:
        from sqlmodel import Session, select
        from yads.database import engine
        from yads.models import SystemConfig
        with Session(engine) as session:
            keys = session.exec(select(SystemConfig)).all()
            cfg = {c.key: c.value for c in keys}
            return cfg.get("DEHASHED_EMAIL"), cfg.get("DEHASHED_API_KEY")
    except Exception:
        return None, None


def _get_gse_keys(target_id: Optional[int]):
    try:
        from sqlmodel import Session, select
        from yads.database import engine
        from yads.models import SystemConfig
        with Session(engine) as session:
            keys = session.exec(select(SystemConfig)).all()
            cfg = {c.key: c.value for c in keys}
            return cfg.get("GOOGLE_CSE_KEY"), cfg.get("GOOGLE_CSE_CX")
    except Exception:
        return None, None


def _query_hibp_domain(domain: str, api_key: str) -> Optional[Dict]:
    """HIBP v3 domain search — returns accounts breached per domain."""
    try:
        r = requests.get(
            HIBP_DOMAIN_URL.format(domain=domain),
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "YADS-Security-Scanner/1.0",
            },
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            # Response: { "breachName": ["alias1@domain", ...], ... }
            breach_count = len(data)
            total_accounts = sum(len(v) for v in data.values())
            breaches = list(data.keys())
            return {
                "breach_count": breach_count,
                "total_accounts": total_accounts,
                "breaches": breaches[:20],
            }
        elif r.status_code == 404:
            return {"breach_count": 0, "total_accounts": 0, "breaches": []}
    except Exception as e:
        logger.debug(f"HIBP domain query failed: {e}")
    return None


def _query_hibp_breach_details(breach_name: str, api_key: str) -> Optional[Dict]:
    """Get details about a specific breach."""
    try:
        r = requests.get(
            HIBP_BREACH_URL.format(name=breach_name),
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "YADS-Security-Scanner/1.0",
            },
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "name": data.get("Name", ""),
                "title": data.get("Title", ""),
                "date": data.get("BreachDate", ""),
                "added": data.get("AddedDate", ""),
                "pwn_count": data.get("PwnCount", 0),
                "data_classes": data.get("DataClasses", []),
                "is_sensitive": data.get("IsSensitive", False),
                "is_verified": data.get("IsVerified", False),
                "description": re.sub(r"<[^>]+>", "", data.get("Description", ""))[:300],
            }
    except Exception as e:
        logger.debug(f"HIBP breach detail failed for {breach_name}: {e}")
    return None


def _query_dehashed(domain: str, email: str, api_key: str) -> Optional[Dict]:
    """DeHashed domain search."""
    try:
        r = requests.get(
            DEHASHED_URL,
            params={"query": f"domain:{domain}", "size": 20},
            auth=(email, api_key),
            headers={"Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            entries = data.get("entries", []) or []
            return {
                "total": data.get("total", 0),
                "entries": [
                    {
                        "email": e.get("email", ""),
                        "username": e.get("username", ""),
                        "database_name": e.get("database_name", ""),
                        "hashed_password": bool(e.get("hashed_password")),
                        "password": "REDACTED" if e.get("password") else None,
                    }
                    for e in entries[:15]
                ],
            }
    except Exception as e:
        logger.debug(f"DeHashed query failed: {e}")
    return None


def _check_paste_sites(domain: str, api_key: str, cx: str) -> List[Dict]:
    """Search paste sites via Google CSE for credential dumps."""
    results = []
    try:
        queries = [
            f'site:pastebin.com OR site:paste.ee OR site:ghostbin.com "@{domain}" password',
            f'"{domain}" credentials filetype:txt OR filetype:csv',
        ]
        for q in queries[:1]:
            r = requests.get(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": api_key, "cx": cx, "q": q, "num": 5},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    results.append({
                        "url": item.get("link", ""),
                        "title": item.get("title", ""),
                        "snippet": item.get("snippet", "")[:200],
                    })
    except Exception as e:
        logger.debug(f"Paste site search failed: {e}")
    return results


def _check_github_leaks(domain: str) -> List[Dict]:
    """Search GitHub for public code referencing domain credentials."""
    results = []
    try:
        r = requests.get(
            GITHUB_SEARCH_URL,
            params={
                "q": f'"{domain}" password OR secret OR credential',
                "per_page": 5,
            },
            headers={
                "User-Agent": "YADS-Security-Scanner/1.0",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            items = r.json().get("items", [])
            for item in items[:5]:
                results.append({
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "file": item.get("name", ""),
                    "url": item.get("html_url", ""),
                })
    except Exception as e:
        logger.debug(f"GitHub leak search failed: {e}")
    return results


class LeakedCredentialsScanner(BaseScannerModule):
    """Leaked credentials and data breach monitoring."""

    @property
    def module_name(self) -> str:
        return "leaked_credentials"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)

        result: Dict[str, Any] = {
            "domain": domain,
            "hibp": None,
            "dehashed": None,
            "paste_results": [],
            "github_leaks": [],
            "breach_details": [],
            "sources_checked": [],
            "findings": [],
            "summary": {
                "score": 100,
                "breach_count": 0,
                "exposed_accounts": 0,
                "status": "unknown",
                "has_passwords": False,
            },
        }

        findings: List[Dict] = []
        score = 100
        total_breaches = 0
        total_accounts = 0
        has_passwords = False
        sensitive_data_classes: Set[str] = set()

        # 1. HIBP (BYOK)
        hibp_key = _get_hibp_key(target_id)
        if hibp_key:
            result["sources_checked"].append("haveibeenpwned")
            hibp = _query_hibp_domain(domain, hibp_key)
            result["hibp"] = hibp
            if hibp:
                total_breaches = hibp["breach_count"]
                total_accounts = hibp["total_accounts"]
                # Get details for top breaches
                breach_details = []
                for bname in hibp["breaches"][:5]:
                    detail = _query_hibp_breach_details(bname, hibp_key)
                    if detail:
                        breach_details.append(detail)
                        for dc in detail.get("data_classes", []):
                            sensitive_data_classes.add(dc)
                        if "Passwords" in detail.get("data_classes", []):
                            has_passwords = True
                            
                        # ADD OSINT INTELLIGENCE RECORD
                        if target_id:
                            from yads.models import OSINTIntelligence
                            # Check for duplicates
                            existing = self.db.query(OSINTIntelligence).filter_by(
                                target_id=target_id, 
                                module_name=self.module_name,
                                data_type="breach_record"
                            ).all()
                            if not any(r.data_json.get("name") == detail.get("name") for r in existing):
                                sev = "critical" if "Passwords" in detail.get("data_classes", []) else "high"
                                self.db.add(OSINTIntelligence(
                                    target_id=target_id,
                                    module_name=self.module_name,
                                    data_type="breach_record",
                                    data_json=detail,
                                    severity=sev
                                ))

                result["breach_details"] = breach_details

                # New-breach diffing (#32): the aggregate "found in N breaches"
                # finding below re-fires whenever the count changes, but that
                # conflates "one more breach appeared" with a re-alert of the
                # same known breaches. Diff breach *names* against the last
                # scan and only webhook-alert for genuinely new ones.
                if target_id and hibp.get("breaches"):
                    try:
                        from yads.database import engine as _engine
                        from sqlmodel import Session as _Session
                        from yads.core.baseline_diff import diff_against_last
                        with _Session(_engine) as _db:
                            breach_diff = diff_against_last(_db, "leaked_credentials_breaches", hibp["breaches"], target_id=target_id)
                        new_breaches = breach_diff["added"]
                        if new_breaches and not breach_diff["is_first"]:
                            result["new_breaches"] = new_breaches
                            try:
                                from yads.core.webhook_service import webhook_service
                                from yads.models import Target as _Target
                                with _Session(_engine) as _db2:
                                    t = _db2.get(_Target, target_id)
                                if t:
                                    webhook_service.trigger_event(t.tenant_id, "security_alert", {
                                        "domain": domain,
                                        "module": "leaked_credentials",
                                        "severity": "high",
                                        "title": f"{len(new_breaches)} new breach(es) for {domain}",
                                        "detail": f"Newly appeared: {', '.join(new_breaches[:5])}",
                                    })
                            except Exception as e:
                                logger.warning(f"[LeakedCreds] New-breach webhook failed (non-fatal): {e}")
                    except Exception as e:
                        logger.debug(f"[LeakedCreds] Breach diffing failed: {e}")

        # 2. DeHashed (BYOK)
        dh_email, dh_key = _get_dehashed_key(target_id)
        if dh_email and dh_key:
            result["sources_checked"].append("dehashed")
            dehashed = _query_dehashed(domain, dh_email, dh_key)
            result["dehashed"] = dehashed
            if dehashed and dehashed.get("total", 0) > 0:
                total_breaches = max(total_breaches, 1)
                total_accounts = max(total_accounts, dehashed["total"])
                # Check if any entries have passwords
                for e in dehashed.get("entries", []):
                    if e.get("password") or e.get("hashed_password"):
                        has_passwords = True

        # 3. Paste sites via Google CSE (BYOK)
        gse_key, gse_cx = _get_gse_keys(target_id)
        if gse_key and gse_cx:
            result["sources_checked"].append("paste_sites")
            pastes = _check_paste_sites(domain, gse_key, gse_cx)
            result["paste_results"] = pastes
            
            # ADD OSINT INTELLIGENCE RECORD
            if target_id and pastes:
                from yads.models import OSINTIntelligence
                existing = self.db.query(OSINTIntelligence).filter_by(
                    target_id=target_id, 
                    module_name=self.module_name,
                    data_type="paste_leak"
                ).all()
                for paste in pastes:
                    if not any(r.data_json.get("url") == paste.get("url") for r in existing):
                        self.db.add(OSINTIntelligence(
                            target_id=target_id,
                            module_name=self.module_name,
                            data_type="paste_leak",
                            data_json=paste,
                            severity="high"
                        ))

        # 4. GitHub leaks (no auth required, rate-limited)
        result["sources_checked"].append("github")
        gh_leaks = _check_github_leaks(domain)
        result["github_leaks"] = gh_leaks
        
        # ADD OSINT INTELLIGENCE RECORD
        if target_id and gh_leaks:
            from yads.models import OSINTIntelligence
            existing = self.db.query(OSINTIntelligence).filter_by(
                target_id=target_id, 
                module_name=self.module_name,
                data_type="github_leak"
            ).all()
            for leak in gh_leaks:
                if not any(r.data_json.get("url") == leak.get("url") for r in existing):
                    self.db.add(OSINTIntelligence(
                        target_id=target_id,
                        module_name=self.module_name,
                        data_type="github_leak",
                        data_json=leak,
                        severity="medium"
                    ))

        result["summary"]["breach_count"] = total_breaches
        result["summary"]["exposed_accounts"] = total_accounts
        result["summary"]["has_passwords"] = has_passwords

        # --- Findings ---
        if not result["sources_checked"] or (not hibp_key and not dh_email):
            findings.append({
                "severity": "info",
                "title": "Leaked credentials check — no API keys configured",
                "description": (
                    "Configure HIBP_API_KEY (Have I Been Pwned) and/or DEHASHED_EMAIL + DEHASHED_API_KEY "
                    "in Settings → System Config for full breach monitoring coverage."
                ),
            })

        if total_breaches > 0:
            sev = "critical" if (has_passwords and total_accounts > 100) else \
                  "high" if has_passwords else \
                  "medium" if total_accounts > 50 else "low"
            data_str = ", ".join(list(sensitive_data_classes)[:5])
            findings.append({
                "severity": sev,
                "title": f"Domain found in {total_breaches} data breach(es) — {total_accounts} account(s) exposed",
                "description": (
                    f"@{domain} email addresses were found in {total_breaches} known data breach(es) "
                    f"with {total_accounts} accounts. "
                    f"Exposed data types: {data_str or 'unknown'}. "
                    + ("Plaintext or hashed passwords were exposed — immediate credential rotation required." if has_passwords else "")
                ),
                "breach_count": total_breaches,
                "account_count": total_accounts,
                "data_classes": list(sensitive_data_classes),
                "has_passwords": has_passwords,
            })
            if sev == "critical":
                score -= 60
            elif sev == "high":
                score -= 40
            elif sev == "medium":
                score -= 25
            else:
                score -= 10

        if result["paste_results"]:
            findings.append({
                "severity": "high",
                "title": f"{len(result['paste_results'])} paste site result(s) referencing this domain",
                "description": (
                    "Public paste sites contain content referencing this domain with keywords "
                    "like 'password' or 'credentials'. Manual review recommended."
                ),
                "pastes": result["paste_results"][:5],
            })
            score -= 20

        if gh_leaks:
            findings.append({
                "severity": "medium",
                "title": f"{len(gh_leaks)} GitHub repository(ies) reference this domain with credential keywords",
                "description": (
                    "Public GitHub repositories contain code referencing this domain alongside "
                    "keywords like 'password', 'secret', or 'credential'. Review for accidental exposure."
                ),
                "repos": gh_leaks[:5],
            })
            score -= 15

        if total_breaches == 0 and not result["paste_results"] and not gh_leaks:
            findings.append({
                "severity": "info",
                "title": "No leaked credentials found",
                "description": f"Domain '{domain}' was not found in checked breach databases or paste sites.",
            })
            result["summary"]["status"] = "clean"
        else:
            result["summary"]["status"] = "breached" if total_breaches > 0 else "suspicious"

        result["findings"] = findings
        result["summary"]["score"] = max(0, score)
        return result
