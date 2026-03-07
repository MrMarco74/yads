"""
Email Security Scanner — SPF, DKIM, DMARC
==========================================
Analyzes DNS-based email authentication records for a domain.
No external API required — pure DNS queries.
"""
import logging
import re
from typing import Any, Dict, List, Optional

import dns.resolver
import dns.exception

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "k2", "s1", "s2",
    "selector1", "selector2", "dkim", "mimecast", "proofpoint",
    "mailchimp", "sendgrid", "amazonses", "mx",
]


class EmailSecurityScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "email_security"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger.info(f"[EmailSecurity] Starting for {target}")
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 5.0

        result: Dict[str, Any] = {
            "spf": self._check_spf(target, resolver),
            "dmarc": self._check_dmarc(target, resolver),
            "dkim": self._probe_dkim(target, resolver),
            "mx": self._check_mx(target, resolver),
            "bimi": self._check_bimi(target, resolver),
        }
        result["score"] = self._compute_score(result)
        result["findings"] = self._build_findings(result)
        logger.info(f"[EmailSecurity] Done for {target} — score {result['score']}/100")
        return result

    # ── SPF ──────────────────────────────────────────────────────────────────
    def _check_spf(self, domain: str, resolver: dns.resolver.Resolver) -> Dict:
        try:
            answers = resolver.resolve(domain, "TXT")
            spf_records = [str(r).strip('"') for r in answers if "v=spf1" in str(r).lower()]
        except Exception:
            spf_records = []

        if not spf_records:
            return {"present": False, "record": None, "policy": None, "issues": ["No SPF record found"]}

        record = spf_records[0]
        issues = []

        if len(spf_records) > 1:
            issues.append("Multiple SPF records found — only one is allowed")

        # Extract qualifier
        policy = None
        if "~all" in record:
            policy = "softfail"
        elif "-all" in record:
            policy = "fail"
        elif "+all" in record:
            policy = "allow_all"
            issues.append("+all allows any sender — dangerous")
        elif "?all" in record:
            policy = "neutral"
            issues.append("?all is neutral — does not reject unauthorised senders")
        elif "all" in record:
            policy = "unknown"

        if policy not in ("fail", "softfail"):
            issues.append("SPF policy does not enforce rejection (use -all or ~all)")

        # DNS lookup count check (max 10 per RFC 7208)
        lookup_mechanisms = re.findall(r'\b(include|a|mx|ptr|exists|redirect):', record)
        if len(lookup_mechanisms) > 8:
            issues.append(f"SPF has {len(lookup_mechanisms)} DNS lookups — risk of exceeding limit of 10")

        return {"present": True, "record": record, "policy": policy, "issues": issues}

    # ── DMARC ────────────────────────────────────────────────────────────────
    def _check_dmarc(self, domain: str, resolver: dns.resolver.Resolver) -> Dict:
        try:
            answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            records = [str(r).strip('"') for r in answers if "v=DMARC1" in str(r)]
        except Exception:
            records = []

        if not records:
            return {"present": False, "record": None, "policy": None, "pct": None, "issues": ["No DMARC record found"]}

        record = records[0]
        issues = []

        policy = self._extract_tag(record, "p")
        sp_policy = self._extract_tag(record, "sp")
        pct = self._extract_tag(record, "pct") or "100"
        rua = self._extract_tag(record, "rua")

        try:
            pct_int = int(pct)
        except ValueError:
            pct_int = 100

        if policy == "none":
            issues.append("DMARC policy is 'none' — monitoring only, no enforcement")
        elif policy not in ("quarantine", "reject"):
            issues.append(f"Unknown DMARC policy: {policy}")

        if pct_int < 100:
            issues.append(f"DMARC applies to only {pct}% of messages")

        if not rua:
            issues.append("No reporting address (rua) configured")

        return {
            "present": True,
            "record": record,
            "policy": policy,
            "subdomain_policy": sp_policy,
            "pct": pct,
            "reporting": rua,
            "issues": issues,
        }

    # ── DKIM ─────────────────────────────────────────────────────────────────
    def _probe_dkim(self, domain: str, resolver: dns.resolver.Resolver) -> Dict:
        found = []
        for selector in DKIM_SELECTORS:
            try:
                answers = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                for r in answers:
                    txt = str(r).strip('"')
                    if "v=DKIM1" in txt or "p=" in txt:
                        found.append({"selector": selector, "record": txt[:200]})
                        break
            except Exception:
                continue

        issues = []
        if not found:
            issues.append("No DKIM selectors found from common selector list")

        return {"selectors_found": found, "count": len(found), "issues": issues}

    # ── MX ───────────────────────────────────────────────────────────────────
    def _check_mx(self, domain: str, resolver: dns.resolver.Resolver) -> Dict:
        try:
            answers = resolver.resolve(domain, "MX")
            records = sorted(
                [{"priority": r.preference, "host": str(r.exchange).rstrip(".")} for r in answers],
                key=lambda x: x["priority"],
            )
            return {"present": True, "records": records, "count": len(records)}
        except Exception:
            return {"present": False, "records": [], "count": 0}

    # ── BIMI ─────────────────────────────────────────────────────────────────
    def _check_bimi(self, domain: str, resolver: dns.resolver.Resolver) -> Dict:
        try:
            answers = resolver.resolve(f"default._bimi.{domain}", "TXT")
            for r in answers:
                txt = str(r).strip('"')
                if "v=BIMI1" in txt:
                    return {"present": True, "record": txt}
        except Exception:
            pass
        return {"present": False, "record": None}

    # ── Scoring ───────────────────────────────────────────────────────────────
    def _compute_score(self, data: Dict) -> int:
        score = 0
        spf = data["spf"]
        dmarc = data["dmarc"]
        dkim = data["dkim"]

        # SPF (30 pts)
        if spf["present"]:
            score += 15
            if spf["policy"] in ("fail", "softfail"):
                score += 15

        # DMARC (40 pts)
        if dmarc["present"]:
            score += 10
            if dmarc["policy"] == "reject":
                score += 30
            elif dmarc["policy"] == "quarantine":
                score += 20
            if dmarc.get("reporting"):
                score += 5  # bonus for reporting

        # DKIM (30 pts)
        if dkim["count"] > 0:
            score += 25
            if dkim["count"] >= 2:
                score += 5

        return min(score, 100)

    # ── Findings ──────────────────────────────────────────────────────────────
    def _build_findings(self, data: Dict) -> List[Dict]:
        findings = []
        for section in ("spf", "dmarc", "dkim"):
            for issue in data[section].get("issues", []):
                severity = "high" if "No " in issue or "dangerous" in issue else "medium"
                findings.append({"section": section.upper(), "issue": issue, "severity": severity})
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _extract_tag(record: str, tag: str) -> Optional[str]:
        match = re.search(rf'\b{tag}=([^;\s]+)', record)
        return match.group(1) if match else None
