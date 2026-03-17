"""
AI Assistant Router (#48, #49, #50)
=====================================
Provides three AI-powered features:
  - Finding Prioritization: rank findings by exploitability + business impact
  - Remediation Assistant: step-by-step fix guidance for a specific finding
  - Natural Language Search: parse NL queries into structured filters and run them
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import requests
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import RoleChecker, get_current_user_html
from yads.database import get_session
from yads.models import ScanResult, SecurityTrend, SystemConfig, Target, Tenant, User
from yads.utils.license_deps import require_feature

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ai-assistant"])

# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------

class PrioritizeRequest(BaseModel):
    target_id: int
    lang: str = "en"


class RemediateRequest(BaseModel):
    finding_title: str
    finding_description: str
    severity: str
    domain: str
    lang: str = "en"


class ExplainFindingRequest(BaseModel):
    """Datensparsamkeit: only generic finding type + severity sent to AI, never hostname/IP."""
    finding_type: str   # e.g. "CORS wildcard misconfiguration"
    severity: str       # critical / high / medium / low / info
    module: str         # e.g. "cors_scanner"
    lang: str = "en"


class ExecutiveSummaryRequest(BaseModel):
    """Datensparsamkeit: only aggregated counts + score sent to AI, never raw hostnames/IPs."""
    target_id: int
    lang: str = "en"


# ---------------------------------------------------------------------------
# AI provider helpers
# ---------------------------------------------------------------------------

def _get_ai_config(session: Session, user: User) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Resolve AI provider config.  Priority:
      1. Tenant llm_provider / llm_api_key / llm_model (per-tenant BYOK)
      2. SystemConfig OPENAI_API_KEY or ANTHROPIC_API_KEY (platform-wide)
    Returns (provider, api_key, model) where provider is 'openai', 'anthropic', or None.
    """
    # --- Tenant-level config ---
    if user.tenant_id:
        tenant = session.get(Tenant, user.tenant_id)
        if tenant and tenant.llm_provider and tenant.llm_api_key:
            prov = tenant.llm_provider.lower()
            if prov in ("openai", "anthropic"):
                model = tenant.llm_model or (
                    "gpt-4o-mini" if prov == "openai" else "claude-haiku-4-5-20251001"
                )
                return prov, tenant.llm_api_key, model

    # --- Platform-level SystemConfig ---
    oai = session.get(SystemConfig, "OPENAI_API_KEY")
    if oai and oai.value:
        return "openai", oai.value, "gpt-4o-mini"

    ant = session.get(SystemConfig, "ANTHROPIC_API_KEY")
    if ant and ant.value:
        return "anthropic", ant.value, "claude-haiku-4-5-20251001"

    return None, None, None


def _call_ai(provider: str, api_key: str, model: str, prompt: str, system: str) -> Optional[str]:
    """Call OpenAI or Anthropic and return the text response, or None on error."""
    try:
        if provider == "openai":
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1500,
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

        elif provider == "anthropic":
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 1500,
                    "system": system,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]

    except Exception as exc:
        logger.warning("AI call failed (%s): %s", provider, exc)
        return None

    return None


def _extract_json(text: str) -> Any:
    """Extract the first JSON object or array from an AI response string."""
    # Try direct parse first
    try:
        return json.loads(text)
    except Exception:
        pass
    # Find JSON block in markdown code fences
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass
    # Find a bare JSON array or object
    match = re.search(r"(\[[\s\S]*\]|\{[\s\S]*\})", text)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Finding extraction (reuse logic from security_findings)
# ---------------------------------------------------------------------------

def _extract_all_findings_for_target(session: Session, target_id: int, user: User) -> List[Dict]:
    """
    Load all latest ScanResults for a target and normalise them into a flat
    list of {title, severity, description, module} dicts.
    """
    # Scope check
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if user.tenant_id and target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    stmt = (
        select(ScanResult)
        .where(ScanResult.target_id == target_id)
        .order_by(ScanResult.scanned_at.desc())
    )
    results = session.exec(stmt).all()

    # Keep only the latest result per module
    latest: Dict[str, ScanResult] = {}
    for r in results:
        if r.module_name not in latest:
            latest[r.module_name] = r

    findings: List[Dict] = []
    for module_name, result in latest.items():
        if not result.data:
            continue
        data = result.data
        extracted = _normalize_findings(module_name, data)
        for f in extracted:
            findings.append({
                "title": f.get("title") or f.get("issue", module_name),
                "severity": f.get("severity", "info"),
                "description": f.get("description", ""),
                "module": module_name,
            })

    return findings


def _normalize_findings(module: str, data: Dict) -> List[Dict]:
    """Convert module-specific data into a generic list of finding dicts."""
    out: List[Dict] = []

    if not data:
        return out

    # Generic extractor: modules that store data["findings"] list
    raw = data.get("findings", [])
    if isinstance(raw, list):
        for f in raw:
            if isinstance(f, dict):
                title = (
                    f.get("title")
                    or f.get("issue")
                    or f.get("name")
                    or f.get("id")
                    or module
                )
                out.append({
                    "title": str(title),
                    "severity": f.get("severity", "info"),
                    "description": f.get("description", "") or f.get("detail", ""),
                })
        if out:
            return out

    # Module-specific extractors
    if module == "email_security":
        for f in data.get("findings", []):
            out.append({
                "title": f"[{f.get('section','')}] {f.get('issue','')}",
                "severity": f.get("severity", "info"),
                "description": "",
            })

    elif module == "axfr_scanner":
        if data.get("vulnerable"):
            f = data.get("finding") or {}
            out.append({
                "title": f.get("issue", "DNS Zone Transfer Exposed"),
                "severity": "critical",
                "description": "Zone transfer succeeded — DNS zone data exposed.",
            })

    elif module == "http_headers":
        for f in data.get("findings", []):
            if f.get("severity") != "info":
                out.append({
                    "title": f"{f.get('header','')}: {f.get('issue','')}",
                    "severity": f.get("severity", "low"),
                    "description": f.get("detail", ""),
                })

    elif module == "cookie_scanner":
        for f in data.get("findings", []):
            out.append({
                "title": f"[{f.get('cookie','')}] {f.get('issue','')}",
                "severity": f.get("severity", "low"),
                "description": "",
            })

    elif module == "cors_scanner":
        for f in data.get("findings", []):
            out.append({
                "title": f.get("issue", "CORS Misconfiguration"),
                "severity": f.get("severity", "medium"),
                "description": f.get("detail", ""),
            })

    elif module == "nuclei_scanner":
        for f in data.get("results", []):
            out.append({
                "title": f.get("templateID", f.get("name", "Nuclei Finding")),
                "severity": f.get("severity", "info"),
                "description": f.get("description", ""),
            })

    elif module == "ssl_scanner":
        for issue in data.get("issues", []):
            if isinstance(issue, dict):
                out.append({
                    "title": issue.get("title", "SSL Issue"),
                    "severity": issue.get("severity", "medium"),
                    "description": issue.get("description", ""),
                })
            elif isinstance(issue, str):
                out.append({"title": issue, "severity": "medium", "description": ""})

    else:
        # Fallback: scan for any nested "findings" or "issues" key
        for key in ("issues", "vulnerabilities", "alerts"):
            items = data.get(key, [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        title = item.get("title") or item.get("issue") or item.get("name") or key
                        out.append({
                            "title": str(title),
                            "severity": item.get("severity", "info"),
                            "description": item.get("description", ""),
                        })
                if out:
                    return out

    return out


# ---------------------------------------------------------------------------
# Rule-based fallbacks
# ---------------------------------------------------------------------------

def _lang_instruction(lang: str) -> str:
    """Return a language instruction suffix for AI system prompts."""
    if lang.lower().startswith("de"):
        return " Antworte auf Deutsch."
    return ""


_SEVERITY_SCORE = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 2}

_KEYWORD_BOOST: List[Tuple[str, int]] = [
    ("rce", 15), ("remote code execution", 15), ("injection", 12), ("sql", 10),
    ("xxe", 10), ("ssrf", 10), ("deserialization", 10), ("zone transfer", 10),
    ("xss", 8), ("cors", 8), ("csrf", 8), ("open redirect", 7),
    ("directory traversal", 7), ("path traversal", 7), ("lfi", 7), ("rfi", 7),
    ("admin", 5), ("login", 5), ("auth", 5), ("password", 5), ("credential", 5),
    ("exposed", 4), ("disclosure", 4), ("leak", 4),
    ("ssl", 3), ("tls", 3), ("certificate", 3), ("header", 2),
]


def _rule_based_prioritize(findings: List[Dict], lang: str = "en") -> List[Dict]:
    scored = []
    for f in findings:
        title_lower = (f.get("title", "") + " " + f.get("description", "")).lower()
        sev = f.get("severity", "info")
        base = _SEVERITY_SCORE.get(sev, 2)
        boost = sum(pts for kw, pts in _KEYWORD_BOOST if kw in title_lower)
        scored.append({**f, "_score": base + boost})

    scored.sort(key=lambda x: x["_score"], reverse=True)

    result = []
    for rank, f in enumerate(scored, start=1):
        sev = f.get("severity", "info")
        raw_score = f["_score"]
        exploitability = min(10, max(1, round(raw_score / 5)))
        business_impact = min(10, max(1, _SEVERITY_SCORE.get(sev, 2) // 4 + 1))
        rationale = _build_rationale(f.get("title", ""), sev, lang)
        result.append({
            "title": f.get("title", ""),
            "severity": sev,
            "module": f.get("module", ""),
            "priority_rank": rank,
            "exploitability": exploitability,
            "business_impact": business_impact,
            "rationale": rationale,
            "ai_generated": False,
        })

    return result


def _build_rationale(title: str, severity: str, lang: str = "en") -> str:
    title_l = title.lower()
    de = lang.lower().startswith("de")
    if any(k in title_l for k in ("rce", "remote code", "injection", "xxe", "ssrf", "deserialization")):
        return ("Hohe Ausnutzbarkeit — Codeausführung oder kritische Datenleckage möglich." if de
                else "High exploitability — code/command execution or critical data exposure possible.")
    if "zone transfer" in title_l or "axfr" in title_l:
        return ("DNS-Zonentransfer legt interne DNS-Struktur offen; kritisches Aufklärungsrisiko." if de
                else "DNS zone transfer exposes full internal DNS map; critical reconnaissance risk.")
    if any(k in title_l for k in ("xss", "cors", "csrf")):
        return ("Client-seitiger Angriffsvektor, der Benutzersitzungen oder Daten gefährden kann." if de
                else "Client-side attack vector that can compromise user sessions or data.")
    if any(k in title_l for k in ("sql", "nosql")):
        return ("Datenbankinjection kann zur vollständigen Datenexfiltration führen." if de
                else "Database injection can lead to full data exfiltration.")
    if any(k in title_l for k in ("admin", "login", "credential", "auth")):
        return ("Exponiertes Administrationsinterface oder schwache Authentifizierung erhöht das Einbruchsrisiko." if de
                else "Exposed administrative interface or weak authentication increases breach risk.")
    if any(k in title_l for k in ("ssl", "tls", "certificate")):
        return ("TLS-Fehlkonfiguration kann Abhören oder Verbindungsfehler ermöglichen." if de
                else "TLS misconfiguration can enable interception or connection failures.")
    if severity == "critical":
        return ("Kritischer Schweregrad — sofortige Behebung erforderlich." if de
                else "Critical severity — immediate remediation required.")
    if severity == "high":
        return ("Hoher Schweregrad — bedeutendes Risiko, im aktuellen Sprint priorisieren." if de
                else "High severity — significant risk, prioritise within current sprint.")
    if severity == "medium":
        return ("Mittlerer Schweregrad — im nächsten Wartungsfenster beheben." if de
                else "Medium severity — remediate within scheduled maintenance window.")
    return ("Niedriger Schweregrad — im nächsten Sicherheitsüberprüfungszyklus behandeln." if de
            else "Low severity — address in next security review cycle.")


_REMEDIATION_MAP: Dict[str, Dict] = {
    "cors": {
        "steps": [
            "Identify all origins that legitimately need cross-origin access.",
            "Set Access-Control-Allow-Origin to an explicit allowlist — never use wildcard (*) with credentials.",
            "Restrict Access-Control-Allow-Methods to only required HTTP verbs.",
            "Remove Access-Control-Allow-Headers: * and enumerate required headers.",
            "Test with curl or browser devtools to confirm only allowed origins receive the header.",
        ],
        "estimated_effort": "low",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            "https://portswigger.net/web-security/cors",
        ],
    },
    "xss": {
        "steps": [
            "Implement a strict Content-Security-Policy (CSP) that prohibits inline scripts.",
            "HTML-encode all user-supplied data before rendering in templates.",
            "Use a well-tested sanitisation library (e.g., DOMPurify for JS, bleach for Python).",
            "Set the X-XSS-Protection: 1; mode=block header as a legacy defence.",
            "Audit all reflected, stored, and DOM-based injection points.",
        ],
        "estimated_effort": "medium",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "sql": {
        "steps": [
            "Replace string-concatenated queries with parameterised queries or prepared statements.",
            "Use an ORM that handles escaping automatically (e.g., SQLAlchemy, Hibernate).",
            "Apply least-privilege database accounts — app user should not have DDL rights.",
            "Enable WAF rules for common SQL injection patterns.",
            "Run a DAST tool (e.g., sqlmap in safe mode) on staging to verify remediation.",
        ],
        "estimated_effort": "medium",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ],
    },
    "ssl": {
        "steps": [
            "Upgrade to TLS 1.2 minimum; prefer TLS 1.3.",
            "Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1 in your web-server configuration.",
            "Renew or replace the certificate before expiry (set automated renewal with ACME/Let's Encrypt).",
            "Enable HSTS with a min-age of at least 1 year and includeSubDomains.",
            "Verify configuration with SSL Labs: https://www.ssllabs.com/ssltest/",
        ],
        "estimated_effort": "low",
        "references": [
            "https://ssl-config.mozilla.org/",
            "https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html",
        ],
    },
    "header": {
        "steps": [
            "Add missing security headers to your web-server or reverse-proxy configuration.",
            "Set Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
            "Define a Content-Security-Policy appropriate to the application.",
            "Remove headers that disclose software versions (Server, X-Powered-By).",
            "Validate with https://securityheaders.com after deployment.",
        ],
        "estimated_effort": "low",
        "references": [
            "https://securityheaders.com/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        ],
    },
    "axfr": {
        "steps": [
            "Restrict AXFR (zone transfer) to trusted secondary nameserver IPs only.",
            "In BIND: add allow-transfer { <secondary_ip>; }; to the zone configuration.",
            "In PowerDNS: set allow-axfr-ips in pdns.conf.",
            "Verify the fix: dig axfr @<nameserver> <domain> should return REFUSED.",
            "Consider TSIG (Transaction Signature) keys for authenticated transfers.",
        ],
        "estimated_effort": "low",
        "references": [
            "https://www.isc.org/blogs/axfr-zone-transfers/",
            "https://dnsinstitute.com/documentation/dnssec-guide/ch03s05.html",
        ],
    },
    "cookie": {
        "steps": [
            "Set the Secure flag on all cookies that contain sensitive data or session tokens.",
            "Set the HttpOnly flag to prevent JavaScript access to session cookies.",
            "Set SameSite=Lax or SameSite=Strict to mitigate CSRF attacks.",
            "Reduce cookie lifetimes — avoid Expires values far in the future for session cookies.",
            "Audit Set-Cookie headers in server responses with browser devtools.",
        ],
        "estimated_effort": "low",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
        ],
    },
    "csrf": {
        "steps": [
            "Implement CSRF tokens (double-submit cookie or synchroniser token pattern).",
            "Set SameSite=Strict on session cookies.",
            "Validate the Origin and Referer headers on state-changing requests.",
            "Use framework-native CSRF protection if available (Django, Laravel, Rails all provide this).",
        ],
        "estimated_effort": "low",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "rce": {
        "steps": [
            "Immediately patch or disable the affected component — this is critical.",
            "Isolate the affected system from the network until patched.",
            "Review and apply vendor security advisories or CVE patches.",
            "Implement input validation and deny-list for system command calls.",
            "Enable application-level WAF rules blocking common RCE payloads.",
            "Review logs for evidence of exploitation and conduct incident response if needed.",
        ],
        "estimated_effort": "high",
        "references": [
            "https://owasp.org/www-community/attacks/Code_Injection",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
    },
    "open redirect": {
        "steps": [
            "Validate redirect destination URLs against an allowlist of trusted domains.",
            "Reject or sanitise absolute URLs in redirect parameters.",
            "Use relative paths for internal redirects wherever possible.",
            "Return a warning page before redirecting to external domains.",
        ],
        "estimated_effort": "low",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ],
    },
    "default": {
        "steps": [
            "Review the finding details and consult the vendor advisory for the affected component.",
            "Apply the latest security patches or updates for the affected software.",
            "Validate the fix in a staging environment before deploying to production.",
            "Re-scan after remediation to confirm the finding is resolved.",
            "Document the remediation steps and timeline in your risk register.",
        ],
        "estimated_effort": "medium",
        "references": [
            "https://owasp.org/www-project-top-ten/",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
    },
}


_EFFORT_DE = {"low": "Geringer Aufwand", "medium": "Mittlerer Aufwand", "high": "Hoher Aufwand"}


def _rule_based_remediate(title: str, description: str, severity: str, lang: str = "en") -> Dict:
    text = (title + " " + description).lower()
    for keyword in ("rce", "remote code", "open redirect", "axfr", "zone transfer",
                    "csrf", "cors", "cookie", "xss", "sql", "ssl", "header"):
        if keyword in text:
            key = {
                "remote code": "rce",
                "zone transfer": "axfr",
            }.get(keyword, keyword)
            entry = _REMEDIATION_MAP.get(key, _REMEDIATION_MAP["default"])
            result = {**entry, "ai_generated": False}
            if lang.lower().startswith("de"):
                result["estimated_effort"] = _EFFORT_DE.get(result.get("estimated_effort", "medium"), result.get("estimated_effort", "medium"))
            return result
    result = {**_REMEDIATION_MAP["default"], "ai_generated": False}
    if lang.lower().startswith("de"):
        result["estimated_effort"] = _EFFORT_DE.get(result.get("estimated_effort", "medium"), result.get("estimated_effort", "medium"))
    return result


# ---------------------------------------------------------------------------
# Rule-based fallback: Finding Explanation (Enterprise)
# ---------------------------------------------------------------------------

_EXPLAIN_MAP: Dict[str, Dict] = {
    "cors": {
        "explanation": (
            "A CORS misconfiguration allows untrusted origins to make authenticated cross-origin "
            "requests to your API. This typically occurs when Access-Control-Allow-Origin is set "
            "to a wildcard (*) or reflects the requesting origin without validation."
        ),
        "attacker_scenario": (
            "An attacker hosts a malicious page that calls your API on behalf of a logged-in victim, "
            "reading or modifying their data by exploiting the permissive CORS policy."
        ),
        "remediation_hint": (
            "Set Access-Control-Allow-Origin to a strict allowlist of trusted domains, "
            "and never combine a wildcard with Access-Control-Allow-Credentials: true."
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            "https://portswigger.net/web-security/cors",
        ],
    },
    "xss": {
        "explanation": (
            "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages "
            "viewed by other users. It arises from insufficient output encoding of user-controlled data."
        ),
        "attacker_scenario": (
            "An attacker injects a script that steals session cookies or performs actions on behalf "
            "of the victim, such as changing passwords or exfiltrating data."
        ),
        "remediation_hint": (
            "HTML-encode all user-supplied output, implement a strict Content-Security-Policy, "
            "and use framework-native templating that auto-escapes."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "ssl": {
        "explanation": (
            "A TLS/SSL misconfiguration exposes the connection to downgrade attacks or interception. "
            "Common causes are weak cipher suites, outdated protocol versions (TLS 1.0/1.1), or "
            "certificates that are expired, self-signed, or mismatched."
        ),
        "attacker_scenario": (
            "A network-level attacker performs a downgrade or MITM attack, decrypting traffic "
            "between the client and server to read or modify sensitive data in transit."
        ),
        "remediation_hint": (
            "Enforce TLS 1.2+ (prefer 1.3), disable legacy cipher suites, enable HSTS, "
            "and ensure certificates are valid and renewed automatically."
        ),
        "references": [
            "https://ssl-config.mozilla.org/",
            "https://www.ssllabs.com/ssltest/",
        ],
    },
    "axfr": {
        "explanation": (
            "A DNS zone transfer (AXFR) is accessible to unauthenticated clients. "
            "This exposes the entire DNS zone including internal hostnames, mail servers, "
            "and infrastructure details that should remain private."
        ),
        "attacker_scenario": (
            "An attacker retrieves the full DNS zone to map internal infrastructure, "
            "identifying high-value targets for further attacks."
        ),
        "remediation_hint": (
            "Restrict AXFR to trusted secondary nameserver IPs only using allow-transfer "
            "directives, and verify with: dig axfr @nameserver domain."
        ),
        "references": ["https://www.isc.org/blogs/axfr-zone-transfers/"],
    },
    "header": {
        "explanation": (
            "Missing or misconfigured HTTP security headers leave the browser without important "
            "security instructions, enabling attacks like clickjacking, MIME-sniffing, or "
            "information disclosure via the Server header."
        ),
        "attacker_scenario": (
            "Without X-Frame-Options, an attacker embeds the site in an iframe for clickjacking. "
            "A missing CSP enables XSS execution. Version headers help enumerate vulnerable software."
        ),
        "remediation_hint": (
            "Add Strict-Transport-Security, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, "
            "Referrer-Policy, and a Content-Security-Policy appropriate to the application."
        ),
        "references": [
            "https://securityheaders.com/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        ],
    },
    "cookie": {
        "explanation": (
            "Session or authentication cookies are missing security flags (Secure, HttpOnly, SameSite). "
            "This exposes them to theft via network sniffing or JavaScript injection."
        ),
        "attacker_scenario": (
            "Without HttpOnly, an XSS payload reads the session cookie. "
            "Without Secure, the cookie is transmitted over HTTP and can be captured in transit."
        ),
        "remediation_hint": (
            "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on all session cookies. "
            "Avoid storing sensitive data in cookies that lack these flags."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    },
    "sql": {
        "explanation": (
            "SQL Injection allows attackers to manipulate database queries by injecting malicious SQL "
            "through user-controlled input. It results from building queries via string concatenation."
        ),
        "attacker_scenario": (
            "An attacker extracts all data from the database, bypasses authentication, "
            "or — with sufficient privileges — executes OS commands."
        ),
        "remediation_hint": (
            "Always use parameterised queries or prepared statements. "
            "Apply least-privilege database accounts and audit all dynamic query construction."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "default": {
        "explanation": (
            "This security finding indicates a configuration weakness or vulnerability that could "
            "be exploited by an attacker to gain unauthorised access, leak data, or disrupt service."
        ),
        "attacker_scenario": (
            "The specific attack scenario depends on the finding. Consult the module documentation "
            "and relevant CVEs or security advisories for the affected component."
        ),
        "remediation_hint": (
            "Apply the latest vendor patches, review the affected configuration against security "
            "baselines, and re-scan after remediation to confirm resolution."
        ),
        "references": [
            "https://owasp.org/www-project-top-ten/",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
    },
}

_EXPLAIN_DE = {
    "explanation": "Erklärung",
    "attacker_scenario": "Angriffsszenario",
    "remediation_hint": "Behebungshinweis",
}


def _rule_based_explain(finding_type: str, severity: str, module: str, lang: str = "en") -> Dict:
    text = (finding_type + " " + module).lower()
    for keyword in ("cors", "xss", "ssl", "tls", "certificate", "axfr", "zone transfer",
                    "header", "cookie", "sql"):
        if keyword in text:
            key = {"tls": "ssl", "certificate": "ssl", "zone transfer": "axfr"}.get(keyword, keyword)
            entry = _EXPLAIN_MAP.get(key, _EXPLAIN_MAP["default"])
            return {**entry, "ai_generated": False}
    return {**_EXPLAIN_MAP["default"], "ai_generated": False}


# ---------------------------------------------------------------------------
# Rule-based fallback: Executive Summary (Enterprise)
# ---------------------------------------------------------------------------

def _rule_based_executive_summary(
    score: int,
    total: int,
    by_severity: Dict[str, int],
    top_modules: List[str],
    lang: str = "en",
) -> Dict:
    de = lang.lower().startswith("de")
    critical = by_severity.get("critical", 0)
    high = by_severity.get("high", 0)
    medium = by_severity.get("medium", 0)

    if score >= 80:
        risk_rating = "Low" if not de else "Niedrig"
    elif score >= 60:
        risk_rating = "Medium" if not de else "Mittel"
    elif score >= 40:
        risk_rating = "High" if not de else "Hoch"
    else:
        risk_rating = "Critical" if not de else "Kritisch"

    if de:
        summary = (
            f"Die Sicherheitsbewertung ergibt einen Score von {score}/100 ({risk_rating}). "
            f"Es wurden insgesamt {total} Findings identifiziert"
            + (f", davon {critical} kritische und {high} hohe" if critical + high > 0 else "")
            + ". "
            f"Die Hauptrisikobereiche sind: {', '.join(top_modules[:3]) if top_modules else 'allgemeine Sicherheitskonfiguration'}. "
            "Eine detaillierte Prüfung und Behebung der kritischen und hohen Findings wird empfohlen."
        )
        key_points = [
            f"Gesamtscore: {score}/100 — Risikoeinstufung: {risk_rating}",
            f"{total} Findings insgesamt ({critical} kritisch, {high} hoch, {medium} mittel)",
            f"Hauptbetroffene Module: {', '.join(top_modules[:3]) if top_modules else '—'}",
        ]
        recommended_actions = [
            f"Sofort: {critical} kritische Finding(s) priorisieren und innerhalb von 24 Stunden beheben." if critical else "Hohe Findings im aktuellen Sprint adressieren.",
            "Mittelfristig: Mittlere und niedrige Findings in regelmäßigen Wartungsfenstern beheben.",
            "Continuous: Regelmäßige Neuscans einplanen, um Regressionen zu erkennen.",
        ]
    else:
        summary = (
            f"The security assessment yielded a score of {score}/100 ({risk_rating} risk). "
            f"A total of {total} findings were identified"
            + (f", including {critical} critical and {high} high severity" if critical + high > 0 else "")
            + ". "
            f"Primary risk areas: {', '.join(top_modules[:3]) if top_modules else 'general security configuration'}. "
            "Immediate remediation of critical and high findings is recommended."
        )
        key_points = [
            f"Overall score: {score}/100 — Risk rating: {risk_rating}",
            f"{total} findings total ({critical} critical, {high} high, {medium} medium)",
            f"Top affected areas: {', '.join(top_modules[:3]) if top_modules else '—'}",
        ]
        recommended_actions = [
            f"Immediate: Prioritise {critical} critical finding(s) for remediation within 24 hours." if critical else "Address high findings within the current sprint.",
            "Medium-term: Remediate medium and low findings within scheduled maintenance windows.",
            "Ongoing: Schedule regular re-scans to detect regressions.",
        ]

    return {
        "summary": summary,
        "risk_rating": risk_rating,
        "key_points": key_points,
        "recommended_actions": recommended_actions,
        "ai_generated": False,
    }


# ---------------------------------------------------------------------------
# NL Search helpers
# ---------------------------------------------------------------------------

_NL_SEVERITY_WORDS = {
    "critical": "critical", "high": "high", "medium": "medium",
    "moderate": "medium", "low": "low", "info": "info",
}

_NL_MODULE_WORDS = {
    "ssl": "ssl_scanner", "tls": "ssl_scanner", "certificate": "ssl_scanner",
    "dns": "dns_scanner", "subdomain": "dns_scanner",
    "email": "email_security", "spf": "email_security", "dkim": "email_security",
    "dmarc": "email_security",
    "header": "http_headers", "headers": "http_headers",
    "cookie": "cookie_scanner", "cookies": "cookie_scanner",
    "cors": "cors_scanner",
    "nuclei": "nuclei_scanner", "vuln": "nuclei_scanner", "cve": "nuclei_scanner",
    "port": "port_scanner", "ports": "port_scanner",
    "web": "web_analyzer", "tech": "web_analyzer",
    "cloud": "cloud_scanner", "s3": "cloud_scanner", "bucket": "cloud_scanner",
    "axfr": "axfr_scanner", "zone": "axfr_scanner",
}


def _rule_based_nl_parse(query: str, lang: str = "en") -> Tuple[Dict, str]:
    """
    Parse a natural language query into filter dict.
    Returns (filters, interpretation_string).
    """
    q = query.lower()
    de = lang.lower().startswith("de")
    filters: Dict[str, Any] = {}
    parts: List[str] = []

    # Severity
    for word, sev in _NL_SEVERITY_WORDS.items():
        if word in q:
            filters["severity"] = sev
            parts.append(f"severity={sev}")
            break

    # Module
    for word, mod in _NL_MODULE_WORDS.items():
        if word in q:
            filters["module"] = mod
            parts.append(f"module={mod}")
            break

    # Domain fragment
    domain_match = re.search(r"\b([a-z0-9-]+\.[a-z]{2,})\b", q)
    if domain_match:
        filters["domain_contains"] = domain_match.group(1)
        parts.append(f"domain~{domain_match.group(1)}")

    if de:
        interpretation = "Angewendete Filter: " + (", ".join(parts) if parts else "keine (alle anzeigen)")
    else:
        interpretation = "Filters applied: " + (", ".join(parts) if parts else "none (showing all)")
    return filters, interpretation


def _ai_nl_parse(provider: str, api_key: str, model: str, query: str, lang: str = "en") -> Optional[Dict]:
    system = (
        "You are a security data analyst. Parse the user's natural language query into "
        "a JSON filter object with optional keys: severity (critical/high/medium/low/info), "
        "module (e.g. ssl_scanner, dns_scanner, email_security, http_headers, cookie_scanner, "
        "cors_scanner, nuclei_scanner, port_scanner, web_analyzer, axfr_scanner), "
        "domain_contains (string). Return ONLY valid JSON, no explanation."
        + _lang_instruction(lang)
    )
    text = _call_ai(provider, api_key, model, f"Query: {query}", system)
    if text:
        parsed = _extract_json(text)
        if isinstance(parsed, dict):
            return parsed
    return None


def _apply_filters(session: Session, user: User, filters: Dict) -> List[Dict]:
    """Run filters against targets+scan results and return matching findings."""
    # Build target query
    tq = select(Target).where(Target.is_archived == False)
    if user.tenant_id:
        tq = tq.where(Target.tenant_id == user.tenant_id)

    domain_contains = filters.get("domain_contains")
    if domain_contains:
        tq = tq.where(Target.domain.contains(domain_contains))

    targets = session.exec(tq).all()
    if not targets:
        return []

    target_ids = [t.id for t in targets]
    target_map = {t.id: t for t in targets}

    # Build scan result query
    rq = (
        select(ScanResult)
        .where(ScanResult.target_id.in_(target_ids))
        .order_by(ScanResult.scanned_at.desc())
    )
    module_filter = filters.get("module")
    if module_filter:
        rq = rq.where(ScanResult.module_name == module_filter)

    results = session.exec(rq).all()

    # Keep latest per (target, module)
    latest: Dict[Tuple[int, str], ScanResult] = {}
    for r in results:
        key = (r.target_id, r.module_name)
        if key not in latest:
            latest[key] = r

    severity_filter = filters.get("severity")
    output: List[Dict] = []

    for (tid, mod), result in latest.items():
        if not result.data:
            continue
        findings = _normalize_findings(mod, result.data)
        for f in findings:
            if severity_filter and f.get("severity") != severity_filter:
                continue
            output.append({
                "domain": target_map[tid].domain,
                "target_id": tid,
                "finding_title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "module": mod,
            })

    # Sort by severity weight
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    output.sort(key=lambda x: (sev_order.get(x["severity"], 9), x["domain"]))
    return output[:200]  # Cap at 200 results


# ---------------------------------------------------------------------------
# UI page
# ---------------------------------------------------------------------------

@router.get("/ai-assistant", response_class=HTMLResponse)
async def ai_assistant_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    _roles: None = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
    has_ai_insights: bool = Depends(require_feature("ai_insights")),
):
    # Check whether AI is configured so the template can show the right badge
    provider, _, _ = _get_ai_config(session, user)

    # Fetch targets for the prioritization dropdown
    tq = select(Target).where(Target.is_archived == False).order_by(Target.domain)
    if user.tenant_id:
        tq = tq.where(Target.tenant_id == user.tenant_id)
    targets = session.exec(tq).all()

    return templates.TemplateResponse(
        "ai_assistant.html",
        {
            "request": request,
            "user": user,
            "targets": targets,
            "ai_provider": provider or "rule-based",
            "has_ai_insights": has_ai_insights,
        },
    )


# ---------------------------------------------------------------------------
# API: Prioritize Findings
# ---------------------------------------------------------------------------

@router.post("/api/ai/prioritize-findings")
async def prioritize_findings(
    body: PrioritizeRequest,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    findings = _extract_all_findings_for_target(session, body.target_id, user)

    if not findings:
        return JSONResponse({"findings": [], "ai_generated": False, "message": "No findings found for this target."})

    provider, api_key, model = _get_ai_config(session, user)
    ai_generated = False
    prioritized: List[Dict] = []

    lang = body.lang
    if provider:
        system = (
            "You are a senior security analyst. Given a list of security findings, "
            "rank them by combined exploitability and business impact. "
            "For each finding return a JSON object with keys: title (string), severity (string), "
            "module (string), priority_rank (integer, 1=highest priority), "
            "exploitability (integer 1-10), business_impact (integer 1-10), "
            "rationale (one concise sentence). "
            "Return a JSON array ordered by priority_rank ascending. No extra text."
            + _lang_instruction(lang)
        )
        prompt = (
            f"Security findings for analysis ({len(findings)} total):\n"
            + json.dumps(
                [{"title": f["title"], "severity": f["severity"], "module": f["module"]} for f in findings],
                indent=2,
            )
        )
        raw = _call_ai(provider, api_key, model, prompt, system)
        if raw:
            parsed = _extract_json(raw)
            if isinstance(parsed, list) and parsed:
                # Merge module info from original findings by title match
                title_to_module = {f["title"]: f["module"] for f in findings}
                for item in parsed:
                    if isinstance(item, dict):
                        item.setdefault("module", title_to_module.get(item.get("title", ""), ""))
                        item["ai_generated"] = True
                prioritized = parsed
                ai_generated = True

    if not prioritized:
        prioritized = _rule_based_prioritize(findings, lang)

    return JSONResponse({"findings": prioritized, "ai_generated": ai_generated})


# ---------------------------------------------------------------------------
# API: Remediation Assistant
# ---------------------------------------------------------------------------

@router.post("/api/ai/remediate")
async def get_remediation(
    body: RemediateRequest,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    provider, api_key, model = _get_ai_config(session, user)
    ai_generated = False
    result: Dict = {}

    lang = body.lang
    if provider:
        system = (
            "You are a senior security engineer. Provide practical, step-by-step remediation "
            "for the described security finding. Be specific and actionable. "
            "Return ONLY a JSON object with keys: "
            "steps (array of strings, each a numbered action), "
            "estimated_effort (one of: low / medium / high), "
            "references (array of relevant URL strings). No extra text outside the JSON."
            + _lang_instruction(lang)
        )
        prompt = (
            f"Finding title: {body.finding_title}\n"
            f"Severity: {body.severity}\n"
            f"Affected domain: {body.domain}\n"
            f"Description: {body.finding_description or '(none provided)'}\n\n"
            "Provide remediation steps."
        )
        raw = _call_ai(provider, api_key, model, prompt, system)
        if raw:
            parsed = _extract_json(raw)
            if isinstance(parsed, dict) and "steps" in parsed:
                result = parsed
                result["ai_generated"] = True
                ai_generated = True

    if not result:
        result = _rule_based_remediate(body.finding_title, body.finding_description, body.severity, lang)

    # Ensure required keys are present
    result.setdefault("steps", ["Review the finding and apply vendor patches or configuration hardening."])
    result.setdefault("estimated_effort", "medium")
    result.setdefault("references", ["https://owasp.org/www-project-top-ten/"])
    result.setdefault("ai_generated", ai_generated)

    return JSONResponse(result)


# ---------------------------------------------------------------------------
# API: Natural Language Search
# ---------------------------------------------------------------------------

@router.get("/api/ai/nl-search")
async def nl_search(
    q: str = Query(default="", description="Natural language search query"),
    lang: str = Query(default="en", description="Response language: en or de"),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner", "auditor"])),
):
    if not q.strip():
        empty_msg = "Leere Suchanfrage" if lang.lower().startswith("de") else "Empty query"
        return JSONResponse({"results": [], "query_interpreted": empty_msg, "filters_applied": {}})

    provider, api_key, model = _get_ai_config(session, user)
    filters: Dict = {}
    interpretation: str = ""

    if provider:
        ai_filters = _ai_nl_parse(provider, api_key, model, q, lang)
        if ai_filters:
            filters = ai_filters
            parts = [f"{k}={v}" for k, v in filters.items()]
            if lang.lower().startswith("de"):
                interpretation = "KI-interpretierte Filter: " + (", ".join(parts) if parts else "keine")
            else:
                interpretation = "AI-interpreted filters: " + (", ".join(parts) if parts else "none")

    if not filters:
        filters, interpretation = _rule_based_nl_parse(q, lang)

    results = _apply_filters(session, user, filters)

    return JSONResponse({
        "results": results,
        "query_interpreted": interpretation,
        "filters_applied": filters,
        "total": len(results),
    })


# ---------------------------------------------------------------------------
# API: Finding Explanation (Enterprise)
# Datensparsamkeit: only {finding_type, severity, module} sent to AI.
# No hostnames, IPs, or raw scan data ever leave the server.
# ---------------------------------------------------------------------------

@router.post("/api/ai/explain-finding")
async def explain_finding(
    body: ExplainFindingRequest,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
    _licensed: bool = Depends(require_feature("ai_insights")),
):
    provider, api_key, model = _get_ai_config(session, user)
    lang = body.lang
    result: Dict = {}
    ai_generated = False

    if provider:
        system = (
            "You are a senior application security expert. "
            "Explain the given security finding in clear, non-technical language suitable "
            "for developers and technical managers. "
            "Return ONLY a JSON object with keys: "
            "explanation (2-3 sentences describing what the finding is), "
            "attacker_scenario (1-2 sentences on what an attacker can do), "
            "remediation_hint (1-2 actionable sentences), "
            "references (array of 1-3 relevant URL strings). No extra text outside JSON."
            + _lang_instruction(lang)
        )
        # Datensparsamkeit: never include target domain or raw scan data in the prompt
        prompt = (
            f"Finding type: {body.finding_type}\n"
            f"Severity: {body.severity}\n"
            f"Scanner module: {body.module}\n\n"
            "Explain this security finding."
        )
        raw = _call_ai(provider, api_key, model, prompt, system)
        if raw:
            parsed = _extract_json(raw)
            if isinstance(parsed, dict) and "explanation" in parsed:
                result = parsed
                result["ai_generated"] = True
                ai_generated = True

    if not result:
        result = _rule_based_explain(body.finding_type, body.severity, body.module, lang)

    result.setdefault("explanation", "No explanation available.")
    result.setdefault("attacker_scenario", "")
    result.setdefault("remediation_hint", "")
    result.setdefault("references", [])
    result.setdefault("ai_generated", ai_generated)

    return JSONResponse(result)


# ---------------------------------------------------------------------------
# API: Executive Summary (Enterprise)
# Datensparsamkeit: only aggregated score + finding counts sent to AI.
# Target domain, IPs, and specific scan data are never included.
# ---------------------------------------------------------------------------

@router.post("/api/ai/executive-summary/{target_id}")
async def executive_summary(
    target_id: int,
    body: ExecutiveSummaryRequest,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner", "auditor"])),
    _licensed: bool = Depends(require_feature("ai_insights")),
):
    # Scope check — no domain or hostname returned to AI
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if user.tenant_id and target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Aggregate findings — only counts, no raw data to AI
    all_findings = _extract_all_findings_for_target(session, target_id, user)
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    module_counts: Dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        mod = f.get("module", "unknown")
        module_counts[mod] = module_counts.get(mod, 0) + 1

    top_modules = sorted(module_counts, key=lambda m: module_counts[m], reverse=True)[:5]
    total = len(all_findings)

    # Get latest security score from SecurityTrend
    score_row = session.exec(
        select(SecurityTrend)
        .where(SecurityTrend.target_id == target_id)
        .order_by(SecurityTrend.recorded_at.desc())
    ).first()
    score = int(score_row.score) if score_row and score_row.score is not None else 0

    lang = body.lang
    result: Dict = {}
    ai_generated = False

    provider, api_key, model = _get_ai_config(session, user)
    if provider:
        system = (
            "You are a senior information security consultant. "
            "Write an executive summary for a security assessment, suitable for management presentation. "
            "Return ONLY a JSON object with keys: "
            "summary (3-4 sentence paragraph), "
            "risk_rating (one of: Critical / High / Medium / Low), "
            "key_points (array of 3-4 short bullet strings), "
            "recommended_actions (array of 2-3 short action strings). "
            "No extra text outside JSON."
            + _lang_instruction(lang)
        )
        # Datensparsamkeit: never include target domain or individual finding details
        prompt = (
            f"Security assessment data:\n"
            f"Security Score: {score}/100\n"
            f"Total findings: {total}\n"
            f"By severity: {json.dumps(by_severity)}\n"
            f"Top affected scan modules: {json.dumps(top_modules)}\n\n"
            "Write an executive summary."
        )
        raw = _call_ai(provider, api_key, model, prompt, system)
        if raw:
            parsed = _extract_json(raw)
            if isinstance(parsed, dict) and "summary" in parsed:
                result = parsed
                result["ai_generated"] = True
                ai_generated = True

    if not result:
        result = _rule_based_executive_summary(score, total, by_severity, top_modules, lang)

    result.setdefault("summary", "No summary available.")
    result.setdefault("risk_rating", "Unknown")
    result.setdefault("key_points", [])
    result.setdefault("recommended_actions", [])
    result.setdefault("ai_generated", ai_generated)
    result["score"] = score
    result["total_findings"] = total
    result["by_severity"] = by_severity

    return JSONResponse(result)
