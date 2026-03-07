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
from yads.models import ScanResult, SystemConfig, Target, Tenant, User

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
