"""
Finding -> real MITRE ATT&CK (Enterprise) technique mapping.

`SecurityAuditLog.mitre_tactic_id`/`mitre_technique_id` already exist but are
wired only to internal audit events (login, password change). This module
maps scan *findings* (module + issue text) to real TAxxxx/Txxxx IDs, used to
populate `SecurityFinding.mitre_tactic_id/mitre_technique_id/mitre_technique_name`
at upsert time (see `_upsert_findings` in api/routers/security_findings.py)
and to feed the ATT&CK Navigator heatmap and exploit-chaining logic.

Matching is deliberately simple (module name -> pattern -> technique) rather
than a full CVE->CAPEC->ATT&CK pipeline. It's precise enough for the common,
recurring finding types our own scanner modules produce; anything unmapped
returns None rather than a guessed phase (the previous behavior in
attack_path.py's `_att_phase_for_finding`, which this is meant to replace).

Rule format: (module_name, issue_substring_lowercase, tactic_id, technique_id, technique_name)
First matching rule wins. `issue_substring` "" matches any issue for that module.
"""
from typing import Optional, TypedDict


class MitreMatch(TypedDict):
    tactic_id: str
    technique_id: str
    technique_name: str


# Tactic IDs (MITRE ATT&CK Enterprise, for reference):
# TA0043 Reconnaissance, TA0042 Resource Development, TA0001 Initial Access,
# TA0002 Execution, TA0003 Persistence, TA0004 Privilege Escalation,
# TA0005 Defense Evasion, TA0006 Credential Access, TA0007 Discovery,
# TA0009 Collection, TA0011 Command and Control, TA0040 Impact

_RULES: list[tuple[str, str, str, str, str]] = [
    # Subdomain takeover -> Initial Access via unclaimed infrastructure
    ("subdomain_takeover_scanner", "", "TA0001", "T1584.001", "Compromise Infrastructure: Domains"),
    # SSL/TLS weaknesses -> Adversary-in-the-Middle exposure
    ("ssl_scanner", "expired", "TA0006", "T1557", "Adversary-in-the-Middle"),
    ("ssl_scanner", "weak", "TA0006", "T1557", "Adversary-in-the-Middle"),
    ("tls_deep_scanner", "", "TA0006", "T1557", "Adversary-in-the-Middle"),
    # Nuclei CVE/RCE-style findings -> Initial Access via public-facing app exploit
    ("nuclei_scanner", "rce", "TA0001", "T1190", "Exploit Public-Facing Application"),
    ("nuclei_scanner", "sqli", "TA0001", "T1190", "Exploit Public-Facing Application"),
    ("nuclei_scanner", "injection", "TA0001", "T1190", "Exploit Public-Facing Application"),
    ("nuclei_scanner", "cve", "TA0001", "T1190", "Exploit Public-Facing Application"),
    ("cve_lookup", "", "TA0001", "T1190", "Exploit Public-Facing Application"),
    # Exposed .git / secrets in JS -> Credential Access via public source repo/artifacts
    ("git_exposure_scanner", "", "TA0006", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    ("js_secrets_scanner", "", "TA0006", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    ("seed_files_scanner", "", "TA0006", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    # Leaked credentials / breach data -> Credential Access via breach dumps
    ("leaked_credentials", "", "TA0006", "T1589.001", "Gather Victim Identity Information: Credentials"),
    ("leak_monitor", "", "TA0006", "T1589.001", "Gather Victim Identity Information: Credentials"),
    # Login form / brute force / password spray -> Credential Access via brute force
    ("password_spray_mapper", "", "TA0006", "T1110.003", "Brute Force: Password Spraying"),
    ("login_scanner", "no mfa", "TA0006", "T1110", "Brute Force"),
    ("login_scanner", "lockout", "TA0006", "T1110", "Brute Force"),
    # Open S3/cloud buckets -> Collection via cloud storage
    ("cloud_scanner", "", "TA0009", "T1530", "Data from Cloud Storage"),
    # Dependency confusion -> Initial Access via supply chain compromise
    ("dependency_confusion", "", "TA0001", "T1195.001", "Supply Chain Compromise: Compromise Software Dependencies"),
    # Open redirect / CORS / CSP misconfig -> Defense Evasion / phishing enablement
    ("open_redirect_scanner", "", "TA0001", "T1566.002", "Phishing: Spearphishing Link"),
    ("cors_scanner", "", "TA0006", "T1557", "Adversary-in-the-Middle"),
    ("csp_scanner", "", "TA0005", "T1055", "Process Injection"),  # XSS-adjacent, coarse
    # WAF absent/bypassed -> Defense Evasion
    ("waf_detector", "", "TA0005", "T1090", "Proxy"),
    # DNS zone transfer / AXFR -> Reconnaissance / Discovery
    ("axfr_scanner", "", "TA0043", "T1590.002", "Gather Victim Network Information: DNS"),
    ("dns_history_scanner", "", "TA0043", "T1590.002", "Gather Victim Network Information: DNS"),
    ("whois_history_scanner", "", "TA0043", "T1590.001", "Gather Victim Network Information: Domain Properties"),
    # Typosquat / phishing / brand -> Resource Development (attacker side) — flag as risk to brand
    ("typosquat_scanner", "", "TA0042", "T1583.001", "Acquire Infrastructure: Domains"),
    ("phishing_scanner", "", "TA0042", "T1583.001", "Acquire Infrastructure: Domains"),
    # RPKI/BGP -> Impact (network hijack)
    ("rpki_scanner", "", "TA0040", "T1498", "Network Denial of Service"),  # coarse: route hijack impact
    # GraphQL / WebSocket / API discovery -> Discovery of exotic API surface
    ("graphql_scanner", "", "TA0007", "T1590", "Gather Victim Network Information"),
    ("websocket_scanner", "", "TA0007", "T1590", "Gather Victim Network Information"),
    ("api_discovery", "", "TA0007", "T1590", "Gather Victim Network Information"),
]


def get_mitre_mapping(module: str, issue: str = "") -> Optional[MitreMatch]:
    """
    Look up the best-matching MITRE technique for a finding.
    `module` should be the scanner module_name (e.g. "nuclei_scanner").
    `issue` is free-text finding description, matched case-insensitively.
    Returns None if no rule matches (do not guess).
    """
    module = (module or "").lower()
    issue_lower = (issue or "").lower()

    best: Optional[MitreMatch] = None
    for rule_module, pattern, tactic_id, technique_id, technique_name in _RULES:
        if rule_module != module:
            continue
        if pattern and pattern not in issue_lower:
            continue
        match: MitreMatch = {
            "tactic_id": tactic_id,
            "technique_id": technique_id,
            "technique_name": technique_name,
        }
        if pattern:
            return match  # specific pattern match wins immediately
        best = best or match  # fallback: module-wide rule (pattern == "")
    return best


# Full MITRE ATT&CK Enterprise tactic list (id -> display name), in kill-chain
# order — used by the ATT&CK Navigator heatmap (#52) so every tactic column
# renders even if this tenant currently has zero findings in it.
TACTIC_NAMES: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}
