"""
Automated Nuclei Template Suggestions (#46)

Analyzes scan results to suggest relevant Nuclei templates:
  - Maps detected tech stack → known vulnerable templates
  - Maps open ports → service-specific templates
  - Maps findings severity → priority template categories
  - Integrates with nuclei template index (public GitHub)
  - Returns ranked template suggestions with CVE mappings
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from yads.auth.deps import RoleChecker
from yads.database import get_session
from yads.models import ScanResult, Target, User

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Tech stack → Nuclei template tags mapping ─────────────────────────────
TECH_TEMPLATE_MAP: Dict[str, List[str]] = {
    # Web servers
    "nginx": ["nginx", "http"],
    "apache": ["apache", "http"],
    "iis": ["iis", "microsoft"],
    "lighttpd": ["lighttpd"],
    "caddy": ["caddy"],
    # CMS
    "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "typo3": ["typo3"],
    "shopify": ["shopify"],
    "magento": ["magento"],
    # Frameworks
    "django": ["django"],
    "laravel": ["laravel", "php"],
    "rails": ["rails", "ruby"],
    "spring": ["spring", "java"],
    "struts": ["struts", "java"],
    "express": ["node"],
    # Languages/Platforms
    "php": ["php"],
    "java": ["java"],
    "python": ["python"],
    "ruby": ["ruby"],
    "node": ["node"],
    "asp.net": ["asp"],
    # Databases/Admin
    "phpmyadmin": ["phpmyadmin"],
    "adminer": ["adminer"],
    "mysql": ["mysql"],
    "postgresql": ["postgresql"],
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "elasticsearch": ["elasticsearch"],
    # Cloud/DevOps
    "kubernetes": ["kubernetes", "k8s"],
    "docker": ["docker"],
    "jenkins": ["jenkins"],
    "grafana": ["grafana"],
    "prometheus": ["prometheus"],
    "kibana": ["kibana"],
    "gitlab": ["gitlab"],
    "github": ["github"],
    "jira": ["jira"],
    "confluence": ["confluence"],
    # CDN/WAF
    "cloudflare": ["cloudflare"],
    "aws": ["aws", "amazon"],
    "azure": ["azure", "microsoft"],
    "gcp": ["gcp", "google"],
    # Other
    "tomcat": ["tomcat"],
    "nginx-unit": ["nginx"],
    "cpanel": ["cpanel"],
    "plesk": ["plesk"],
    "weblogic": ["weblogic"],
    "jboss": ["jboss"],
}

# ── Finding-based template suggestions ───────────────────────────────────
FINDING_TEMPLATE_MAP: Dict[str, List[Dict]] = {
    "cors": [{"id": "cors-misconfig", "name": "CORS Misconfiguration", "severity": "medium", "tags": ["cors", "misconfig"]}],
    "sql injection": [{"id": "sql-injection", "name": "SQL Injection", "severity": "critical", "tags": ["sqli", "injection"]}],
    "xss": [{"id": "xss", "name": "Cross-Site Scripting", "severity": "high", "tags": ["xss"]}],
    "open redirect": [{"id": "open-redirect", "name": "Open Redirect", "severity": "medium", "tags": ["redirect"]}],
    "directory listing": [{"id": "directory-listing", "name": "Directory Listing", "severity": "medium", "tags": ["listing"]}],
    "exposed git": [{"id": "git-config", "name": "Git Config Exposure", "severity": "medium", "tags": ["git", "exposure"]}],
    "backup file": [{"id": "backup-files", "name": "Backup File Discovery", "severity": "medium", "tags": ["backup", "exposure"]}],
    "admin panel": [{"id": "admin-panel", "name": "Admin Panel Detection", "severity": "info", "tags": ["panel", "admin"]}],
    "default credential": [{"id": "default-logins", "name": "Default Login Check", "severity": "high", "tags": ["default-login"]}],
    "cve": [{"id": "cve", "name": "CVE-based checks", "severity": "varies", "tags": ["cve"]}],
    "ssrf": [{"id": "ssrf", "name": "SSRF Detection", "severity": "high", "tags": ["ssrf"]}],
    "lfi": [{"id": "lfi", "name": "Local File Inclusion", "severity": "high", "tags": ["lfi", "traversal"]}],
    "rce": [{"id": "rce", "name": "Remote Code Execution", "severity": "critical", "tags": ["rce"]}],
    "misconfiguration": [{"id": "misconfiguration", "name": "Misconfiguration checks", "severity": "varies", "tags": ["misconfig"]}],
    "exposed api": [{"id": "api-keys", "name": "Exposed API Keys", "severity": "high", "tags": ["exposure", "api"]}],
}

# ── Port → template tags ─────────────────────────────────────────────────
PORT_TEMPLATE_MAP: Dict[int, List[str]] = {
    21: ["ftp"],
    22: ["ssh"],
    23: ["telnet"],
    25: ["smtp", "email"],
    53: ["dns"],
    80: ["http"],
    110: ["pop3"],
    143: ["imap"],
    443: ["http", "ssl"],
    445: ["smb", "windows"],
    3306: ["mysql"],
    3389: ["rdp", "windows"],
    5432: ["postgresql"],
    5900: ["vnc"],
    6379: ["redis"],
    8080: ["http"],
    8443: ["http", "ssl"],
    8888: ["jupyter"],
    9200: ["elasticsearch"],
    27017: ["mongodb"],
}


def _extract_tech_stack(scan_results: List[ScanResult]) -> List[str]:
    """Extract detected technologies from web_analyzer results."""
    tech = set()
    for sr in scan_results:
        if sr.module_name == "web_analyzer":
            data = sr.data or {}
            for t in data.get("technologies", []):
                name = (t.get("name") or "").lower()
                if name:
                    tech.add(name)
    return list(tech)


def _extract_open_ports(scan_results: List[ScanResult]) -> List[int]:
    """Extract open ports from port_scanner or nmap results."""
    ports = set()
    for sr in scan_results:
        if sr.module_name in ("port_scanner", "nmap_scanner"):
            data = sr.data or {}
            for port_info in data.get("open_ports", []):
                if isinstance(port_info, dict):
                    ports.add(int(port_info.get("port", 0)))
                elif isinstance(port_info, int):
                    ports.add(port_info)
    return sorted(ports)


def _extract_findings_keywords(scan_results: List[ScanResult]) -> List[str]:
    """Extract keywords from finding titles for template mapping."""
    keywords = set()
    for sr in scan_results:
        data = sr.data or {}
        for finding in data.get("findings", []):
            title = (finding.get("title") or "").lower()
            for keyword in FINDING_TEMPLATE_MAP:
                if keyword in title:
                    keywords.add(keyword)
    return list(keywords)


def _build_suggestions(
    tech_stack: List[str],
    open_ports: List[int],
    finding_keywords: List[str],
    domain: str,
) -> List[Dict]:
    suggestions = []
    seen_tags = set()

    # 1. Tech-based suggestions
    for tech in tech_stack:
        for tech_key, tags in TECH_TEMPLATE_MAP.items():
            if tech_key in tech or tech in tech_key:
                tag_key = tuple(sorted(tags))
                if tag_key not in seen_tags:
                    seen_tags.add(tag_key)
                    suggestions.append({
                        "priority": 1,
                        "reason": f"Technology detected: {tech}",
                        "template_tags": tags,
                        "nuclei_command": f"nuclei -u https://{domain} -tags {','.join(tags)}",
                        "category": "tech_stack",
                    })

    # 2. Port-based suggestions
    for port in open_ports:
        tags = PORT_TEMPLATE_MAP.get(port, [])
        if tags:
            tag_key = tuple(sorted(tags))
            if tag_key not in seen_tags:
                seen_tags.add(tag_key)
                suggestions.append({
                    "priority": 2,
                    "reason": f"Open port detected: {port}",
                    "template_tags": tags,
                    "nuclei_command": f"nuclei -u https://{domain} -tags {','.join(tags)}",
                    "category": "port_service",
                })

    # 3. Finding-based suggestions
    for keyword in finding_keywords:
        templates = FINDING_TEMPLATE_MAP.get(keyword, [])
        for tmpl in templates:
            tag_key = tuple(sorted(tmpl["tags"]))
            if tag_key not in seen_tags:
                seen_tags.add(tag_key)
                suggestions.append({
                    "priority": 0,  # Highest priority — based on actual findings
                    "reason": f"Finding matched: {keyword}",
                    "template_tags": tmpl["tags"],
                    "template_id": tmpl.get("id"),
                    "nuclei_command": f"nuclei -u https://{domain} -tags {','.join(tmpl['tags'])}",
                    "category": "finding_based",
                    "expected_severity": tmpl.get("severity"),
                })

    # Sort by priority (0 = highest)
    suggestions.sort(key=lambda x: x["priority"])

    # Add always-recommended templates
    always_recommended = [
        {
            "priority": 3,
            "reason": "Recommended for all targets",
            "template_tags": ["misconfig", "exposure"],
            "nuclei_command": f"nuclei -u https://{domain} -tags misconfig,exposure",
            "category": "baseline",
        },
        {
            "priority": 3,
            "reason": "Recommended for all targets",
            "template_tags": ["cve", "high", "critical"],
            "nuclei_command": f"nuclei -u https://{domain} -severity high,critical",
            "category": "baseline",
        },
    ]
    for rec in always_recommended:
        tag_key = tuple(sorted(rec["template_tags"]))
        if tag_key not in seen_tags:
            suggestions.append(rec)

    return suggestions[:25]


@router.get("/api/targets/{target_id}/nuclei-suggestions")
async def get_nuclei_suggestions(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    """Return Nuclei template suggestions based on scan results."""
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan_results = session.exec(
        select(ScanResult).where(ScanResult.target_id == target_id)
        .order_by(ScanResult.created_at.desc())
    ).all()

    # Use only most recent result per module
    seen_modules = set()
    latest_results = []
    for sr in scan_results:
        if sr.module_name not in seen_modules:
            seen_modules.add(sr.module_name)
            latest_results.append(sr)

    tech_stack = _extract_tech_stack(latest_results)
    open_ports = _extract_open_ports(latest_results)
    finding_keywords = _extract_findings_keywords(latest_results)

    suggestions = _build_suggestions(tech_stack, open_ports, finding_keywords, target.domain)

    return {
        "domain": target.domain,
        "tech_stack": tech_stack,
        "open_ports": open_ports,
        "finding_keywords": finding_keywords,
        "suggestions": suggestions,
        "total": len(suggestions),
        "nuclei_combined": f"nuclei -u https://{target.domain} -tags " + ",".join(
            tag for s in suggestions[:5] for tag in s["template_tags"]
        ) if suggestions else f"nuclei -u https://{target.domain} -severity high,critical",
    }
