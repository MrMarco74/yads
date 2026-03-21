"""
Tech Stack Analyzer

Passively identifies technologies, frameworks, CMS, and servers running on the target.
Uses HTTP Response Headers, Meta Tags, and Script Tags.
Creates a robust technology footprint to easily spot outdated software.
"""

import logging
import re
from typing import Any, Dict, Optional
import requests
from bs4 import BeautifulSoup

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

class TechStackAnalyzer(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "tech_stack_analyzer"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "technologies": [],
            "findings": [],
            "summary": {
                "score": 100
            }
        }
        
        target_url = target if target.startswith("http") else f"https://{target}"
        
        # Signatures dictionary mapping tech to identification patterns
        signatures = {
            "WordPress": {"headers": {}, "meta": {"generator": r"WordPress"}, "body": r"wp-content|wp-includes"},
            "Joomla": {"headers": {}, "meta": {"generator": r"Joomla"}, "body": r"joomla"},
            "Drupal": {"headers": {"x-generator": r"Drupal"}, "meta": {"generator": r"Drupal"}, "body": r"sites/default/files"},
            "React": {"headers": {}, "meta": {}, "body": r"react-dom\.production|data-reactroot|_reactRoot"},
            "Next.js": {"headers": {"x-powered-by": r"Next\.js"}, "meta": {}, "body": r"__NEXT_DATA__|_next/static"},
            "Vue.js": {"headers": {}, "meta": {}, "body": r"data-v-|__VUE__"},
            "Nuxt.js": {"headers": {}, "meta": {}, "body": r"__NUXT__"},
            "Angular": {"headers": {}, "meta": {}, "body": r"ng-version|ng-app"},
            "PHP": {"headers": {"x-powered-by": r"PHP/?([0-9.]+)?", "server": r"PHP/?([0-9.]+)?"}, "meta": {}, "body": r"\.php"},
            "Express": {"headers": {"x-powered-by": r"Express"}, "meta": {}, "body": r""},
            "Laravel": {"headers": {"set-cookie": r"laravel_session"}, "meta": {}, "body": r""},
            "Apache": {"headers": {"server": r"Apache/?([0-9a-zA-Z.]+)?", "x-powered-by": r"Apache"}, "meta": {}, "body": r""},
            "Nginx": {"headers": {"server": r"nginx/?([0-9a-zA-Z.]+)?", "x-powered-by": r"nginx"}, "meta": {}, "body": r""},
            "Cloudflare": {"headers": {"server": r"cloudflare", "cf-ray": r".*"}, "meta": {}, "body": r""},
            "Google Analytics": {"headers": {}, "meta": {}, "body": r"google-analytics\.com/analytics\.js|googletagmanager\.com/gtag/js"},
            "jQuery": {"headers": {}, "meta": {}, "body": r"jquery[.-]?([0-9.]+)?\.js"},
            "Bootstrap": {"headers": {}, "meta": {}, "body": r"bootstrap[.-]?([0-9.]+)?\.css|bootstrap[.-]?([0-9.]+)?\.js"},
            "Tailwind CSS": {"headers": {}, "meta": {}, "body": r"tailwind"},
        }

        detected_techs = []
        
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 YADS/1.0"}
            response = requests.get(target_url, headers=headers, timeout=12, allow_redirects=True)
            text_body = response.text
            lower_headers = {k.lower(): v for k, v in response.headers.items()}
            
            soup = BeautifulSoup(text_body, "html.parser")
            meta_tags = soup.find_all("meta")
            
            meta_dict = {}
            for tag in meta_tags:
                name = tag.get("name") or tag.get("property")
                content = tag.get("content")
                if name and content:
                    meta_dict[name.lower()] = content

            # Signature Matching
            for tech_name, sig in signatures.items():
                matched = False
                version = None
                
                # Check headers
                for h_key, h_regex in sig["headers"].items():
                    if h_key in lower_headers:
                        match = re.search(h_regex, lower_headers[h_key], re.IGNORECASE)
                        if match:
                            matched = True
                            if len(match.groups()) > 0 and match.group(1):
                                version = match.group(1)
                
                # Check meta tags
                if not matched:
                    for m_key, m_regex in sig["meta"].items():
                        if m_key in meta_dict:
                            match = re.search(m_regex, meta_dict[m_key], re.IGNORECASE)
                            if match:
                                matched = True
                
                # Check body content
                if not matched and sig["body"]:
                    match = re.search(sig["body"], text_body, re.IGNORECASE)
                    if match:
                        matched = True
                        if len(match.groups()) > 0 and match.group(1):
                            version = match.group(1)
                            
                if matched:
                    detected_techs.append({
                        "name": tech_name,
                        "version": version or "Unknown",
                    })

            result["technologies"] = detected_techs
            
            # DB Persistence
            if target_id and detected_techs:
                from yads.models import OSINTIntelligence
                existing_stack = self.db.query(OSINTIntelligence).filter_by(
                    target_id=target_id, module_name=self.module_name, data_type="tech_stack"
                ).all()
                seen = {f"{r.data_json.get('name')}_{r.data_json.get('version')}" for r in existing_stack}
                
                for tech in detected_techs:
                    key = f"{tech.get('name')}_{tech.get('version')}"
                    if key not in seen:
                        self.db.add(OSINTIntelligence(
                            target_id=target_id,
                            module_name=self.module_name,
                            data_type="tech_stack",
                            data_json=tech,
                            severity="info"
                        ))
                        seen.add(key)
                        
            # Identify findings
            versions_leaked = [t["name"] for t in detected_techs if t["version"] and t["version"] != "Unknown"]
            if versions_leaked:
                result["findings"].append({
                    "severity": "info",
                    "title": "Software Versions Disclosed",
                    "description": f"The target discloses the exact version of: {', '.join(versions_leaked)}. While not necessarily a vulnerability, version disclosure greatly aids attackers in finding precise exploits."
                })
                result["summary"]["score"] -= 5

        except Exception as e:
            logger.debug(f"Tech stack analysis failed for {target_url}: {e}")
            result["error"] = str(e)

        return result
