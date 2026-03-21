"""
Cloud Misconfiguration Scanner (Extended) (#26)

Checks for exposed/misconfigured cloud storage and services:
  - AWS S3 (public buckets, ACL misconfig)
  - Google Cloud Storage
  - Azure Blob Storage
  - DigitalOcean Spaces
  - Firebase / GCP App Engine
  - GitHub Pages / Netlify / Vercel / Heroku (shadow IT)
  - Cloudflare R2
  - Generates severity-rated findings
"""

import requests
import logging
from typing import Any, Dict, List, Optional
from yads.core.base import BaseScannerModule


TIMEOUT = 3


class CloudScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "cloud_scanner"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.cloud_scanner")

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        self.logger.info(f"Starting extended Cloud Asset scan for: {target}")

        parts = target.split(".")
        base_name = parts[0]
        if base_name == "www" and len(parts) > 1:
            base_name = parts[1]
        # Safe DNS-friendly name
        safe_target = target.replace(".", "-")

        keywords = [
            "", "backup", "assets", "dev", "staging", "prod", "public",
            "internal", "data", "files", "images", "media", "static",
            "corp", "api", "admin", "uploads", "logs", "archive",
        ]
        separators = ["", "-"]

        candidates = {safe_target, base_name}
        for kw in keywords:
            for sep in separators:
                if kw:
                    candidates.add(f"{base_name}{sep}{kw}")
                    candidates.add(f"{kw}{sep}{base_name}")
                    candidates.add(f"{safe_target}{sep}{kw}")

        candidate_list = sorted(candidates, key=len)[:80]

        assets = []
        findings = []

        # ── Object storage providers ──────────────────────────────────────
        storage_providers = [
            {
                "name": "AWS S3",
                "template": "https://{name}.s3.amazonaws.com",
                "open_codes": [200],
                "exists_codes": [403],
                "not_found_codes": [404],
            },
            {
                "name": "Google Cloud Storage",
                "template": "https://storage.googleapis.com/{name}",
                "open_codes": [200],
                "exists_codes": [403],
                "not_found_codes": [404],
            },
            {
                "name": "Azure Blob Storage",
                "template": "https://{name}.blob.core.windows.net",
                "open_codes": [200],
                "exists_codes": [400, 403],
                "not_found_codes": [404],
            },
            {
                "name": "DigitalOcean Spaces",
                "template": "https://{name}.nyc3.digitaloceanspaces.com",
                "open_codes": [200],
                "exists_codes": [403],
                "not_found_codes": [404],
            },
            {
                "name": "DigitalOcean Spaces (AMS)",
                "template": "https://{name}.ams3.digitaloceanspaces.com",
                "open_codes": [200],
                "exists_codes": [403],
                "not_found_codes": [404],
            },
            {
                "name": "Cloudflare R2",
                "template": "https://{name}.r2.dev",
                "open_codes": [200],
                "exists_codes": [403],
                "not_found_codes": [404],
            },
        ]

        self.logger.info(f"Checking {len(candidate_list)} names across {len(storage_providers)} storage providers...")

        for name in candidate_list:
            if not name or len(name) < 3:
                continue
            for prov in storage_providers:
                url = prov["template"].format(name=name)
                try:
                    resp = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
                    status_code = resp.status_code

                    if status_code in prov["open_codes"]:
                        status = "Public (Open)"
                        severity = "high"
                    elif status_code in prov["exists_codes"]:
                        status = "Protected (Exists)"
                        severity = "info"
                    else:
                        continue

                    asset = {
                        "provider": prov["name"],
                        "bucket_name": name,
                        "url": url,
                        "status": status,
                        "status_code": status_code,
                        "severity": severity,
                    }
                    assets.append(asset)
                    self.logger.info(f"Found {prov['name']} asset: {name} ({status})")

                    if severity in ("high", "critical"):
                        findings.append({
                            "title": f"Public {prov['name']} Bucket: {name}",
                            "description": (
                                f"The cloud storage bucket '{name}' on {prov['name']} is publicly "
                                f"accessible (HTTP {status_code}). This may expose sensitive data. "
                                f"URL: {url}"
                            ),
                            "severity": "high",
                            "url": url,
                            "category": "cloud_exposure",
                        })
                except Exception:
                    pass

        # ── Shadow IT: PaaS / hosting platforms ──────────────────────────
        paas_providers = [
            {"name": "GitHub Pages", "template": "https://{name}.github.io"},
            {"name": "Netlify", "template": "https://{name}.netlify.app"},
            {"name": "Vercel", "template": "https://{name}.vercel.app"},
            {"name": "Heroku", "template": "https://{name}.herokuapp.com"},
            {"name": "Firebase Hosting", "template": "https://{name}.web.app"},
            {"name": "Firebase (Appspot)", "template": "https://{name}.appspot.com"},
            {"name": "Render", "template": "https://{name}.onrender.com"},
            {"name": "Railway", "template": "https://{name}.up.railway.app"},
            {"name": "Fly.io", "template": "https://{name}.fly.dev"},
        ]

        # Check only high-value names (base name + a few variants) for PaaS
        paas_candidates = [base_name, safe_target, f"{base_name}-app", f"{base_name}-api"]

        self.logger.info(f"Checking {len(paas_candidates)} names across {len(paas_providers)} PaaS providers...")
        for name in paas_candidates:
            for prov in paas_providers:
                url = prov["template"].format(name=name)
                try:
                    resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
                    # 200/301/302 = active site
                    if resp.status_code in (200, 301, 302, 307, 308):
                        # Exclude "default" pages (Netlify/Heroku default error pages)
                        body_sample = resp.text[:500].lower() if hasattr(resp, "text") else ""
                        is_default = any(x in body_sample for x in [
                            "there's nothing here", "site not found", "no such app",
                            "we couldn't find", "not deployed",
                        ])
                        if not is_default:
                            assets.append({
                                "provider": prov["name"],
                                "bucket_name": name,
                                "url": url,
                                "status": "Active Hosting",
                                "status_code": resp.status_code,
                                "severity": "info",
                            })
                            findings.append({
                                "title": f"Shadow IT: {prov['name']} hosting detected — {name}",
                                "description": (
                                    f"An active site was found at {url} on {prov['name']}. "
                                    "This may indicate shadow IT or untracked infrastructure "
                                    "associated with your domain."
                                ),
                                "severity": "low",
                                "url": url,
                                "category": "shadow_it",
                            })
                            self.logger.info(f"Found {prov['name']} active: {url}")
                except Exception:
                    pass

        # ── Summary ──────────────────────────────────────────────────────
        open_buckets = [a for a in assets if a["status"] == "Public (Open)"]
        existing_buckets = [a for a in assets if a["status"] == "Protected (Exists)"]
        shadow_it = [a for a in assets if a["status"] == "Active Hosting"]

        summary = {
            "total_assets_found": len(assets),
            "open_buckets": len(open_buckets),
            "protected_buckets": len(existing_buckets),
            "shadow_it_detected": len(shadow_it),
            "findings_count": len(findings),
        }

        self.logger.info(
            f"Cloud scan complete: {len(assets)} assets found "
            f"({len(open_buckets)} open, {len(existing_buckets)} protected, "
            f"{len(shadow_it)} shadow IT)"
        )

        # Persist public buckets to OSINTIntelligence model
        if target_id and self.db:
            from yads.models import OSINTIntelligence
            import datetime
            for bucket in open_buckets:
                bucket_name = bucket["bucket_name"]
                existing = self.db.query(OSINTIntelligence).filter_by(
                    target_id=target_id, module_name=self.module_name, data_type="cloud_exposure"
                ).filter(OSINTIntelligence.data_json["url"].astext == bucket["url"]).first()
                if not existing:
                    self.db.add(OSINTIntelligence(
                        target_id=target_id, module_name=self.module_name, data_type="cloud_exposure",
                        data_json={"bucket_name": bucket_name, "provider": bucket["provider"], "url": bucket["url"]},
                        severity=bucket["severity"], timestamp=datetime.datetime.utcnow()
                    ))
            try:
                self.db.commit()
            except Exception as e:
                self.logger.error(f"[CloudScanner] DB Commit failed: {e}")
                self.db.rollback()

        return {
            "assets": assets,
            "findings": findings,
            "summary": summary,
        }
