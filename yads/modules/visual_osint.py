import logging
import os
import shutil
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
import requests
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False
try:
    from PIL import Image
    import imagehash
    import mmh3
    _VISUAL_DEPS_AVAILABLE = True
except ImportError:
    _VISUAL_DEPS_AVAILABLE = False
import base64
import codecs

from yads.core.base import BaseScannerModule
from yads.config import settings

class VisualOSINT(BaseScannerModule):
    """
    Visual Regression & Defacement Monitor.
    - Captures screenshots using Playwright (Headless Chromium).
    - Compares current screenshot against a baseline using dHash (Difference Hash).
    - Alerts on significant visual deviations (Defacement / Broken UI).
    """
    @property
    def module_name(self) -> str:
        return "visual_osint"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.visual_osint")
        self.screenshot_dir = os.path.join(settings.STATIC_DIR, "screenshots")
        os.makedirs(self.screenshot_dir, exist_ok=True)

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Executes the visual scan.
        """
        self.logger.info(f"Starting Visual Regression scan for: {target}")
        
        timestamp = int(datetime.utcnow().timestamp())
        # Sanitized filename
        safe_target = target.replace(":", "_").replace("/", "_")
        filename = f"{safe_target}_{timestamp}.png"
        filepath = os.path.join(self.screenshot_dir, filename)
        
        # 1. Capture Screenshot
        captured = self._capture_screenshot(target, filepath)
        
        results = {
            "logos": [], # Kept for backward compatibility if needed, or we can fetch them too
            "screenshot_path": filename if captured else None,
            "baseline_path": None,
            "diff_score": 0,
            "diff_score": 0,
            "is_defaced": False,
            "favicon_hash": None,
            "status": "success" if captured else "failed"
        }

        if not captured:
            self.logger.error("Screenshot capture failed.")
            return results

        # 2. Baseline Comparison
        baseline_file = self._get_baseline(safe_target)
        
        if baseline_file:
            self.logger.info(f"Comparing against baseline: {baseline_file}")
            results["baseline_path"] = baseline_file
            
            diff_score = self._compare_images(
                os.path.join(self.screenshot_dir, baseline_file),
                filepath
            )
            results["diff_score"] = diff_score
            
            # Threshold: dHash 0-10 is very similar. > 20 is significant change.
            if diff_score > 15:
                self.logger.warning(f"Visual deviation detected! Score: {diff_score}")
                results["is_defaced"] = True
            else:
                self.logger.info(f"Visual check passed. Score: {diff_score}")
        else:
            self.logger.info("No baseline found. Setting current as baseline.")
            self._set_baseline(safe_target, filename)
            results["baseline_path"] = filename

        # 3. Fetch Logos (Legacy/Extra)
        # We can keep the old lightweight logic or disable it. 
        # Let's run it quickly as it adds value (Favicons).
        results["logos"] = self._fetch_logos(target)
        
        # 4. Calculate Favicon Hash (MurmurHash for Shodan)
        # We try HTTP/HTTPS root favicon first
        results["favicon_hash"] = self._calculate_favicon_hash(f"https://{target}")
        if not results["favicon_hash"]:
             results["favicon_hash"] = self._calculate_favicon_hash(f"http://{target}")
        
        return results

    def _capture_screenshot(self, target: str, output_path: str) -> bool:
        """
        Captures a screenshot using Playwright.
        """
        try:
            if not _PLAYWRIGHT_AVAILABLE:
                logger.error("Playwright not available in this environment")
                return False
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
                )
                try:
                    context = browser.new_context(viewport={'width': 1280, 'height': 800})
                    page = context.new_page()

                    captured = False
                    for scheme in ("https", "http"):
                        url = f"{scheme}://{target}"
                        self.logger.info(f"Trying {url} ...")
                        try:
                            page.goto(url, timeout=15000, wait_until="load")
                            captured = True
                            break
                        except Exception as e:
                            self.logger.warning(f"{scheme.upper()} failed: {e}")

                    if not captured:
                        return False

                    page.screenshot(path=output_path, full_page=True)
                    return True
                finally:
                    try:
                        context.close()
                    except Exception:
                        pass
                    browser.close()

        except Exception as e:
            self.logger.error(f"Playwright error: {e}")
            return False

    def _compare_images(self, path_a: str, path_b: str) -> int:
        """
        Computes the hamming distance between dHash of two images.
        0 = Identical
        > 10 = Changed
        """
        if not _VISUAL_DEPS_AVAILABLE:
            self.logger.error("PIL/imagehash not available — image comparison disabled.")
            return 999
        try:
            hash_a = imagehash.dhash(Image.open(path_a))
            hash_b = imagehash.dhash(Image.open(path_b))
            # Convert to native Python int to avoid JSON serialization issues with numpy.int64
            return int(hash_a - hash_b)
        except Exception as e:
            self.logger.error(f"Image comparison failed: {e}")
            return 999 # Error score

    def _get_baseline(self, safe_target: str) -> Optional[str]:
        """
        Finds the baseline screenshot for a target.
        In a real app, this should be stored in the DB (Target.baseline_screenshot).
        For now, we look for a file suffix or local state file.
        Let's assume we store it in a simple JSON map or look for 'baseline' file pattern.
        
        Simple approach: Look for {safe_target}_baseline.png
        """
        baseline_name = f"{safe_target}_baseline.png"
        baseline_path = os.path.join(self.screenshot_dir, baseline_name)
        if os.path.exists(baseline_path):
            return baseline_name
        return None

    def _set_baseline(self, safe_target: str, current_filename: str):
        """
        Sets the current screenshot as new baseline.
        """
        src = os.path.join(self.screenshot_dir, current_filename)
        dst = os.path.join(self.screenshot_dir, f"{safe_target}_baseline.png")
        try:
            shutil.copy2(src, dst)
        except Exception as e:
            self.logger.error(f"Failed to set baseline: {e}")

    def _fetch_logos(self, target: str) -> List[Dict]:
        """
        Original lightweight logic for favicons.
        """
        logos = []
        sources = [
             {"name": "Google", "url": f"https://www.google.com/s2/favicons?domain={target}&sz=128", "type": "favicon"},
             {"name": "Clearbit", "url": f"https://logo.clearbit.com/{target}", "type": "logo"}
        ]
        for s in sources:
            try:
                r = requests.head(s["url"], timeout=3)
                if r.status_code == 200:
                    logos.append(s)
            except Exception as e:
                self.logger.debug(f"Failed to check logo source {s['url']}: {e}")
        return logos

    def _calculate_favicon_hash(self, base_url: str) -> Optional[int]:
        """
        Calculates the MurmurHash3 of the favicon for Shodan pivots.
        Method: 
        1. GET /favicon.ico
        2. Base64 Encode content
        3. Insert newlines every 76 chars (standard MIME/PEM format)
        4. Calculate mmh3 hash
        """
        if not _VISUAL_DEPS_AVAILABLE:
            return None
        favicon_url = f"{base_url.rstrip('/')}/favicon.ico"
        try:
            r = requests.get(favicon_url, timeout=5, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
            if r.status_code == 200 and len(r.content) > 0:
                # Shodan Hashing Algorithm:
                # 1. Base64
                b64 = base64.encodebytes(r.content) # encodebytes adds newlines
                # but mmh3 expects string or bytes.
                # Shodan uses: mmh3.hash(codecs.encode(response.content, 'base64'))
                # which adds newlines automatically.
                
                # Using the standard shodan approach:
                encoded = codecs.encode(r.content, "base64") 
                # This returns the b64 with newlines
                
                favicon_hash = mmh3.hash(encoded)
                self.logger.info(f"Favicon Hash for {base_url}: {favicon_hash}")
                return favicon_hash
        except Exception as e:
            self.logger.debug(f"Favicon hash calculation failed for {favicon_url}: {e}")
        return None
