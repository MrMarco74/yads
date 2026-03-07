import requests
import imagehash
from PIL import Image
from io import BytesIO
import logging
from typing import List, Dict, Any, Optional

class BrandMonitor:
    def __init__(self):
        self.logger = logging.getLogger("yads.modules.brand_monitor")

    def _fetch_image(self, url: str) -> Optional[Image.Image]:
        try:
            # Fake user agent to avoid blocking
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 YADS/1.19"
            }
            resp = requests.get(url, headers=headers, timeout=5, stream=True)
            if resp.status_code == 200:
                img = Image.open(BytesIO(resp.content))
                # Convert to RGB to handle alpha channels/palettes for hashing
                return img.convert("RGB")
        except Exception as e:
            self.logger.debug(f"Failed to fetch image {url}: {e}")
        return None

    def _make_square(self, img: Image.Image) -> Image.Image:
        """
        Pads the image with white background to make it square.
        """
        if img.width == img.height:
            return img
            
        size = max(img.width, img.height)
        new_img = Image.new("RGB", (size, size), (255, 255, 255))
        
        left = (size - img.width) // 2
        top = (size - img.height) // 2
        
        new_img.paste(img, (left, top))
        return new_img

    def compute_phash(self, img: Image.Image):
        # Normalize to square to preserve aspect ratio features during hash resize
        sq_img = self._make_square(img)
        return imagehash.phash(sq_img)

    def compare_images_by_url(self, url1: str, url2: str) -> Dict[str, Any]:
        """
        Downloads two images and compares them.
        Returns:
            {
                "match": bool,
                "score": float (0.0 to 1.0, 1.0 being identical),
                "distance": int
            }
        """
        img1 = self._fetch_image(url1)
        if not img1:
            return {"error": "Could not fetch reference image"}
        
        img2 = self._fetch_image(url2)
        if not img2:
            return {"error": "Could not fetch candidate image"}

        h1 = self.compute_phash(img1)
        h2 = self.compute_phash(img2)
        
        # Hamming distance: 0 = identical
        # Typically < 10 is similar for pHash (64-bit)
        distance = h1 - h2
        
        # Normalize to score (heuristic)
        # Max distance ~64. 
        score = max(0, (64 - distance) / 64)
        
        return {
            "match": distance <= 10, # Threshold
            "score": score,
            "distance": distance
        }

    def hunt_lookalikes(self, reference_logo: str, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Checks a list of candidate domains for visual similarity to reference logo.
        Candidates should be dicts with at least 'domain'.
        """
        ref_img = self._fetch_image(reference_logo)
        if not ref_img:
            self.logger.error("Could not fetch reference logo")
            return []
            
        ref_hash = self.compute_phash(ref_img)
        
        results = []
        
        for cand in candidates:
            domain = cand.get("domain")
            if not domain: continue
            
            # Try to guess favicon location
            # (In a real scenario, we might use Google Favicon API or construct common paths)
            possible_urls = [
                f"https://www.google.com/s2/favicons?domain={domain}&sz=128", 
                f"http://{domain}/favicon.ico",
                f"https://{domain}/favicon.ico"
            ]
            
            match_found = False
            best_score = 0
            
            for icon_url in possible_urls:
                cand_img = self._fetch_image(icon_url)
                if cand_img:
                    try:
                        cand_hash = self.compute_phash(cand_img)
                        distance = ref_hash - cand_hash
                        score = max(0, (64 - distance) / 64)
                        
                        if distance <= 12: # Slightly looser threshold for hunting
                            results.append({
                                "domain": domain,
                                "match_url": icon_url,
                                "distance": distance,
                                "score": score,
                                "ip": cand.get("ip")
                            })
                            match_found = True
                            break
                    except Exception as e:
                        print(e)
                        pass
                if match_found: break
                
        return sorted(results, key=lambda x: x['distance'])
