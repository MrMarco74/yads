import requests
import logging
from typing import Any, Dict, List
import datetime
from yads.core.base import BaseScannerModule

class WaybackScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "wayback_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger = logging.getLogger("yads.modules.wayback")
        logger.info(f"Wayback Scan started for {target}")
        
        results = {
            "snapshots_found": False,
            "total_snapshots": 0, # Note: Standard API doesn't give total count easily without pagination, we might just check availability
            "earliest": None,
            "latest": None,
            "link": None
        }

        # 1. Availability API (Latest)
        # https://archive.org/wayback/available?url=example.com
        try:
            url = f"https://archive.org/wayback/available?url={target}"
            logger.info(f"Querying Wayback Availability: {url}")
            resp = requests.get(url, timeout=10)
            logger.debug(f"Wayback Availability Status: {resp.status_code}")
            
            if resp.status_code == 200:
                data = resp.json()
                snapshots = data.get("archived_snapshots", {})
                closest = snapshots.get("closest", {})
                
                if closest and closest.get("available"):
                    results["snapshots_found"] = True
                    results["latest"] = {
                        "url": closest.get("url"),
                        "timestamp": closest.get("timestamp"), # Format: YYYYMMDDhhmmss
                        "status": closest.get("status")
                    }
                    results["link"] = f"https://web.archive.org/web/*/{target}"
                    logger.info(f"Wayback Snapshot Found: {closest.get('url')}")
                else:
                    logger.info("Wayback: No available snapshots returned by API.")
            else:
                logger.warning(f"Wayback API returned non-200 status: {resp.status_code} - {resp.text}")
                
        except Exception as e:
            logger.error(f"Wayback API error: {e}")
            results["error"] = str(e)

        # 2. CDX API for First snapshot (optional but nice)
        if results["snapshots_found"]:
            try:
                # Limit 1, sort by date ascending
                cdx_url = f"https://web.archive.org/cdx/search/cdx?url={target}&output=json&limit=1&sort=original&filter=statuscode:200"
                # This might be slow/rate-limited, so use short timeout and permissive failure
                resp_cdx = requests.get(cdx_url, timeout=5)
                if resp_cdx.status_code == 200:
                    cdx_data = resp_cdx.json()
                    # cdx_data is list of lists, first is header
                    if len(cdx_data) > 1:
                        # header: urlkey, timestamp, original, mimetype, statuscode, digest, length
                        # finding timestamp index
                        # typically ["urlkey", "timestamp", "original", ...]
                        row = cdx_data[1]
                        results["earliest"] = {
                            "timestamp": row[1],
                            "url": f"https://web.archive.org/web/{row[1]}/{target}"
                        }
            except Exception as e:
                logger.warning(f"Wayback CDX query failed: {e}")

        return results
