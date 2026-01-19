import requests
import logging
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from yads.core.base import BaseScannerModule
from yads.models import ScanResult

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get").lower(),
                "inputs": [],
                "id": attrs_dict.get("id"),
                "class": attrs_dict.get("class")
            }
            self.forms.append(self._current_form)
            
        elif tag in ["input", "textarea", "select"] and self._current_form is not None:
            input_data = {
                "tag": tag,
                "name": attrs_dict.get("name"),
                "type": attrs_dict.get("type", "text") if tag == "input" else None,
                "id": attrs_dict.get("id")
            }
            self._current_form["inputs"].append(input_data)

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None

class FormDiscoveryScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "form_discovery"

    def run_scan(self, target: str) -> Dict[str, Any]:
        logger = logging.getLogger("yads.modules.form_discovery")
        
        url = target
        if not url.startswith("http"):
            url = f"https://{target}"
            
        results = {
            "forms": [],
            "error": None
        }
        
        try:
            # 1. Fetch Page
            # Verify False to ensure we get results even with bad certs
            resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            
            if resp.status_code == 200:
                # 2. Parse
                parser = FormParser()
                parser.feed(resp.text)
                
                # 3. Post-process (Absolute URLs)
                base_url = resp.url # Final URL after redirects
                
                for form in parser.forms:
                    action = form.get("action")
                    if action:
                        form["action_absolute"] = urljoin(base_url, action)
                    else:
                        form["action_absolute"] = base_url # Empty action submits to self
                        
                    results["forms"].append(form)
                    
                logger.info(f"Found {len(results['forms'])} forms on {url}")
            else:
                results["error"] = f"HTTP {resp.status_code}"
                
        except Exception as e:
            logger.error(f"Form Discovery Failed: {e}")
            results["error"] = str(e)
            
        return results
