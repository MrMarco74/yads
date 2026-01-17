from typing import Dict, List, Any, Optional
import json
from pydantic import BaseModel

class DiffChange(BaseModel):
    added: List[str] = []
    removed: List[str] = []
    # For property changes (e.g. headers: Old -> New)
    changed: Dict[str, Dict[str, Any]] = {} 

class ComparisonResult(BaseModel):
    target_id: int
    scan_a_id: int
    scan_b_id: int
    
    ports: DiffChange = DiffChange()
    tech_stack: DiffChange = DiffChange()
    subdomains: DiffChange = DiffChange()
    headers: DiffChange = DiffChange()
    
    has_changes: bool = False

class ComparisonEngine:
    @staticmethod
    def _safe_load(data: Any) -> Dict[str, Any]:
        if isinstance(data, dict): return data
        if not data: return {}
        try:
            return json.loads(data)
        except:
            return {}

    @staticmethod
    def compare(res_a_data: Any, res_b_data: Any, target_id: int, a_id: int, b_id: int) -> ComparisonResult:
        """
        Compares two scan result data blobs (B vs A, where B is "New" and A is "Old").
        """
        data_a = ComparisonEngine._safe_load(res_a_data) # Old
        data_b = ComparisonEngine._safe_load(res_b_data) # New
        
        diff = ComparisonResult(
            target_id=target_id,
            scan_a_id=a_id,
            scan_b_id=b_id
        )
        
        # 1. Ports (Port Scanner)
        # Expected structure: {"open_ports": [80, 443]}
        ports_a = set(data_a.get("open_ports", []))
        ports_b = set(data_b.get("open_ports", []))
        
        if ports_a or ports_b:
            diff.ports.added = [str(p) for p in (ports_b - ports_a)]
            diff.ports.removed = [str(p) for p in (ports_a - ports_b)]
            
        # 2. Tech Stack (Web Analyzer)
        # Expected structure: {"tech_stack": ["Nginx", "React"]}
        tech_a = set(data_a.get("tech_stack", []))
        tech_b = set(data_b.get("tech_stack", []))
        
        if tech_a or tech_b:
            diff.tech_stack.added = list(tech_b - tech_a)
            diff.tech_stack.removed = list(tech_a - tech_b)
            
        # 3. Subdomains (DNS Scanner)
        # Expected: {"subdomains": ["sub.example.com"]}
        subs_a = set(data_a.get("subdomains", []))
        subs_b = set(data_b.get("subdomains", []))
        
        if subs_a or subs_b:
            diff.subdomains.added = list(subs_b - subs_a)
            diff.subdomains.removed = list(subs_a - subs_b)
            
        # 4. Headers (Web Analyzer)
        # Expected: {"http_headers": {"Server": "Nginx"}}
        headers_a = data_a.get("http_headers") or {}
        headers_b = data_b.get("http_headers") or {}
        
        all_keys = set(headers_a.keys()) | set(headers_b.keys())
        for k in all_keys:
            val_a = headers_a.get(k)
            val_b = headers_b.get(k)
            
            if val_a == val_b: continue
            
            # Simple existence check
            if val_a is None and val_b is not None:
                diff.headers.added.append(f"{k}: {val_b}")
            elif val_a is not None and val_b is None:
                diff.headers.removed.append(f"{k}: {val_a}")
            else:
                # Changed
                diff.headers.changed[k] = {"old": val_a, "new": val_b}

        # Calculate has_changes
        if (diff.ports.added or diff.ports.removed or 
            diff.tech_stack.added or diff.tech_stack.removed or
            diff.subdomains.added or diff.subdomains.removed or
            diff.headers.added or diff.headers.removed or diff.headers.changed):
            diff.has_changes = True
            
        return diff
