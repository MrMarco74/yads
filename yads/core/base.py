import abc
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from yads.core.api_block_detection import ApiBlockedError
from yads.models import ModuleState, ScanResult, Target, ChangeEvent


@dataclass
class ApiKeySpec:
    """
    Declares an API key required by a scanner module.
    Used by the tenant settings UI to render key input fields dynamically.
    """
    name: str                          # e.g. "shodan_api_key"
    label: str                         # e.g. "Shodan API Key"
    description: str = ""              # shown in UI
    placeholder: str = ""              # input placeholder
    help_url: str = ""                 # link to get the key
    required: bool = False             # warn if missing
    settings_fallback: Optional[str] = None   # global env var name (e.g. "SHODAN_API_KEY")
    legacy_tenant_attr: Optional[str] = None  # old Tenant model attr (e.g. "nuclei_api_key")

def sanitize_null_bytes(value):
    """
    Recursively removes null bytes (\u0000) from strings, dicts, and lists.
    PostgreSQL (especially JSONB) does not support null bytes in text.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value.replace('\u0000', '').replace('\x00', '')
    if isinstance(value, dict):
        return {k: sanitize_null_bytes(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_null_bytes(v) for v in value]
    return value

class BaseScannerModule(abc.ABC):
    """
    Abstract base class for all scanner modules.
    Implements the core 'State' and 'Hashing' logic.
    """

    # Declare API keys required by this module. UI renders these dynamically.
    api_key_specs: ClassVar[List[ApiKeySpec]] = []

    def __init__(self, db_session):
        self.db = db_session

    @property
    @abc.abstractmethod
    def module_name(self) -> str:
        pass

    @abc.abstractmethod
    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute the actual scanning logic.
        Returns a dictionary representing the raw data.
        """
        pass

    def compute_hash(self, data: Dict[str, Any]) -> str:
        """
        Computes a deterministic hash of the data.
        """
        # Sort keys to ensure deterministic JSON representation
        serialized = json.dumps(data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    def process(self, target_id: int, target_domain: str, precomputed: Optional[Dict[str, Any]] = None) -> Optional[ScanResult]:
        """
        Main entry point for the worker.
        1. Runs scan (or reuses `precomputed` run_scan output if given).
        2. Computes hash.
        3. Compares with DB state.
        4. Saves if changed.

        precomputed: if a caller already invoked run_scan() for this target
        (e.g. the parked-domain pre-check needs the live verdict for its gating
        decision), it can pass that same result dict here so process() persists
        the identical observation instead of running the scan a second time.
        """
        # 1. Run Scan (or reuse a precomputed run_scan result)
        try:
            raw_data = precomputed if precomputed is not None else self.run_scan(target_domain, target_id=target_id)
            raw_data = sanitize_null_bytes(raw_data)
        except ApiBlockedError:
            raise
        except Exception as e:
            # TODO: Log error properly
            print(f"Error scanning {target_domain}: {e}")
            return None

        # 2. Compute Hash
        new_hash = self.compute_hash(raw_data)
        
        # 3. Fetch State
        state = self.db.query(ModuleState).filter(
            ModuleState.target_id == target_id,
            ModuleState.module_name == self.module_name
        ).first()

        current_time = datetime.utcnow()

        # If no previous state, create one and save result
        if not state:
            state = ModuleState(
                target_id=target_id,
                module_name=self.module_name,
                last_result_hash=new_hash,
                last_scanned_at=current_time
            )
            self.db.add(state)

            # Save Result
            result = self._save_result(target_id, raw_data, new_hash, current_time)
            self.db.flush()

            # Record ChangeEvent for first scan
            event = ChangeEvent(
                scan_result_id=result.id,
                event_type="FIRST_SCAN",
                description=self._describe_change(raw_data),
            )
            self.db.add(event)
            self.db.commit()
            return result

        # Check for change
        if state.last_result_hash != new_hash:
            # CHANGE DETECTED
            print(f"Change detected for {target_domain} in {self.module_name}")

            # Update State
            state.last_result_hash = new_hash
            state.last_scanned_at = current_time
            self.db.add(state)

            # Save Result
            result = self._save_result(target_id, raw_data, new_hash, current_time)
            self.db.flush()

            # Record ChangeEvent
            event = ChangeEvent(
                scan_result_id=result.id,
                event_type="DATA_CHANGED",
                description=self._describe_change(raw_data),
            )
            self.db.add(event)
            self.db.commit()
            return result
        else:
            # NO CHANGE IN DATA
            # But we still want to update the 'last_scanned_at' and potentially return the object so logs can be attached
            state.last_scanned_at = current_time
            self.db.add(state)
            
            # We need to return a result object so the worker can attach logs.
            # We'll fetch the *latest* result for this module/target to attach logs to it, 
            # OR create a new "no-change" result.
            # Strategy: Create a new result entry even if identical? No, that fills DB.
            # Strategy: Return an object that has 'log_content' attribute but isn't a DB model?
            # Strategy: Update the *existing* latest result's logs?
            
            # Let's try to fetch the most recent result and update its logs/timestamp?
            # actually, usually we want a record that the scan ran.
            # For now, let's just create a new result even if content is same, for debugging purposes?
            # Or better: MODIFY logic in worker.py.
            # But for now, let's just return key data so worker is happy.
            
            # Use _save_result to force saving an entry even if duplicate data (for now, to fix log visibility)
            # This is acceptable for debugging.
            result = self._save_result(target_id, raw_data, new_hash, current_time)
            self.db.commit()
            return result

    def _describe_change(self, data: Dict) -> str:
        """Build a short human-readable summary of the scan result for ChangeEvent."""
        summary = data.get("summary", {})
        parts = []
        score = summary.get("score")
        if score is not None:
            parts.append(f"Score: {score}")
        findings = data.get("findings", [])
        fc = len(findings) if isinstance(findings, list) else summary.get("findings_count", 0)
        if fc:
            parts.append(f"{fc} finding(s)")
        # Module-specific extras
        if data.get("error"):
            parts.append(f"Error: {data['error']}")
        return "; ".join(parts) if parts else "Data updated"

    def _save_result(self, target_id: int, data: Dict, result_hash: str, timestamp: datetime) -> ScanResult:
        result = ScanResult(
            target_id=target_id,
            module_name=self.module_name,
            data=sanitize_null_bytes(data),
            result_hash=result_hash,
            scanned_at=timestamp
        )
        self.db.add(result)
        return result
