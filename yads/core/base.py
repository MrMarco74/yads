import abc
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from yads.models import ModuleState, ScanResult, Target, ChangeEvent

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

    def process(self, target_id: int, target_domain: str) -> Optional[ScanResult]:
        """
        Main entry point for the worker.
        1. Runs scan.
        2. Computes hash.
        3. Compares with DB state.
        4. Saves if changed.
        """
        # 1. Run Scan
        try:
            raw_data = self.run_scan(target_domain, target_id=target_id)
            raw_data = sanitize_null_bytes(raw_data)
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
