import abc
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from yads.models import ModuleState, ScanResult, Target, ChangeEvent

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
    def run_scan(self, target: str) -> Dict[str, Any]:
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
            raw_data = self.run_scan(target_domain)
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
            
            # Save Result (and potentially generate diffs)
            result = self._save_result(target_id, raw_data, new_hash, current_time)
            self.db.commit()
            return result
        else:
            # NO CHANGE
            state.last_scanned_at = current_time
            self.db.add(state)
            self.db.commit()
            return None

    def _save_result(self, target_id: int, data: Dict, result_hash: str, timestamp: datetime) -> ScanResult:
        result = ScanResult(
            target_id=target_id,
            module_name=self.module_name,
            data=data,
            result_hash=result_hash,
            scanned_at=timestamp
        )
        self.db.add(result)
        return result
