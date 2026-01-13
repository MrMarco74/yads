import logging
from typing import Any, Mapping, MutableMapping, Optional, Tuple

class TenantLogger(logging.LoggerAdapter):
    """
    A LoggerAdapter that injects '[Tenant: <id>]' into the beginning of log messages.
    This allows file-based logs to be filtered by tenant ID.
    
    Usage:
        base_logger = logging.getLogger("yads.some_module")
        logger = TenantLogger(base_logger, tenant_id=123)
        logger.info("Something happened") 
        # Output: [Tenant: 123] Something happened
    """
    def __init__(self, logger: logging.Logger, tenant_id: Optional[int]):
        super().__init__(logger, {"tenant_id": tenant_id})
        self.tenant_id = tenant_id

    def process(self, msg: Any, kwargs: MutableMapping[str, Any]) -> Tuple[Any, MutableMapping[str, Any]]:
        if self.tenant_id is not None:
            return f"[Tenant: {self.tenant_id}] {msg}", kwargs
        return msg, kwargs
