# Re-export sanitize_null_bytes from core.base for backwards compatibility
from yads.core.base import sanitize_null_bytes

__all__ = ["sanitize_null_bytes"]
