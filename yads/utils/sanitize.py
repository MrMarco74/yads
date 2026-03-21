# Re-export sanitize_null_bytes from core.base for backwards compatibility
from yads.core.base import sanitize_null_bytes

__all__ = ["sanitize_null_bytes", "redact_headers"]

REDACT_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", 
    "x-api-key", "api-key", "token", "password", "secret", "bearer"
}

def redact_headers(headers: dict) -> dict:
    """
    Redacts sensitive HTTP headers from a dictionary.
    Returns a new dictionary with sensitive values replaced by '[REDACTED]'.
    """
    if not headers:
        return {}
    
    redacted = {}
    for k, v in headers.items():
        if k.lower() in REDACT_HEADERS:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
            
    return redacted
