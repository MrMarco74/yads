import socket
import requests
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.connection import create_connection as _orig_create_connection
from typing import Optional, Dict
from yads.config import settings
from yads.database import redis_client
from datetime import datetime, timedelta

logger = logging.getLogger("yads.api.update")


def _ipv4_create_connection(address, *args, **kwargs):
    """Resolve hostname to IPv4 only — avoids IPv6 failures in Docker overlay networks."""
    host, port = address
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return _orig_create_connection(infos[0][4], *args, **kwargs)
    except socket.gaierror:
        pass
    return _orig_create_connection(address, *args, **kwargs)


class _IPv4Adapter(HTTPAdapter):
    def send(self, *args, **kwargs):
        import urllib3.util.connection as _conn
        _orig = _conn.create_connection
        _conn.create_connection = _ipv4_create_connection
        try:
            return super().send(*args, **kwargs)
        finally:
            _conn.create_connection = _orig

class UpdateService:
    VERSION_URL = "https://yads-security.com/releases/version.json"
    CACHE_KEY = "yads_latest_version_cache"
    CACHE_TTL = 21600 # 6 hours

    @staticmethod
    def check_for_updates() -> Optional[Dict]:
        """
        Fetches the latest version from yads-security.com and compares it with the current version.
        Returns a dictionary with result if an update is available, else None.
        """
        import json
        
        # 1. Check Cache (Redis)
        try:
            r = redis_client
            cached = r.get(UpdateService.CACHE_KEY)
            if cached:
                cached_data = json.loads(cached)
                # Check if it's truly an update based on local version
                if UpdateService._is_newer(cached_data.get("version"), settings.VERSION):
                    return cached_data
                return None
        except Exception as e:
            logger.warning(f"Failed to access Redis cache for update check: {e}")

        # 2. Fetch Remote
        try:
            # Use requests (already a dependency)
            session = requests.Session()
            session.mount("https://", _IPv4Adapter())
            response = session.get(UpdateService.VERSION_URL, timeout=5.0)
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                # If server returns malformed JSON (e.g. unescaped quotes in 'text' field)
                # We try a simple regex cleanup for the 'text' field
                import re
                raw_text = response.text
                match = re.search(r'("text":\s*")(.*?)("(?:\n|\s)*,)', raw_text, re.DOTALL)
                if match:
                    prefix, content, suffix = match.groups()
                    # Escape internal quotes that aren't already escaped
                    # We match quotes that are NOT preceded by a backslash
                    fixed_content = re.sub(r'([^\\])"', r'\1\"', content)
                    # Also handle the case where a quote is at the very beginning of content
                    if fixed_content.startswith('"'):
                        fixed_content = '\\"' + fixed_content[1:]
                        
                    fixed_text = raw_text.replace(match.group(0), f'{prefix}{fixed_content}{suffix}')
                    data = json.loads(fixed_text)
                else:
                    raise

            # Expected format: {"version": "1.13.0", "text": "New features available!", "url": "https://..."}
            remote_version = data.get("version")
            
            # 3. Cache it (even if no update, we cache the 'no update' state for a while?)
            # Actually, cache the data we got.
            if r:
                try:
                    r.setex(UpdateService.CACHE_KEY, UpdateService.CACHE_TTL, json.dumps(data))
                except: pass

            if UpdateService._is_newer(remote_version, settings.VERSION):
                return data
        except Exception as e:
            logger.error(f"Failed to check for YADS updates: {e}")
            
        return None

    @staticmethod
    def _is_newer(remote: str, local: str) -> bool:
        """Simple semantic version comparison."""
        if not remote or not local:
            return False
            
        try:
            r_parts = [int(p) for p in remote.split('.')]
            l_parts = [int(p) for p in local.split('.')]
            
            for r, l in zip(r_parts, l_parts):
                if r > l: return True
                if l > r: return False
                
            return len(r_parts) > len(l_parts)
        except:
            return remote > local # Fallback
