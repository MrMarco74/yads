"""get_api_key's TLS-required check must accept requests that reached the app
over HTTPS at the edge and were forwarded as HTTP by a reverse proxy (the
standard prod topology: TLS terminates at the proxy, uvicorn sees http +
X-Forwarded-Proto: https). Before this fix it looked only at
request.url.scheme, so behind the proxy EVERY API key was rejected with
'SSL/TLS Required' — making the entire /api/v1 (yads-mcp) surface unusable in
production, while tests passed because DEBUG=true skips the check."""

import asyncio
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from yads.auth.deps import get_api_key
import yads.auth.deps as deps


def _request(scheme, x_forwarded_proto=None):
    headers = {}
    if x_forwarded_proto:
        headers["x-forwarded-proto"] = x_forwarded_proto
    req = MagicMock()
    req.url.scheme = scheme
    req.headers.get = lambda k, d=None: headers.get(k.lower(), d)
    return req


def test_tls_check_accepts_forwarded_proto_https(monkeypatch):
    monkeypatch.setattr(deps.settings, "DEBUG", False)
    req = _request("http", x_forwarded_proto="https")
    # TLS passes -> falls through to the missing-key 401, NOT the TLS 403.
    with pytest.raises(HTTPException) as ei:
        asyncio.run(get_api_key(req, session=MagicMock()))
    assert ei.value.status_code == 401


def test_tls_check_rejects_plain_http(monkeypatch):
    monkeypatch.setattr(deps.settings, "DEBUG", False)
    req = _request("http")  # no forwarded-proto, genuinely plain http
    with pytest.raises(HTTPException) as ei:
        asyncio.run(get_api_key(req, session=MagicMock()))
    assert ei.value.status_code == 403
    assert "SSL/TLS" in ei.value.detail


def test_tls_check_accepts_direct_https(monkeypatch):
    monkeypatch.setattr(deps.settings, "DEBUG", False)
    req = _request("https")
    with pytest.raises(HTTPException) as ei:
        asyncio.run(get_api_key(req, session=MagicMock()))
    assert ei.value.status_code == 401  # TLS ok -> missing key
