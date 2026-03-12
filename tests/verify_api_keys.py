import os
import sys
from pathlib import Path

# Setup paths
yads_path = "/home/mrmarco/Documents/gitlab/yads"
sys.path.insert(0, yads_path)

import unittest
from unittest.mock import MagicMock, patch
from sqlmodel import Session, SQLModel, create_engine, select, Field, Relationship, Column
from sqlalchemy import JSON
from sqlalchemy.dialects import postgresql

# TRICK: Mock JSONB to be JSON for SQLite testing
postgresql.JSONB = JSON

# Now import models
from yads.models import APIKey, Tenant, User
from yads.auth.security import generate_api_key, hash_api_key

class TestAPIKeySystemExtended(unittest.TestCase):
    def setUp(self):
        # Use a temporary SQLite database for testing
        self.test_engine = create_engine("sqlite:///:memory:")
        
        # Create tables
        APIKey.__table__.create(self.test_engine)
        Tenant.__table__.create(self.test_engine)
        User.__table__.create(self.test_engine)
        
        self.session = Session(self.test_engine)
        
        # Create a test tenant
        self.tenant = Tenant(name="Test Tenant")
        self.session.add(self.tenant)
        self.session.commit()
        self.session.refresh(self.tenant)
        
        # Create a test user
        self.user = User(username="testadmin", password_hash="hash", role="admin", tenant_id=self.tenant.id)
        self.session.add(self.user)
        self.session.commit()

    def test_key_auth_flow(self):
        plain_key, prefix, key_hash = generate_api_key()
        new_key = APIKey(
            tenant_id=self.tenant.id,
            name="Test Key",
            key_prefix=prefix,
            key_hash=key_hash,
            is_active=True
        )
        self.session.add(new_key)
        self.session.commit()

        # Mock FastAPI Request
        request = MagicMock()
        request.headers = {"X-API-Key": plain_key}
        request.url = MagicMock()
        request.url.scheme = "http" # Test with http in debug
        request.method = "GET"
        
        # Mock redis_client and settings
        with patch("yads.auth.deps.redis_client") as mock_redis, \
             patch("yads.auth.deps.settings") as mock_settings, \
             patch("yads.auth.deps.log_api_key_access") as mock_log:
            
            mock_settings.DEBUG = True
            mock_redis.incr.return_value = 1
            
            # Run dependency logic
            async def run_dep():
                from yads.auth.deps import get_api_key
                return await get_api_key(request, self.session)

            import asyncio
            db_key = asyncio.run(run_dep())
            
            self.assertEqual(db_key.id, new_key.id)
            self.assertTrue(mock_redis.incr.called)
            self.assertTrue(mock_log.called)

    def test_rate_limit_exceeded(self):
        plain_key, prefix, key_hash = generate_api_key()
        new_key = APIKey(
            tenant_id=self.tenant.id,
            name="Test Key",
            key_prefix=prefix,
            key_hash=key_hash,
            is_active=True
        )
        self.session.add(new_key)
        self.session.commit()

        request = MagicMock()
        request.headers = {"X-API-Key": plain_key}
        request.url.scheme = "http"
        
        with patch("yads.auth.deps.redis_client") as mock_redis, \
             patch("yads.auth.deps.settings") as mock_settings:
            
            mock_settings.DEBUG = True
            mock_redis.incr.return_value = 61 # Exceed limit
            
            # Run dependency logic
            async def run_dep():
                from yads.auth.deps import get_api_key
                try:
                    await get_api_key(request, self.session)
                except Exception as e:
                    return e

            import asyncio
            from fastapi import HTTPException
            err = asyncio.run(run_dep())
            
            self.assertIsInstance(err, HTTPException)
            self.assertEqual(err.status_code, 429)

if __name__ == "__main__":
    unittest.main()
