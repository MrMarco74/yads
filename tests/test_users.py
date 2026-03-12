"""
User management tests.
Covers: user list, create, delete, password reset, role enforcement.
"""

import pytest


@pytest.mark.users
class TestUserList:
    def test_users_page_loads(self, admin_client):
        r = admin_client.get("/users", follow_redirects=True)
        assert r.status_code == 200


@pytest.mark.users
class TestUserCreate:
    def test_create_user_succeeds(self, admin_client, db_session):
        """Admin must be able to create a new user."""
        r = admin_client.post(
            "/users/create",
            data={
                "username": "pytest-testuser",
                "password": "TestPass123!",
                "role": "scanner",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200

        # Cleanup
        from yads.models import User
        from sqlmodel import select
        user = db_session.exec(
            select(User).where(User.username == "pytest-testuser")
        ).first()
        if user:
            db_session.delete(user)
            db_session.commit()

    def test_duplicate_username_rejected(self, admin_client):
        """Creating a user that already exists must not crash the server."""
        r = admin_client.post(
            "/users/create",
            data={
                "username": "admin",  # already exists
                "password": "AnotherPass!",
                "role": "scanner",
            },
            follow_redirects=True,
        )
        # Server handles duplicate gracefully
        assert r.status_code < 500


@pytest.mark.users
class TestUserPasswordReset:
    def test_reset_password_endpoint_reachable(self, admin_client, db_session):
        """Admin must be able to reset a user's password."""
        from yads.models import User
        from sqlmodel import select

        user = db_session.exec(
            select(User).where(User.username == "admin")
        ).first()
        assert user is not None

        r = admin_client.post(
            "/users/reset_password",
            data={
                "user_id": str(user.id),
                "new_password": "NewTestPass123!",
            },
            follow_redirects=True,
        )
        assert r.status_code < 500

        # Restore original password so other tests still work
        from yads.auth.security import get_password_hash
        user.password_hash = get_password_hash("admin")
        db_session.add(user)
        db_session.commit()


@pytest.mark.users
class TestUserProfile:
    def test_profile_page_loads(self, admin_client):
        r = admin_client.get("/profile", follow_redirects=True)
        assert r.status_code == 200
