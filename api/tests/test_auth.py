"""
tests/test_auth.py — Authentication flow tests
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


# ── Registration ──────────────────────────────────────────────────

async def test_register_success(client):
    r = await client.post("/api/v1/auth/register", json={
        "email": "new@example.com", "first_name": "New", "last_name": "User",
        "password": "ValidPass1", "address": {"country": "ZA"},
    })
    assert r.status_code == 201
    data = r.json()
    assert data["email"] == "new@example.com"
    assert data["is_active"] is True
    assert data["is_verified"] is False
    assert "id" in data


async def test_register_duplicate_email(client, registered_user):
    r = await client.post("/api/v1/auth/register", json={
        "email": "jane@example.com", "first_name": "Jane", "last_name": "Dup",
        "password": "AnotherPass1", "address": {"country": "ZA"},
    })
    assert r.status_code == 409
    assert "already registered" in r.json()["detail"]


async def test_register_weak_password_no_uppercase(client):
    r = await client.post("/api/v1/auth/register", json={
        "email": "weak@example.com", "first_name": "W", "last_name": "P",
        "password": "nouppercase1", "address": {},
    })
    assert r.status_code == 422


async def test_register_weak_password_no_digit(client):
    r = await client.post("/api/v1/auth/register", json={
        "email": "weak2@example.com", "first_name": "W", "last_name": "P",
        "password": "NoDigitHere", "address": {},
    })
    assert r.status_code == 422


async def test_register_invalid_email(client):
    r = await client.post("/api/v1/auth/register", json={
        "email": "not-an-email", "first_name": "X", "last_name": "Y",
        "password": "ValidPass1", "address": {},
    })
    assert r.status_code == 422


# ── Login ─────────────────────────────────────────────────────────

async def test_login_success(client, registered_user):
    r = await client.post("/api/v1/auth/login", json={
        "email": "jane@example.com", "password": "SecurePass1",
    })
    assert r.status_code == 200
    data = r.json()
    assert "access_token"  in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 3600


async def test_login_wrong_password(client, registered_user):
    r = await client.post("/api/v1/auth/login", json={
        "email": "jane@example.com", "password": "WrongPass1",
    })
    assert r.status_code == 401


async def test_login_unknown_email(client):
    r = await client.post("/api/v1/auth/login", json={
        "email": "ghost@example.com", "password": "SomePass1",
    })
    assert r.status_code == 401


# ── Token refresh ─────────────────────────────────────────────────

async def test_refresh_token(client, registered_user):
    login = await client.post("/api/v1/auth/login", json={
        "email": "jane@example.com", "password": "SecurePass1",
    })
    refresh = login.json()["refresh_token"]
    r = await client.post("/api/v1/auth/refresh",
                           headers={"Authorization": f"Bearer {refresh}"})
    assert r.status_code == 200
    assert "access_token" in r.json()


async def test_refresh_with_access_token_fails(client, auth_headers):
    access_token = auth_headers["Authorization"].split(" ")[1]
    r = await client.post("/api/v1/auth/refresh",
                           headers={"Authorization": f"Bearer {access_token}"})
    assert r.status_code == 401


# ── Logout / Token revocation ─────────────────────────────────────

async def test_logout_revokes_token(client, auth_headers):
    # Confirm token works before logout
    r = await client.get("/api/v1/users/me", headers=auth_headers)
    assert r.status_code == 200

    # Logout
    r = await client.post("/api/v1/auth/logout", headers=auth_headers)
    assert r.status_code == 200

    # Same token should now be rejected
    r = await client.get("/api/v1/users/me", headers=auth_headers)
    assert r.status_code == 401
    assert "revoked" in r.json()["detail"].lower()


async def test_unauthenticated_request(client):
    r = await client.get("/api/v1/users/me")
    assert r.status_code == 401


# ── Password change ───────────────────────────────────────────────

async def test_change_password(client, auth_headers):
    r = await client.post("/api/v1/auth/change-password",
                           headers=auth_headers,
                           json={"current_password": "SecurePass1",
                                 "new_password": "NewSecure2"})
    assert r.status_code == 200

    # Old password should now fail
    r = await client.post("/api/v1/auth/login", json={
        "email": "jane@example.com", "password": "SecurePass1",
    })
    assert r.status_code == 401

    # New password should work
    r = await client.post("/api/v1/auth/login", json={
        "email": "jane@example.com", "password": "NewSecure2",
    })
    assert r.status_code == 200


async def test_change_password_wrong_current(client, auth_headers):
    r = await client.post("/api/v1/auth/change-password",
                           headers=auth_headers,
                           json={"current_password": "WrongCurrent1",
                                 "new_password": "NewSecure2"})
    assert r.status_code == 400


# ── Password reset flow ───────────────────────────────────────────

async def test_forgot_and_reset_password(client, registered_user):
    # Request reset token
    r = await client.post("/api/v1/auth/forgot-password",
                           json={"email": "jane@example.com"})
    assert r.status_code == 200
    token = r.json()["reset_token"]

    # Apply reset
    r = await client.post("/api/v1/auth/reset-password",
                           json={"token": token, "new_password": "Reset1234"})
    assert r.status_code == 200

    # Login with new password
    r = await client.post("/api/v1/auth/login", json={
        "email": "jane@example.com", "password": "Reset1234",
    })
    assert r.status_code == 200


async def test_reset_token_cannot_be_reused(client, registered_user):
    r = await client.post("/api/v1/auth/forgot-password",
                           json={"email": "jane@example.com"})
    token = r.json()["reset_token"]
    await client.post("/api/v1/auth/reset-password",
                      json={"token": token, "new_password": "Reset1234"})
    # Second use must fail
    r = await client.post("/api/v1/auth/reset-password",
                           json={"token": token, "new_password": "AnotherReset5"})
    assert r.status_code == 400


async def test_forgot_password_unknown_email_still_200(client):
    """Must not leak whether the email exists."""
    r = await client.post("/api/v1/auth/forgot-password",
                           json={"email": "ghost@example.com"})
    assert r.status_code == 200


# ── Email verification ────────────────────────────────────────────

async def test_email_verification_flow(client, auth_headers):
    r = await client.post("/api/v1/auth/request-verification", headers=auth_headers)
    assert r.status_code == 200
    token = r.json()["verification_token"]

    r = await client.get(f"/api/v1/auth/verify-email?token={token}")
    assert r.status_code == 200

    # Profile should show verified
    r = await client.get("/api/v1/users/me", headers=auth_headers)
    assert r.json()["is_verified"] is True


async def test_invalid_verification_token(client):
    r = await client.get("/api/v1/auth/verify-email?token=bogustoken")
    assert r.status_code == 400
