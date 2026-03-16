"""
tests/test_users.py — User profile, settings, subscription, account deletion
"""

import pytest
pytestmark = pytest.mark.asyncio


# ── Profile ───────────────────────────────────────────────────────

async def test_get_profile(client, auth_headers, registered_user):
    r = await client.get("/api/v1/users/me", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["email"] == "jane@example.com"
    assert data["first_name"] == "Jane"
    assert "hashed_password" not in data


async def test_update_profile(client, auth_headers):
    r = await client.patch("/api/v1/users/me", headers=auth_headers,
                            json={"first_name": "Janet", "phone": "+27821234567"})
    assert r.status_code == 200
    data = r.json()
    assert data["first_name"] == "Janet"
    assert data["phone"] == "+27821234567"


async def test_update_profile_empty_body(client, auth_headers):
    r = await client.patch("/api/v1/users/me", headers=auth_headers, json={})
    assert r.status_code == 400


# ── Settings ──────────────────────────────────────────────────────

async def test_get_settings(client, auth_headers):
    r = await client.get("/api/v1/users/me/settings", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["currency"] == "ZAR"
    assert data["timezone"] == "Africa/Johannesburg"
    assert data["energy_rate_per_kwh"] == 2.50


async def test_update_settings(client, auth_headers):
    r = await client.patch("/api/v1/users/me/settings", headers=auth_headers,
                            json={"energy_rate_per_kwh": 3.10, "theme": "dark"})
    assert r.status_code == 200
    data = r.json()
    assert data["energy_rate_per_kwh"] == 3.10
    assert data["theme"] == "dark"


async def test_update_settings_requires_auth(client):
    r = await client.patch("/api/v1/users/me/settings",
                            json={"theme": "dark"})
    assert r.status_code == 401


# ── Subscription ──────────────────────────────────────────────────

async def test_get_subscription(client, auth_headers):
    r = await client.get("/api/v1/users/me/subscription", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["tier"] == "free"
    assert data["max_devices"] == 1
    assert data["history_days"] == 7
    assert data["ai_insights_enabled"] is False


async def test_upgrade_subscription(client, auth_headers):
    r = await client.post("/api/v1/users/me/subscription/upgrade?tier=pro",
                           headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["new_tier"] == "pro"

    # Verify limits updated
    r = await client.get("/api/v1/users/me/subscription", headers=auth_headers)
    data = r.json()
    assert data["tier"] == "pro"
    assert data["max_devices"] == 20
    assert data["history_days"] == 365
    assert data["ai_insights_enabled"] is True


async def test_upgrade_unlocks_more_devices(client, auth_headers):
    """After upgrading to BASIC (5 devices), a second device must be allowed."""
    await client.post("/api/v1/users/me/subscription/upgrade?tier=basic",
                      headers=auth_headers)

    for i in range(2):
        r = await client.post("/api/v1/devices", headers=auth_headers,
                               json={"name": f"Device {i}", "device_type": "general",
                                     "location": f"room-{i}", "phases": ["L1"]})
        assert r.status_code == 201, f"Device {i} failed: {r.json()}"


# ── Account deletion ──────────────────────────────────────────────

async def test_delete_account(client, auth_headers):
    r = await client.delete("/api/v1/users/me", headers=auth_headers)
    assert r.status_code == 200

    # Token no longer works
    r = await client.get("/api/v1/users/me", headers=auth_headers)
    assert r.status_code == 401


async def test_delete_account_cascades_devices(client, auth_headers,
                                                registered_device):
    """Deleting the account must also delete the user's devices."""
    # Device exists before deletion
    key = registered_device["device_key"]
    r   = await client.get(f"/api/v1/devices/{key}", headers=auth_headers)
    assert r.status_code == 200

    await client.delete("/api/v1/users/me", headers=auth_headers)

    # After deletion, device API key must be invalid
    r = await client.post("/api/v1/readings",
                           headers={"X-Device-API-Key": registered_device["api_key"]},
                           json={"device_key": key, "phase": "L1",
                                 "voltage": 230, "current": 10,
                                 "power_watts": 2300, "energy_kwh": 100})
    assert r.status_code == 401
