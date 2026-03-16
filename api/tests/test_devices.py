"""
tests/test_devices.py — Device registration, CRUD, API key rotation
"""

import pytest
pytestmark = pytest.mark.asyncio


# ── Registration ──────────────────────────────────────────────────

async def test_register_device_success(client, auth_headers):
    r = await client.post("/api/v1/devices", headers=auth_headers, json={
        "name": "Solar Inverter", "device_type": "solar_inverter",
        "location": "roof", "phases": ["L1", "L2"],
    })
    assert r.status_code == 201
    data = r.json()
    assert "device_key" in data
    assert "api_key"    in data
    assert data["api_key"].startswith("ems_")
    assert data["warning"]  # one-time key warning
    assert data["status"] == "pending"


async def test_api_key_shown_only_once(client, auth_headers, registered_device):
    """After registration, listing devices must NOT expose the raw API key."""
    r = await client.get("/api/v1/devices", headers=auth_headers)
    for d in r.json()["devices"]:
        assert "api_key" not in d
        assert "api_key_hash" not in d


async def test_device_limit_enforced_free_tier(client, auth_headers):
    """Free tier allows 1 device — second registration must fail."""
    # First device (already registered via fixture in other tests — register fresh here)
    r1 = await client.post("/api/v1/devices", headers=auth_headers, json={
        "name": "Device 1", "device_type": "general",
        "location": "kitchen", "phases": ["L1"],
    })
    assert r1.status_code == 201

    # Second device must hit the limit
    r2 = await client.post("/api/v1/devices", headers=auth_headers, json={
        "name": "Device 2", "device_type": "general",
        "location": "lounge", "phases": ["L1"],
    })
    assert r2.status_code == 403
    assert "limit" in r2.json()["detail"].lower()


# ── List & Get ────────────────────────────────────────────────────

async def test_list_devices(client, auth_headers, registered_device):
    r = await client.get("/api/v1/devices", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert "total" in body
    assert "devices" in body


async def test_get_single_device(client, auth_headers, registered_device):
    key = registered_device["device_key"]
    r   = await client.get(f"/api/v1/devices/{key}", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["device_key"] == key


async def test_get_nonexistent_device(client, auth_headers):
    r = await client.get("/api/v1/devices/dev_doesnotexist", headers=auth_headers)
    assert r.status_code == 404


async def test_list_devices_pagination(client, auth_headers, registered_device):
    r = await client.get("/api/v1/devices?skip=0&limit=1", headers=auth_headers)
    assert r.status_code == 200
    assert len(r.json()["devices"]) <= 1


# ── Update ────────────────────────────────────────────────────────

async def test_update_device(client, auth_headers, registered_device):
    key = registered_device["device_key"]
    r   = await client.patch(f"/api/v1/devices/{key}",
                              headers=auth_headers,
                              json={"name": "Renamed Device", "location": "garage"})
    assert r.status_code == 200
    updated = r.json()
    assert updated["name"]     == "Renamed Device"
    assert updated["location"] == "garage"


async def test_update_device_empty_body(client, auth_headers, registered_device):
    key = registered_device["device_key"]
    r   = await client.patch(f"/api/v1/devices/{key}",
                              headers=auth_headers, json={})
    assert r.status_code == 400


async def test_update_other_users_device(client, registered_device):
    """A different user must not be able to update this device."""
    r = await client.post("/api/v1/auth/register", json={
        "email": "other@example.com", "first_name": "Other", "last_name": "User",
        "password": "OtherPass1", "address": {},
    })
    login = await client.post("/api/v1/auth/login",
                               json={"email": "other@example.com", "password": "OtherPass1"})
    other_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    key = registered_device["device_key"]
    r   = await client.patch(f"/api/v1/devices/{key}",
                              headers=other_headers, json={"name": "Hijacked"})
    assert r.status_code == 404


# ── API Key rotation ──────────────────────────────────────────────

async def test_rotate_api_key(client, auth_headers, registered_device):
    key     = registered_device["device_key"]
    old_key = registered_device["api_key"]

    r = await client.post(f"/api/v1/devices/{key}/rotate-key", headers=auth_headers)
    assert r.status_code == 200
    new_key = r.json()["api_key"]
    assert new_key != old_key
    assert new_key.startswith("ems_")

    # Old key must no longer work for readings
    r = await client.post("/api/v1/readings",
                           headers={"X-Device-API-Key": old_key},
                           json={"device_key": key, "phase": "L1",
                                 "voltage": 230, "current": 10,
                                 "power_watts": 2300, "energy_kwh": 100})
    assert r.status_code == 401


# ── Delete ────────────────────────────────────────────────────────

async def test_delete_device(client, auth_headers, registered_device):
    key = registered_device["device_key"]
    r   = await client.delete(f"/api/v1/devices/{key}", headers=auth_headers)
    assert r.status_code == 200

    # Must be gone from list
    r = await client.get(f"/api/v1/devices/{key}", headers=auth_headers)
    assert r.status_code == 404
