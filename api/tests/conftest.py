"""
conftest.py — shared pytest fixtures for the Energy Monitoring API test suite.

Uses an in-memory mongomock database so no real MongoDB is needed.
Run with:  pytest api/tests/ -v
"""

import asyncio
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport

# ── patch motor before importing the app ──────────────────────────
import mongomock_motor

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def mock_db():
    """In-memory MongoDB using mongomock_motor."""
    client = mongomock_motor.AsyncMongoMockClient()
    db = client["energy_monitor_test"]
    yield db
    client.close()


@pytest_asyncio.fixture(scope="function")
async def client(mock_db):
    """
    AsyncClient wired to the FastAPI app with the real DB dependency
    swapped for the in-memory mock.
    """
    from database import get_db
    from main import app

    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db

    # Bypass lifespan so we don't need a real Mongo connection
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


# ── Helpers ───────────────────────────────────────────────────────

REGISTER_PAYLOAD = {
    "email":      "jane@example.com",
    "first_name": "Jane",
    "last_name":  "Smith",
    "password":   "SecurePass1",
    "address":    {"country": "ZA"},
}

DEVICE_PAYLOAD = {
    "name":        "Main Distribution Board",
    "device_type": "smart_meter",
    "location":    "main-panel",
    "phases":      ["L1", "L2", "L3"],
}


@pytest_asyncio.fixture
async def registered_user(client):
    """Register a user and return the response JSON."""
    r = await client.post("/api/v1/auth/register", json=REGISTER_PAYLOAD)
    assert r.status_code == 201
    return r.json()


@pytest_asyncio.fixture
async def auth_headers(client, registered_user):
    """Log in and return Authorization headers."""
    r = await client.post("/api/v1/auth/login", json={
        "email":    REGISTER_PAYLOAD["email"],
        "password": REGISTER_PAYLOAD["password"],
    })
    assert r.status_code == 200
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def registered_device(client, auth_headers):
    """Register a device and return {device_key, api_key}."""
    r = await client.post("/api/v1/devices", json=DEVICE_PAYLOAD,
                          headers=auth_headers)
    assert r.status_code == 201
    return r.json()


@pytest_asyncio.fixture
async def device_headers(registered_device):
    """X-Device-API-Key headers for the registered device."""
    return {"X-Device-API-Key": registered_device["api_key"]}
