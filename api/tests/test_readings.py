"""
tests/test_readings.py — Energy reading ingestion, history query, anomalies
"""

import pytest
pytestmark = pytest.mark.asyncio

SAMPLE_READING = {
    "device_key":   "FILLED_BY_FIXTURE",
    "phase":        "L1",
    "voltage":      230.5,
    "current":      12.3,
    "power_watts":  2829.15,
    "energy_kwh":   145.6,
    "power_factor": 0.95,
    "frequency_hz": 50.0,
    "temperature_celsius": 38.2,
}


# ── Ingest ────────────────────────────────────────────────────────

async def test_ingest_reading_success(client, registered_device, device_headers):
    payload = {**SAMPLE_READING, "device_key": registered_device["device_key"]}
    r = await client.post("/api/v1/readings", headers=device_headers, json=payload)
    assert r.status_code == 200
    assert r.json()["status"] == "success"


async def test_ingest_reading_bad_api_key(client, registered_device):
    payload = {**SAMPLE_READING, "device_key": registered_device["device_key"]}
    r = await client.post("/api/v1/readings",
                           headers={"X-Device-API-Key": "ems_badkey"},
                           json=payload)
    assert r.status_code == 401


async def test_ingest_reading_no_api_key(client, registered_device):
    payload = {**SAMPLE_READING, "device_key": registered_device["device_key"]}
    r = await client.post("/api/v1/readings", json=payload)
    assert r.status_code == 401


async def test_ingest_reading_invalid_voltage(client, registered_device, device_headers):
    payload = {**SAMPLE_READING, "device_key": registered_device["device_key"],
               "voltage": -10}
    r = await client.post("/api/v1/readings", headers=device_headers, json=payload)
    assert r.status_code == 422


async def test_ingest_reading_invalid_frequency(client, registered_device, device_headers):
    payload = {**SAMPLE_READING, "device_key": registered_device["device_key"],
               "frequency_hz": 30.0}  # below 45 Hz floor
    r = await client.post("/api/v1/readings", headers=device_headers, json=payload)
    assert r.status_code == 422


async def test_ingest_bulk_readings(client, registered_device, device_headers):
    dk = registered_device["device_key"]
    r  = await client.post("/api/v1/readings/bulk",
                            headers=device_headers,
                            json={"readings": [
                                {**SAMPLE_READING, "device_key": dk, "phase": "L1"},
                                {**SAMPLE_READING, "device_key": dk, "phase": "L2",
                                 "voltage": 231.0, "current": 11.5},
                                {**SAMPLE_READING, "device_key": dk, "phase": "L3",
                                 "power_watts": 2650.0},
                            ]})
    assert r.status_code == 200
    assert r.json()["processed"] == 3


# ── History query ─────────────────────────────────────────────────

async def test_query_readings_returns_stored(client, auth_headers,
                                              registered_device, device_headers):
    dk = registered_device["device_key"]
    # Insert a reading first
    await client.post("/api/v1/readings", headers=device_headers,
                      json={**SAMPLE_READING, "device_key": dk})

    r = await client.get(f"/api/v1/readings?device_key={dk}", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert body["readings"][0]["device_key"] == dk


async def test_query_readings_pagination(client, auth_headers,
                                          registered_device, device_headers):
    dk = registered_device["device_key"]
    for _ in range(5):
        await client.post("/api/v1/readings", headers=device_headers,
                          json={**SAMPLE_READING, "device_key": dk})

    r = await client.get(f"/api/v1/readings?device_key={dk}&limit=2&skip=0",
                          headers=auth_headers)
    assert r.status_code == 200
    assert len(r.json()["readings"]) <= 2


async def test_query_readings_requires_auth(client):
    r = await client.get("/api/v1/readings")
    assert r.status_code == 401


async def test_query_readings_other_users_device(client, registered_device):
    """A different user cannot read another user's device history."""
    await client.post("/api/v1/auth/register", json={
        "email": "intruder@example.com", "first_name": "X", "last_name": "Y",
        "password": "Intruder1", "address": {},
    })
    login = await client.post("/api/v1/auth/login",
                               json={"email": "intruder@example.com",
                                     "password": "Intruder1"})
    other_hdrs = {"Authorization": f"Bearer {login.json()['access_token']}"}
    dk = registered_device["device_key"]
    r  = await client.get(f"/api/v1/readings?device_key={dk}", headers=other_hdrs)
    assert r.status_code == 404


# ── Summary ───────────────────────────────────────────────────────

async def test_readings_summary(client, auth_headers,
                                 registered_device, device_headers):
    dk = registered_device["device_key"]
    await client.post("/api/v1/readings", headers=device_headers,
                      json={**SAMPLE_READING, "device_key": dk})

    r = await client.get(f"/api/v1/readings/summary?period=24h", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert "devices" in body
    assert body["period"] == "24h"


# ── Anomalies ─────────────────────────────────────────────────────

async def test_report_anomaly(client, registered_device, device_headers):
    r = await client.post("/api/v1/anomalies",
                           headers=device_headers,
                           json={"device_key":   registered_device["device_key"],
                                 "anomaly_type": "voltage_spike",
                                 "description":  "Voltage exceeded 260V for 3s"})
    assert r.status_code == 200
    assert r.json()["status"] == "success"


async def test_list_anomalies(client, auth_headers,
                               registered_device, device_headers):
    await client.post("/api/v1/anomalies",
                      headers=device_headers,
                      json={"device_key": registered_device["device_key"],
                            "anomaly_type": "low_power_factor"})

    r = await client.get("/api/v1/anomalies", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert body["anomalies"][0]["anomaly_type"] in ["low_power_factor", "voltage_spike"]


async def test_anomaly_bad_key(client, registered_device):
    r = await client.post("/api/v1/anomalies",
                           headers={"X-Device-API-Key": "ems_badkey"},
                           json={"device_key": registered_device["device_key"],
                                 "anomaly_type": "test"})
    assert r.status_code == 401
