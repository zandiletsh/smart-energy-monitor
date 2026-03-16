# &#x20;Smart Energy Monitoring System 

AI-powered smart energy monitoring system using IoT sensors, cloud infrastructure, and machine learning.

This project combines electrical engineering, cloud computing, and artificial intelligence to build an intelligent energy monitoring system.

Project Goals
Monitor electricity usage from sensors
Send data to the cloud
Store energy data
Use AI to predict power consumption
Visualize energy usage on a dashboard

\---

## &#x20;Quick Start

```bash
# 1. Copy env template and fill in your secrets
cp .env.example .env
# Edit .env — set strong passwords for MONGO, SECRET\_KEY, GRAFANA

# 2. Start the full stack
docker-compose up --build -d

# 3. Open the interfaces
#   API docs  → http://localhost:8000/docs
#   Grafana   → http://localhost:3000  (admin / your GRAFANA\_ADMIN\_PASSWORD)
#   Prometheus→ http://localhost:9090
```

\---

## Project Structure

```
energy-monitor/
├── .env.example              ← Copy to .env, never commit .env
├── .gitignore
├── docker-compose.yml
├── api/
│   ├── main.py               ← All routes (auth, devices, readings, anomalies)
│   ├── schemas.py            ← Pydantic + MongoDB document models
│   ├── security.py           ← JWT, bcrypt, API keys, token revocation
│   ├── database.py           ← Motor async MongoDB client + index setup
│   ├── requirements.txt
│   └── Dockerfile
├── prometheus/
│   ├── prometheus.yml
│   └── rules/energy\_alerts.yml
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/prometheus.yml
│   │   └── dashboards/dashboards.yml
│   └── dashboards/energy\_monitor.json   ← Pre-built dashboard (auto-loads)
└── mongo/
    └── init.js               ← Collection + TTL index setup
```

\---

## Authentication

### User JWT (for dashboard/app endpoints)

```bash
# Register
curl -X POST http://localhost:8000/api/v1/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{"email":"user@example.com","first\_name":"Jane","last\_name":"Smith",
       "password":"SecurePass1","address":{"country":"ZA"}}'

# Login — get access + refresh tokens
curl -X POST http://localhost:8000/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email":"user@example.com","password":"SecurePass1"}'

# Use the access\_token on protected routes
curl http://localhost:8000/api/v1/users/me \\
  -H "Authorization: Bearer <access\_token>"

# Logout (revokes current token)
curl -X POST http://localhost:8000/api/v1/auth/logout \\
  -H "Authorization: Bearer <access\_token>"
```

### Device API Key (for IoT sensors)

```bash
# 1. Register a device (JWT required)
curl -X POST http://localhost:8000/api/v1/devices \\
  -H "Authorization: Bearer <access\_token>" \\
  -H "Content-Type: application/json" \\
  -d '{"name":"Main DB","device\_type":"smart\_meter","location":"main-panel","phases":\["L1","L2","L3"]}'

# Response includes api\_key — save it, shown once only!

# 2. Send readings using the device api\_key
curl -X POST http://localhost:8000/api/v1/readings \\
  -H "X-Device-API-Key: ems\_<your\_device\_api\_key>" \\
  -H "Content-Type: application/json" \\
  -d '{"device\_key":"dev\_xxx","phase":"L1","voltage":230.5,"current":12.3,
       "power\_watts":2829,"energy\_kwh":145.6,"power\_factor":0.95,"frequency\_hz":50}'
```

\---

## API Reference

### Auth

|Method|Path|Auth|Description|
|-|-|-|-|
|POST|`/api/v1/auth/register`|—|Create account|
|POST|`/api/v1/auth/login`|—|Get JWT tokens|
|POST|`/api/v1/auth/logout`|JWT|Revoke current token|
|POST|`/api/v1/auth/logout-all`|JWT|Revoke all sessions|
|POST|`/api/v1/auth/refresh`|Refresh token|Issue new token pair|
|POST|`/api/v1/auth/change-password`|JWT|Change password|
|POST|`/api/v1/auth/forgot-password`|—|Request reset token|
|POST|`/api/v1/auth/reset-password`|—|Apply reset token|
|POST|`/api/v1/auth/request-verification`|JWT|Request email verification|
|GET|`/api/v1/auth/verify-email?token=`|—|Verify email address|

### User Account

|Method|Path|Description|
|-|-|-|
|GET|`/api/v1/users/me`|Get profile|
|PATCH|`/api/v1/users/me`|Update profile|
|DELETE|`/api/v1/users/me`|Delete account (soft)|
|GET|`/api/v1/users/me/settings`|Get settings|
|PATCH|`/api/v1/users/me/settings`|Update settings|
|GET|`/api/v1/users/me/subscription`|Get subscription|
|POST|`/api/v1/users/me/subscription/upgrade?tier=pro`|Upgrade tier|

### Devices

|Method|Path|Auth|Description|
|-|-|-|-|
|GET|`/api/v1/devices`|JWT|List all devices (paginated)|
|POST|`/api/v1/devices`|JWT|Register new device|
|GET|`/api/v1/devices/{key}`|JWT|Get single device|
|PATCH|`/api/v1/devices/{key}`|JWT|Update device|
|DELETE|`/api/v1/devices/{key}`|JWT|Delete device + its readings|
|POST|`/api/v1/devices/{key}/rotate-key`|JWT|Rotate device API key|

### Energy Data

|Method|Path|Auth|Description|
|-|-|-|-|
|POST|`/api/v1/readings`|Device key|Ingest single reading|
|POST|`/api/v1/readings/bulk`|Device key|Ingest batch readings|
|GET|`/api/v1/readings`|JWT|Query historical readings|
|GET|`/api/v1/readings/summary`|JWT|Aggregated energy summary|
|POST|`/api/v1/anomalies`|Device key|Report anomaly|
|GET|`/api/v1/anomalies`|JWT|List anomalies|

\---

## Prometheus Metrics

Every metric carries **8 labels** for fine-grained Grafana filtering:

`user\_id` · `user\_email` · `subscription\_tier` · `device\_key` · `device\_name` · `device\_type` · `location` · `phase`

|Metric|Type|
|-|-|
|`energy\_consumption\_kwh`|Gauge|
|`power\_watts`|Gauge|
|`voltage\_volts`|Gauge|
|`current\_amperes`|Gauge|
|`power\_factor`|Gauge|
|`frequency\_hz`|Gauge|
|`sensor\_temperature\_celsius`|Gauge|
|`sensor\_readings\_total`|Counter|
|`energy\_anomalies\_total`|Counter|
|`sensor\_reading\_latency\_seconds`|Histogram|
|`user\_device\_count`|Gauge|
|`active\_users\_total`|Gauge|

\---

## Subscription Tiers

|Tier|Max Devices|History|AI Insights|
|-|-|-|-|
|FREE|1|7 days|✗|
|BASIC|5|30 days|✗|
|PRO|20|1 year|✓|
|ENTERPRISE|Unlimited|10 years|✓|

Old readings outside the history window are **automatically expired** via MongoDB TTL indexes — no manual cleanup needed.

\---

## &#x20;Stop / Reset

```bash
docker-compose down          # stop
docker-compose down -v       # stop + wipe all data volumes
```

