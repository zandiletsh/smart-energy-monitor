"""
main.py — Smart Energy Monitoring API v3 (complete)
Covers: auth, token revocation, password reset, device CRUD,
        historical readings storage + query, subscription enforcement,
        account deletion, Prometheus user-scoped metrics, rate limiting.
"""

import hashlib
import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorDatabase
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.requests import Request
from starlette.responses import Response

from database import close_db, connect_db, get_db
from schemas import (
    TIER_LIMITS, APIResponse, AnomalyReport, BulkEnergyReading,
    ChangePasswordRequest, DeviceCreate, DeviceUpdate, EnergyReading,
    ForgotPasswordRequest, LoginRequest, ResetPasswordRequest,
    SubscriptionTier, TokenData, TokenResponse, UserCreate, UserResponse,
    UserSettingsUpdate, UserUpdate,
)
from security import (
    create_access_token, create_refresh_token, decode_token,
    generate_api_key, get_current_user, get_device_by_api_key,
    hash_password, is_token_revoked, revoke_token, verify_password,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title="Smart Energy Monitoring API",
    description="Complete IoT energy monitoring — auth, devices, readings history, metrics",
    version="3.0.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)


# ═══════════════════════════════════════════════════════════════════
#  PROMETHEUS METRICS (fully user + device scoped)
# ═══════════════════════════════════════════════════════════════════

_U  = ["user_id", "user_email", "subscription_tier"]
_D  = ["device_key", "device_name", "device_type", "location"]
_ALL = _U + _D + ["phase"]
_BASE = _U + _D

ENERGY_KWH    = Gauge("energy_consumption_kwh",      "Cumulative kWh",        _ALL)
POWER_W       = Gauge("power_watts",                  "Instantaneous watts",   _ALL)
VOLTAGE_V     = Gauge("voltage_volts",                "Voltage in volts",      _ALL)
CURRENT_A     = Gauge("current_amperes",              "Current in amperes",    _ALL)
POWER_FACTOR  = Gauge("power_factor",                 "Power factor 0-1",      _BASE)
FREQUENCY_HZ  = Gauge("frequency_hz",                 "Grid frequency Hz",     _BASE)
TEMPERATURE_C = Gauge("sensor_temperature_celsius",   "Sensor temperature °C", _BASE)
READINGS_TOT  = Counter("sensor_readings_total",      "Total readings",        _BASE + ["status"])
READING_LAT   = Histogram("sensor_reading_latency_seconds", "Processing latency",
                           buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
ANOMALIES     = Counter("energy_anomalies_total",     "Anomalies detected",    _BASE + ["anomaly_type"])
USER_DEVICES  = Gauge("user_device_count",            "Devices per user",      _U)
ACTIVE_USERS  = Gauge("active_users_total",           "Active users per tier", ["subscription_tier"])


def _lbl(user: TokenData, device: dict, phase: str | None = None) -> dict:
    d = {
        "user_id":           user.user_id,
        "user_email":        user.email,
        "subscription_tier": user.tier.value,
        "device_key":        device.get("device_key", "unknown"),
        "device_name":       device.get("name", "unknown"),
        "device_type":       device.get("device_type", "general"),
        "location":          device.get("location", "unknown"),
    }
    if phase is not None:
        d["phase"] = phase
    return d

def _u_lbl(user: TokenData) -> dict:
    return {"user_id": user.user_id, "user_email": user.email,
            "subscription_tier": user.tier.value}


# ═══════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════

async def _get_device(db, user_id: str, device_key: str) -> dict:
    d = await db["devices"].find_one({"device_key": device_key, "user_id": user_id})
    if not d:
        raise HTTPException(404, "Device not found or not owned by you")
    return d

async def _get_sub(db, user_id: str) -> dict:
    sub = await db["subscriptions"].find_one({"user_id": user_id})
    return sub or {"tier": "free", "max_devices": 1, "history_days": 7,
                   "ai_insights_enabled": False, "status": "trialing"}

async def _resolve_token(user_id: str, db) -> TokenData:
    user = await db["users"].find_one({"_id": user_id})
    if not user:
        raise HTTPException(404, "Device owner not found")
    sub  = await _get_sub(db, user_id)
    tier = SubscriptionTier(sub["tier"])
    return TokenData(user_id=str(user["_id"]), email=user["email"],
                     role=user["role"], tier=tier)

def _safe_device(d: dict) -> dict:
    d = dict(d)
    d["id"] = str(d.pop("_id", ""))
    d.pop("api_key_hash", None)
    return d


# ═══════════════════════════════════════════════════════════════════
#  HEALTH
# ═══════════════════════════════════════════════════════════════════

@app.get("/", tags=["Health"])
async def root():
    return {"service": "Smart Energy Monitoring API v3", "docs": "/docs", "metrics": "/metrics"}

@app.get("/health", tags=["Health"])
async def health(db: AsyncIOMotorDatabase = Depends(get_db)):
    try:
        await db.command("ping")
        ok = True
    except Exception:
        ok = False
    return {"status": "healthy" if ok else "degraded", "mongo": ok, "ts": time.time()}


# ═══════════════════════════════════════════════════════════════════
#  AUTH — register / login / logout / refresh
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/v1/auth/register", response_model=UserResponse, status_code=201, tags=["Auth"])
@limiter.limit("5/minute")
async def register(request: Request, body: UserCreate,
                   db: AsyncIOMotorDatabase = Depends(get_db)):
    if await db["users"].find_one({"email": body.email}):
        raise HTTPException(409, "Email already registered")

    uid = str(ObjectId())
    now = datetime.utcnow()
    await db["users"].insert_one({
        "_id": uid, "email": body.email,
        "first_name": body.first_name, "last_name": body.last_name,
        "phone": body.phone, "address": body.address.model_dump(),
        "role": body.role.value, "hashed_password": hash_password(body.password),
        "is_active": True, "is_verified": False, "login_count": 0,
        "device_ids": [], "created_at": now, "updated_at": now,
    })
    sub_id      = str(ObjectId())
    settings_id = str(ObjectId())
    await db["subscriptions"].insert_one({
        "_id": sub_id, "user_id": uid,
        "tier": SubscriptionTier.FREE.value, "status": "trialing",
        "max_devices": 1, "history_days": 7, "ai_insights_enabled": False,
        "created_at": now, "updated_at": now,
    })
    await db["user_settings"].insert_one({
        "_id": settings_id, "user_id": uid,
        "theme": "system", "language": "en", "timezone": "Africa/Johannesburg",
        "currency": "ZAR", "energy_rate_per_kwh": 2.50, "dashboard_widgets": [],
        "notifications": {}, "show_co2_equivalent": True, "co2_kg_per_kwh": 0.9,
        "date_format": "DD/MM/YYYY", "api_access_enabled": False,
        "created_at": now, "updated_at": now,
    })
    await db["users"].update_one({"_id": uid},
        {"$set": {"subscription_id": sub_id, "settings_id": settings_id}})

    ACTIVE_USERS.labels(subscription_tier=SubscriptionTier.FREE.value).inc()
    logger.info(f"Registered: {body.email}")
    return UserResponse(id=uid, email=body.email, first_name=body.first_name,
                        last_name=body.last_name, phone=body.phone,
                        address=body.address, role=body.role,
                        is_active=True, is_verified=False, last_login=None,
                        device_count=0, created_at=now)


@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["Auth"])
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest,
                db: AsyncIOMotorDatabase = Depends(get_db)):
    user = await db["users"].find_one({"email": body.email, "is_active": True})
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(401, "Invalid credentials")
    sub  = await _get_sub(db, user["_id"])
    tier = SubscriptionTier(sub["tier"])
    td   = TokenData(user_id=str(user["_id"]), email=user["email"],
                     role=user["role"], tier=tier)
    access_token,  _  = create_access_token(td)
    refresh_token, _  = create_refresh_token(str(user["_id"]))
    await db["users"].update_one({"_id": user["_id"]},
        {"$set": {"last_login": datetime.utcnow()}, "$inc": {"login_count": 1}})
    return TokenResponse(access_token=access_token, refresh_token=refresh_token, expires_in=3600)


@app.post("/api/v1/auth/logout", tags=["Auth"])
async def logout(request: Request,
                 current_user: TokenData = Depends(get_current_user),
                 db: AsyncIOMotorDatabase = Depends(get_db)):
    """Revoke the current access token so it can't be reused."""
    auth    = request.headers.get("Authorization", "")[7:]
    payload = decode_token(auth)
    jti     = payload.get("jti")
    exp     = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    if jti:
        await revoke_token(jti, exp, db)
    return {"status": "success", "message": "Logged out — token revoked"}


@app.post("/api/v1/auth/logout-all", tags=["Auth"])
async def logout_all(request: Request,
                     current_user: TokenData = Depends(get_current_user),
                     db: AsyncIOMotorDatabase = Depends(get_db)):
    """Revoke ALL tokens for this user by rotating a server-side generation counter."""
    await db["users"].update_one(
        {"_id": current_user.user_id},
        {"$inc": {"token_generation": 1}, "$set": {"updated_at": datetime.utcnow()}}
    )
    return {"status": "success", "message": "All sessions revoked"}


@app.post("/api/v1/auth/refresh", response_model=TokenResponse, tags=["Auth"])
@limiter.limit("20/minute")
async def refresh_token(request: Request, db: AsyncIOMotorDatabase = Depends(get_db)):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Refresh token required")
    payload = decode_token(auth[7:])
    if payload.get("type") != "refresh":
        raise HTTPException(401, "Refresh token required")
    jti = payload.get("jti")
    if jti and await is_token_revoked(jti, db):
        raise HTTPException(401, "Refresh token has been revoked")
    user = await db["users"].find_one({"_id": payload["sub"], "is_active": True})
    if not user:
        raise HTTPException(401, "User not found")
    # Rotate: revoke old refresh token, issue new pair
    if jti:
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        await revoke_token(jti, exp, db)
    sub  = await _get_sub(db, user["_id"])
    tier = SubscriptionTier(sub["tier"])
    td   = TokenData(user_id=str(user["_id"]), email=user["email"],
                     role=user["role"], tier=tier)
    access_token,  _ = create_access_token(td)
    new_refresh,   _ = create_refresh_token(str(user["_id"]))
    return TokenResponse(access_token=access_token, refresh_token=new_refresh, expires_in=3600)


# ═══════════════════════════════════════════════════════════════════
#  PASSWORD MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/v1/auth/change-password", tags=["Auth"])
async def change_password(body: ChangePasswordRequest,
                          current_user: TokenData = Depends(get_current_user),
                          db: AsyncIOMotorDatabase = Depends(get_db)):
    user = await db["users"].find_one({"_id": current_user.user_id})
    if not verify_password(body.current_password, user["hashed_password"]):
        raise HTTPException(400, "Current password is incorrect")
    await db["users"].update_one(
        {"_id": current_user.user_id},
        {"$set": {"hashed_password": hash_password(body.new_password),
                  "updated_at": datetime.utcnow()}}
    )
    return {"status": "success", "message": "Password updated"}


@app.post("/api/v1/auth/forgot-password", tags=["Auth"])
@limiter.limit("3/minute")
async def forgot_password(request: Request, body: ForgotPasswordRequest,
                          db: AsyncIOMotorDatabase = Depends(get_db)):
    """
    Generate a password-reset token. In production wire this to an email
    service (SendGrid, SES, etc.). The token is returned here for development.
    """
    user = await db["users"].find_one({"email": body.email, "is_active": True})
    # Always return 200 to prevent email enumeration
    if not user:
        return {"status": "success", "message": "If that email exists, a reset link has been sent"}

    raw_token   = secrets.token_urlsafe(32)
    token_hash  = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at  = datetime.utcnow() + timedelta(hours=1)

    # Remove any existing reset tokens for this user
    await db["password_reset_tokens"].delete_many({"user_id": str(user["_id"])})
    await db["password_reset_tokens"].insert_one({
        "_id":        str(ObjectId()),
        "user_id":    str(user["_id"]),
        "token_hash": token_hash,
        "expires_at": expires_at,
        "used":       False,
        "created_at": datetime.utcnow(),
    })
    logger.info(f"Password reset requested for {body.email}")
    # TODO: replace this with actual email delivery in production
    return {"status": "success",
            "message": "Reset token generated",
            "reset_token": raw_token,   # REMOVE in production — send via email only
            "expires_in_minutes": 60}


@app.post("/api/v1/auth/reset-password", tags=["Auth"])
async def reset_password(body: ResetPasswordRequest,
                         db: AsyncIOMotorDatabase = Depends(get_db)):
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    doc = await db["password_reset_tokens"].find_one({
        "token_hash": token_hash,
        "used":       False,
        "expires_at": {"$gt": datetime.utcnow()},
    })
    if not doc:
        raise HTTPException(400, "Invalid or expired reset token")

    await db["users"].update_one(
        {"_id": doc["user_id"]},
        {"$set": {"hashed_password": hash_password(body.new_password),
                  "updated_at": datetime.utcnow()}}
    )
    await db["password_reset_tokens"].update_one(
        {"_id": doc["_id"]}, {"$set": {"used": True}}
    )
    return {"status": "success", "message": "Password has been reset. Please log in again."}


# ═══════════════════════════════════════════════════════════════════
#  EMAIL VERIFICATION
# ═══════════════════════════════════════════════════════════════════

@app.post("/api/v1/auth/request-verification", tags=["Auth"])
@limiter.limit("3/minute")
async def request_verification(request: Request,
                                current_user: TokenData = Depends(get_current_user),
                                db: AsyncIOMotorDatabase = Depends(get_db)):
    user = await db["users"].find_one({"_id": current_user.user_id})
    if user.get("is_verified"):
        return {"status": "already_verified"}

    raw_token  = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = datetime.utcnow() + timedelta(hours=24)

    await db["email_verification_tokens"].replace_one(
        {"user_id": current_user.user_id},
        {"_id": str(ObjectId()), "user_id": current_user.user_id,
         "token_hash": token_hash, "expires_at": expires_at, "created_at": datetime.utcnow()},
        upsert=True,
    )
    # TODO: send email in production
    return {"status": "success", "verification_token": raw_token,
            "message": "Verification token generated (send via email in production)"}


@app.get("/api/v1/auth/verify-email", tags=["Auth"])
async def verify_email(token: str = Query(...),
                       db: AsyncIOMotorDatabase = Depends(get_db)):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    doc = await db["email_verification_tokens"].find_one({
        "token_hash": token_hash,
        "expires_at": {"$gt": datetime.utcnow()},
    })
    if not doc:
        raise HTTPException(400, "Invalid or expired verification token")
    await db["users"].update_one(
        {"_id": doc["user_id"]},
        {"$set": {"is_verified": True, "email_verified_at": datetime.utcnow()}}
    )
    await db["email_verification_tokens"].delete_one({"_id": doc["_id"]})
    return {"status": "success", "message": "Email verified"}


# ═══════════════════════════════════════════════════════════════════
#  USER ACCOUNT
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/v1/users/me", response_model=UserResponse, tags=["User Account"])
async def get_me(current_user: TokenData = Depends(get_current_user),
                 db: AsyncIOMotorDatabase = Depends(get_db)):
    user = await db["users"].find_one({"_id": current_user.user_id})
    if not user:
        raise HTTPException(404, "User not found")
    return UserResponse(
        id=str(user["_id"]), email=user["email"],
        first_name=user["first_name"], last_name=user["last_name"],
        phone=user.get("phone"), address=user.get("address", {}),
        role=user["role"], is_active=user["is_active"],
        is_verified=user["is_verified"], last_login=user.get("last_login"),
        device_count=len(user.get("device_ids", [])), created_at=user["created_at"],
    )


@app.patch("/api/v1/users/me", response_model=UserResponse, tags=["User Account"])
async def update_me(body: UserUpdate,
                    current_user: TokenData = Depends(get_current_user),
                    db: AsyncIOMotorDatabase = Depends(get_db)):
    updates = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    if not updates:
        raise HTTPException(400, "No fields to update")
    updates["updated_at"] = datetime.utcnow()
    await db["users"].update_one({"_id": current_user.user_id}, {"$set": updates})
    return await get_me(current_user, db)


@app.delete("/api/v1/users/me", tags=["User Account"])
async def delete_account(current_user: TokenData = Depends(get_current_user),
                          db: AsyncIOMotorDatabase = Depends(get_db)):
    """
    Soft-delete: marks the account inactive and anonymises PII.
    Hard-delete all devices and readings for this user.
    """
    uid = current_user.user_id
    # Remove all devices
    await db["devices"].delete_many({"user_id": uid})
    # Remove all readings
    await db["energy_readings"].delete_many({"user_id": uid})
    # Soft-delete user (keep record for billing audit trail)
    await db["users"].update_one({"_id": uid}, {"$set": {
        "is_active":    False,
        "email":        f"deleted_{uid}@deleted.invalid",
        "first_name":   "Deleted",
        "last_name":    "User",
        "phone":        None,
        "deleted_at":   datetime.utcnow(),
        "updated_at":   datetime.utcnow(),
    }})
    ACTIVE_USERS.labels(subscription_tier=current_user.tier.value).dec()
    logger.info(f"Account soft-deleted: {uid}")
    return {"status": "success", "message": "Account deleted"}


# ═══════════════════════════════════════════════════════════════════
#  USER SETTINGS
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/v1/users/me/settings", tags=["User Settings"])
async def get_settings(current_user: TokenData = Depends(get_current_user),
                       db: AsyncIOMotorDatabase = Depends(get_db)):
    s = await db["user_settings"].find_one({"user_id": current_user.user_id})
    if not s:
        raise HTTPException(404, "Settings not found")
    s["id"] = str(s.pop("_id"))
    return s


@app.patch("/api/v1/users/me/settings", tags=["User Settings"])
async def update_settings(body: UserSettingsUpdate,
                           current_user: TokenData = Depends(get_current_user),
                           db: AsyncIOMotorDatabase = Depends(get_db)):
    updates = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    if not updates:
        raise HTTPException(400, "No fields to update")
    updates["updated_at"] = datetime.utcnow()
    await db["user_settings"].update_one(
        {"user_id": current_user.user_id}, {"$set": updates})
    return await get_settings(current_user, db)


# ═══════════════════════════════════════════════════════════════════
#  SUBSCRIPTION
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/v1/users/me/subscription", tags=["Subscription"])
async def get_subscription(current_user: TokenData = Depends(get_current_user),
                            db: AsyncIOMotorDatabase = Depends(get_db)):
    sub = await db["subscriptions"].find_one({"user_id": current_user.user_id})
    if not sub:
        raise HTTPException(404, "Subscription not found")
    sub["id"] = str(sub.pop("_id"))
    return sub


@app.post("/api/v1/users/me/subscription/upgrade", tags=["Subscription"])
async def upgrade_subscription(
    tier: SubscriptionTier,
    current_user: TokenData = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """
    Upgrade subscription tier.
    In production this must be gated behind a Stripe payment confirmation webhook.
    The endpoint currently allows free upgrades — add Stripe verification before deploying.
    """
    limits = TIER_LIMITS[tier]
    await db["subscriptions"].update_one(
        {"user_id": current_user.user_id},
        {"$set": {
            "tier":                tier.value,
            "status":              "active",
            "max_devices":         limits["max_devices"],
            "history_days":        limits["history_days"],
            "ai_insights_enabled": limits["ai_insights"],
            "updated_at":          datetime.utcnow(),
        }}
    )
    # Prune old readings that now fall outside the new history window (or expand — no-op)
    cutoff = datetime.utcnow() - timedelta(days=limits["history_days"])
    await db["energy_readings"].delete_many({
        "user_id":   current_user.user_id,
        "timestamp": {"$lt": cutoff},
    })
    logger.info(f"User {current_user.user_id} → {tier.value}")
    return {"status": "success", "new_tier": tier.value, "limits": limits}


# ═══════════════════════════════════════════════════════════════════
#  DEVICE MANAGEMENT — full CRUD
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/v1/devices", tags=["Devices"])
async def list_devices(current_user: TokenData = Depends(get_current_user),
                       db: AsyncIOMotorDatabase = Depends(get_db),
                       skip: int = Query(0, ge=0),
                       limit: int = Query(50, ge=1, le=200)):
    cursor  = db["devices"].find({"user_id": current_user.user_id}).skip(skip).limit(limit)
    devices = [_safe_device(d) async for d in cursor]
    total   = await db["devices"].count_documents({"user_id": current_user.user_id})
    return {"devices": devices, "count": len(devices), "total": total, "skip": skip, "limit": limit}


@app.get("/api/v1/devices/{device_key}", tags=["Devices"])
async def get_device(device_key: str,
                     current_user: TokenData = Depends(get_current_user),
                     db: AsyncIOMotorDatabase = Depends(get_db)):
    d = await _get_device(db, current_user.user_id, device_key)
    return _safe_device(d)


@app.post("/api/v1/devices", status_code=201, tags=["Devices"])
async def register_device(body: DeviceCreate,
                           current_user: TokenData = Depends(get_current_user),
                           db: AsyncIOMotorDatabase = Depends(get_db)):
    sub      = await _get_sub(db, current_user.user_id)
    max_devs = sub["max_devices"]
    count    = await db["devices"].count_documents({"user_id": current_user.user_id})
    if count >= max_devs:
        raise HTTPException(
            403,
            f"Device limit ({max_devs}) reached for your {sub['tier']} plan. "
            "Upgrade your subscription to add more devices."
        )
    raw_key, key_hash = generate_api_key()
    device_key = "dev_" + secrets.token_hex(8)
    now        = datetime.utcnow()
    doc = {
        "_id": str(ObjectId()), "user_id": current_user.user_id,
        "device_key": device_key, "api_key_hash": key_hash,
        "name": body.name, "device_type": body.device_type.value,
        "location": body.location, "phases": body.phases,
        "metadata": body.metadata.model_dump(),
        "status": "pending", "last_seen": None,
        "created_at": now, "updated_at": now,
    }
    await db["devices"].insert_one(doc)
    await db["users"].update_one(
        {"_id": current_user.user_id}, {"$addToSet": {"device_ids": doc["_id"]}})
    USER_DEVICES.labels(**_u_lbl(current_user)).inc()
    return {
        "id":         doc["_id"],
        "device_key": device_key,
        "api_key":    raw_key,
        "name":       body.name,
        "location":   body.location,
        "status":     "pending",
        "warning":    "Save your API key — it will not be shown again.",
    }


@app.patch("/api/v1/devices/{device_key}", tags=["Devices"])
async def update_device(device_key: str, body: DeviceUpdate,
                         current_user: TokenData = Depends(get_current_user),
                         db: AsyncIOMotorDatabase = Depends(get_db)):
    await _get_device(db, current_user.user_id, device_key)
    updates = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    if not updates:
        raise HTTPException(400, "No fields to update")
    updates["updated_at"] = datetime.utcnow()
    await db["devices"].update_one({"device_key": device_key}, {"$set": updates})
    d = await db["devices"].find_one({"device_key": device_key})
    return _safe_device(d)


@app.delete("/api/v1/devices/{device_key}", tags=["Devices"])
async def delete_device(device_key: str,
                         current_user: TokenData = Depends(get_current_user),
                         db: AsyncIOMotorDatabase = Depends(get_db)):
    device = await _get_device(db, current_user.user_id, device_key)
    await db["devices"].delete_one({"device_key": device_key})
    await db["energy_readings"].delete_many({"device_key": device_key})
    await db["users"].update_one(
        {"_id": current_user.user_id}, {"$pull": {"device_ids": device["_id"]}})
    USER_DEVICES.labels(**_u_lbl(current_user)).dec()
    return {"status": "deleted", "device_key": device_key}


@app.post("/api/v1/devices/{device_key}/rotate-key", tags=["Devices"])
async def rotate_key(device_key: str,
                      current_user: TokenData = Depends(get_current_user),
                      db: AsyncIOMotorDatabase = Depends(get_db)):
    await _get_device(db, current_user.user_id, device_key)
    raw_key, key_hash = generate_api_key()
    await db["devices"].update_one(
        {"device_key": device_key},
        {"$set": {"api_key_hash": key_hash, "updated_at": datetime.utcnow()}}
    )
    return {"api_key": raw_key, "warning": "Save your new API key — it will not be shown again."}


# ═══════════════════════════════════════════════════════════════════
#  ENERGY READINGS — ingest (device auth) + query (user JWT)
# ═══════════════════════════════════════════════════════════════════

async def _persist_reading(reading: EnergyReading, device: dict,
                            user_token: TokenData, db: AsyncIOMotorDatabase):
    """Write one reading to MongoDB and update Prometheus."""
    ts  = datetime.fromtimestamp(reading.timestamp) if reading.timestamp else datetime.utcnow()
    sub = await _get_sub(db, device["user_id"])
    expires_at = ts + timedelta(days=sub["history_days"])

    doc = {
        "_id":                 str(ObjectId()),
        "user_id":             device["user_id"],
        "device_key":          device["device_key"],
        "device_name":         device.get("name", ""),
        "location":            device.get("location", ""),
        "phase":               reading.phase,
        "voltage":             reading.voltage,
        "current":             reading.current,
        "power_watts":         reading.power_watts,
        "energy_kwh":          reading.energy_kwh,
        "power_factor":        reading.power_factor,
        "frequency_hz":        reading.frequency_hz,
        "temperature_celsius": reading.temperature_celsius,
        "timestamp":           ts,
        "expires_at":          expires_at,
    }
    await db["energy_readings"].insert_one(doc)
    return ts


@app.post("/api/v1/readings", response_model=APIResponse, tags=["Energy Data"])
@limiter.limit("120/minute")
async def ingest_reading(request: Request, reading: EnergyReading,
                          device: dict = Depends(get_device_by_api_key),
                          db: AsyncIOMotorDatabase = Depends(get_db)):
    start = time.time()
    try:
        ut   = await _resolve_token(device["user_id"], db)
        full = _lbl(ut, device, reading.phase)
        base = {k: v for k, v in full.items() if k != "phase"}

        ENERGY_KWH.labels(**full).set(reading.energy_kwh)
        POWER_W.labels(**full).set(reading.power_watts)
        VOLTAGE_V.labels(**full).set(reading.voltage)
        CURRENT_A.labels(**full).set(reading.current)
        POWER_FACTOR.labels(**base).set(reading.power_factor)
        FREQUENCY_HZ.labels(**base).set(reading.frequency_hz)
        if reading.temperature_celsius is not None:
            TEMPERATURE_C.labels(**base).set(reading.temperature_celsius)
        READINGS_TOT.labels(**base, status="success").inc()
        READING_LAT.observe(time.time() - start)

        await _persist_reading(reading, device, ut, db)
        await db["devices"].update_one(
            {"device_key": device["device_key"]},
            {"$set": {"last_seen": datetime.utcnow(), "status": "online"}})

        return APIResponse(status="success", message="Reading recorded")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Reading error: {e}")
        raise HTTPException(500, str(e))


@app.post("/api/v1/readings/bulk", response_model=APIResponse, tags=["Energy Data"])
@limiter.limit("30/minute")
async def ingest_bulk(request: Request, payload: BulkEnergyReading,
                       device: dict = Depends(get_device_by_api_key),
                       db: AsyncIOMotorDatabase = Depends(get_db)):
    processed, errors = 0, 0
    for r in payload.readings:
        try:
            await ingest_reading(request, r, device, db)
            processed += 1
        except Exception:
            errors += 1
    return APIResponse(
        status="success" if not errors else "partial",
        message=f"Processed {processed}/{len(payload.readings)}",
        processed=processed,
    )


@app.get("/api/v1/readings", tags=["Energy Data"])
async def query_readings(
    current_user: TokenData = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
    device_key: str | None = Query(None, description="Filter by specific device"),
    phase:      str | None = Query(None),
    start:      datetime | None = Query(None, description="ISO datetime — start of range"),
    end:        datetime | None = Query(None, description="ISO datetime — end of range"),
    limit:      int = Query(100, ge=1, le=1000),
    skip:       int = Query(0, ge=0),
):
    """
    Query historical energy readings for the authenticated user.
    Filtered by device, phase, and/or time range. Respects subscription history window.
    """
    sub     = await _get_sub(db, current_user.user_id)
    cutoff  = datetime.utcnow() - timedelta(days=sub["history_days"])
    q: dict = {"user_id": current_user.user_id, "timestamp": {"$gte": cutoff}}

    if device_key:
        # Verify ownership
        d = await db["devices"].find_one(
            {"device_key": device_key, "user_id": current_user.user_id})
        if not d:
            raise HTTPException(404, "Device not found or not yours")
        q["device_key"] = device_key
    if phase:
        q["phase"] = phase
    if start:
        q["timestamp"]["$gte"] = max(start, cutoff)
    if end:
        q["timestamp"]["$lte"] = end

    cursor = db["energy_readings"].find(q, {"_id": 0, "expires_at": 0}) \
                                   .sort("timestamp", -1).skip(skip).limit(limit)
    rows   = [r async for r in cursor]
    total  = await db["energy_readings"].count_documents(q)
    return {
        "readings":      rows,
        "count":         len(rows),
        "total":         total,
        "skip":          skip,
        "limit":         limit,
        "history_window": f"{sub['history_days']} days ({sub['tier']} plan)",
    }


@app.get("/api/v1/readings/summary", tags=["Energy Data"])
async def readings_summary(
    current_user: TokenData = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
    device_key: str | None = Query(None),
    period: str = Query("24h", description="Summary period: 1h | 24h | 7d | 30d"),
):
    """Aggregated energy summary — total kWh, avg power, peak power for a period."""
    period_map = {"1h": 1/24, "24h": 1, "7d": 7, "30d": 30}
    days = period_map.get(period, 1)
    since = datetime.utcnow() - timedelta(days=days)
    q: dict = {"user_id": current_user.user_id, "timestamp": {"$gte": since}}
    if device_key:
        q["device_key"] = device_key

    pipeline = [
        {"$match": q},
        {"$group": {
            "_id":          "$device_key",
            "device_name":  {"$first": "$device_name"},
            "location":     {"$first": "$location"},
            "total_kwh":    {"$sum": "$energy_kwh"},
            "avg_watts":    {"$avg": "$power_watts"},
            "peak_watts":   {"$max": "$power_watts"},
            "avg_voltage":  {"$avg": "$voltage"},
            "reading_count": {"$sum": 1},
            "last_seen":    {"$max": "$timestamp"},
        }},
        {"$sort": {"total_kwh": -1}},
    ]
    results = await db["energy_readings"].aggregate(pipeline).to_list(length=100)
    for r in results:
        r["device_key"] = r.pop("_id")
    return {"period": period, "since": since.isoformat(), "devices": results}


@app.post("/api/v1/anomalies", response_model=APIResponse, tags=["Anomalies"])
async def report_anomaly(anomaly: AnomalyReport,
                          device: dict = Depends(get_device_by_api_key),
                          db: AsyncIOMotorDatabase = Depends(get_db)):
    ut   = await _resolve_token(device["user_id"], db)
    base = _lbl(ut, device)
    ANOMALIES.labels(**base, anomaly_type=anomaly.anomaly_type).inc()
    await db["anomalies"].insert_one({
        "_id":          str(ObjectId()),
        "user_id":      device["user_id"],
        "device_key":   anomaly.device_key,
        "anomaly_type": anomaly.anomaly_type,
        "description":  anomaly.description,
        "timestamp":    datetime.utcnow(),
    })
    return APIResponse(status="success", message="Anomaly recorded")


@app.get("/api/v1/anomalies", tags=["Anomalies"])
async def list_anomalies(
    current_user: TokenData = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
    device_key: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    skip:  int = Query(0, ge=0),
):
    q: dict = {"user_id": current_user.user_id}
    if device_key:
        q["device_key"] = device_key
    cursor = db["anomalies"].find(q, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit)
    rows = [r async for r in cursor]
    return {"anomalies": rows, "count": len(rows)}


# ═══════════════════════════════════════════════════════════════════
#  PROMETHEUS SCRAPE
# ═══════════════════════════════════════════════════════════════════

@app.get("/metrics", tags=["Prometheus"], include_in_schema=False)
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
