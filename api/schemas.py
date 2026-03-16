"""
schemas.py — MongoDB document schemas for Smart Energy Monitoring System
"""

from datetime import datetime
from enum import Enum
from typing import Annotated, Any
from bson import ObjectId
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from pydantic.functional_validators import BeforeValidator


# ─── ObjectId helper ──────────────────────────────────────────────────────────

def validate_object_id(v: Any) -> str:
    if isinstance(v, ObjectId):
        return str(v)
    if isinstance(v, str) and ObjectId.is_valid(v):
        return v
    raise ValueError(f"Invalid ObjectId: {v}")

PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]


# ─── Enums ────────────────────────────────────────────────────────────────────

class SubscriptionTier(str, Enum):
    FREE       = "free"
    BASIC      = "basic"
    PRO        = "pro"
    ENTERPRISE = "enterprise"

class SubscriptionStatus(str, Enum):
    ACTIVE    = "active"
    TRIALING  = "trialing"
    PAST_DUE  = "past_due"
    CANCELLED = "cancelled"
    PAUSED    = "paused"

class DeviceType(str, Enum):
    SMART_METER    = "smart_meter"
    CLAMP_SENSOR   = "clamp_sensor"
    SOLAR_INVERTER = "solar_inverter"
    EV_CHARGER     = "ev_charger"
    HVAC           = "hvac"
    GENERAL        = "general"

class DeviceStatus(str, Enum):
    ONLINE   = "online"
    OFFLINE  = "offline"
    DEGRADED = "degraded"
    PENDING  = "pending"

class AlertChannel(str, Enum):
    EMAIL = "email"
    SMS   = "sms"
    PUSH  = "push"

class ThemePreference(str, Enum):
    LIGHT  = "light"
    DARK   = "dark"
    SYSTEM = "system"

class UserRole(str, Enum):
    OWNER  = "owner"
    ADMIN  = "admin"
    VIEWER = "viewer"


# ─── Embedded sub-documents ───────────────────────────────────────────────────

class Address(BaseModel):
    street:      str | None = None
    city:        str | None = None
    province:    str | None = None
    country:     str = "ZA"
    postal_code: str | None = None


class AlertThresholds(BaseModel):
    max_power_watts:           float = Field(default=5000.0, ge=0)
    min_voltage_volts:         float = Field(default=210.0,  ge=0)
    max_voltage_volts:         float = Field(default=250.0,  ge=0)
    min_power_factor:          float = Field(default=0.80,   ge=0, le=1)
    max_temperature_celsius:   float = Field(default=70.0,   ge=-40, le=200)
    high_consumption_kwh_daily: float = Field(default=50.0,  ge=0)


class NotificationPreferences(BaseModel):
    channels:          list[AlertChannel] = [AlertChannel.EMAIL]
    alert_thresholds:  AlertThresholds    = Field(default_factory=AlertThresholds)
    quiet_hours_start: str | None = None
    quiet_hours_end:   str | None = None
    weekly_report:     bool = True
    anomaly_alerts:    bool = True
    billing_alerts:    bool = True


class DashboardWidget(BaseModel):
    widget_id:   str
    widget_type: str
    position_x:  int = 0
    position_y:  int = 0
    width:       int = 2
    height:      int = 2
    config:      dict[str, Any] = Field(default_factory=dict)


class DeviceMetadata(BaseModel):
    manufacturer:    str | None = None
    model:           str | None = None
    firmware:        str | None = None
    serial_number:   str | None = None
    install_date:    datetime | None = None
    warranty_expiry: datetime | None = None
    notes:           str | None = None
    tags:            list[str] = []


# ═══════════════════════════════════════════════════════════════════
#  DEVICE
# ═══════════════════════════════════════════════════════════════════

class DeviceBase(BaseModel):
    name:        str        = Field(..., min_length=1, max_length=100)
    device_type: DeviceType = DeviceType.GENERAL
    location:    str        = Field(...)
    phases:      list[str]  = Field(default=["L1"])
    metadata:    DeviceMetadata = Field(default_factory=DeviceMetadata)


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    name:        str | None = Field(default=None, min_length=1, max_length=100)
    device_type: DeviceType | None = None
    location:    str | None = None
    phases:      list[str] | None = None
    metadata:    DeviceMetadata | None = None


# ═══════════════════════════════════════════════════════════════════
#  SUBSCRIPTION
# ═══════════════════════════════════════════════════════════════════

TIER_LIMITS: dict[SubscriptionTier, dict] = {
    SubscriptionTier.FREE:       {"max_devices": 1,       "history_days": 7,    "ai_insights": False},
    SubscriptionTier.BASIC:      {"max_devices": 5,       "history_days": 30,   "ai_insights": False},
    SubscriptionTier.PRO:        {"max_devices": 20,      "history_days": 365,  "ai_insights": True},
    SubscriptionTier.ENTERPRISE: {"max_devices": 999_999, "history_days": 3650, "ai_insights": True},
}


# ═══════════════════════════════════════════════════════════════════
#  USER SETTINGS
# ═══════════════════════════════════════════════════════════════════

class UserSettingsUpdate(BaseModel):
    theme:               ThemePreference | None = None
    language:            str | None = None
    timezone:            str | None = None
    currency:            str | None = None
    energy_rate_per_kwh: float | None = None
    notifications:       NotificationPreferences | None = None
    show_co2_equivalent: bool | None = None
    co2_kg_per_kwh:      float | None = None
    date_format:         str | None = None
    api_access_enabled:  bool | None = None
    dashboard_widgets:   list[DashboardWidget] | None = None


# ═══════════════════════════════════════════════════════════════════
#  USER ACCOUNT
# ═══════════════════════════════════════════════════════════════════

class UserBase(BaseModel):
    email:      EmailStr
    first_name: str     = Field(..., min_length=1, max_length=100)
    last_name:  str     = Field(..., min_length=1, max_length=100)
    phone:      str | None = None
    address:    Address = Field(default_factory=Address)
    role:       UserRole = UserRole.OWNER


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserResponse(UserBase):
    id:           str
    is_active:    bool
    is_verified:  bool
    last_login:   datetime | None
    device_count: int = 0
    created_at:   datetime

    model_config = {"populate_by_name": True}


class UserUpdate(BaseModel):
    first_name: str | None = None
    last_name:  str | None = None
    phone:      str | None = None
    address:    Address | None = None


# ─── Auth Schemas ──────────────────────────────────────────────────

class TokenData(BaseModel):
    user_id: str
    email:   str
    role:    UserRole
    tier:    SubscriptionTier = SubscriptionTier.FREE


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str = Field(..., min_length=8)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Must contain at least one digit")
        return v


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token:        str
    new_password: str = Field(..., min_length=8)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Must contain at least one digit")
        return v


# ─── Energy Schemas ────────────────────────────────────────────────

class EnergyReading(BaseModel):
    device_key:          str   = Field(...)
    phase:               str   = Field(default="L1")
    voltage:             float = Field(..., ge=0, le=1000)
    current:             float = Field(..., ge=0, le=1000)
    power_watts:         float = Field(..., ge=0)
    energy_kwh:          float = Field(..., ge=0)
    power_factor:        float = Field(default=1.0, ge=0, le=1.0)
    frequency_hz:        float = Field(default=50.0, ge=45.0, le=65.0)
    temperature_celsius: float | None = Field(default=None, ge=-40, le=150)
    timestamp:           float | None = None


class BulkEnergyReading(BaseModel):
    readings: list[EnergyReading]


class AnomalyReport(BaseModel):
    device_key:   str
    anomaly_type: str = Field(..., example="voltage_spike")
    description:  str | None = None


class ReadingQueryParams(BaseModel):
    device_key: str | None = None
    phase:      str | None = None
    start:      datetime | None = None
    end:        datetime | None = None
    limit:      int = Field(default=100, ge=1, le=1000)
    skip:       int = Field(default=0, ge=0)


class APIResponse(BaseModel):
    status:    str
    message:   str
    processed: int = 1
    data:      Any = None


# ─── MongoDB Index Definitions ─────────────────────────────────────

MONGO_INDEXES = {
    "users": [
        {"key": [("email", 1)],       "unique": True,  "name": "email_unique"},
        {"key": [("created_at", -1)], "name": "created_at_desc"},
    ],
    "devices": [
        {"key": [("device_key", 1)],  "unique": True,  "name": "device_key_unique"},
        {"key": [("user_id", 1)],     "name": "user_id_idx"},
        {"key": [("api_key_hash", 1)], "unique": True, "name": "api_key_hash_unique"},
        {"key": [("status", 1)],      "name": "status_idx"},
    ],
    "subscriptions": [
        {"key": [("user_id", 1)],                  "unique": True, "name": "user_id_unique"},
        {"key": [("stripe_subscription_id", 1)],   "sparse": True, "name": "stripe_sub_idx"},
    ],
    "user_settings": [
        {"key": [("user_id", 1)],     "unique": True,  "name": "user_id_unique"},
    ],
    "energy_readings": [
        {"key": [("device_key", 1), ("timestamp", -1)], "name": "device_ts_idx"},
        {"key": [("user_id", 1),    ("timestamp", -1)], "name": "user_ts_idx"},
        {"key": [("timestamp", -1)],                    "name": "ts_desc"},
        # TTL indexes per tier are managed dynamically; this is the fallback
        {"key": [("expires_at", 1)], "expireAfterSeconds": 0, "name": "ttl_expires"},
    ],
    "revoked_tokens": [
        {"key": [("jti", 1)],        "unique": True,  "name": "jti_unique"},
        {"key": [("expires_at", 1)], "expireAfterSeconds": 0, "name": "ttl_revoked"},
    ],
    "password_reset_tokens": [
        {"key": [("token_hash", 1)], "unique": True,  "name": "token_hash_unique"},
        {"key": [("user_id", 1)],    "name": "user_id_idx"},
        {"key": [("expires_at", 1)], "expireAfterSeconds": 0, "name": "ttl_reset"},
    ],
}
