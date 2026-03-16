"""
security.py — JWT, password hashing, API keys, token revocation
"""

import os
import uuid
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from jose import JWTError, jwt
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorDatabase

from database import get_db
from schemas import TokenData, UserRole, SubscriptionTier

logger = logging.getLogger(__name__)

SECRET_KEY        = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_USE_32_CHARS_MIN")
ALGORITHM         = "HS256"
ACCESS_TOKEN_TTL  = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "60"))
REFRESH_TOKEN_TTL = int(os.getenv("REFRESH_TOKEN_TTL_DAYS",   "30"))

pwd_context    = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme  = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-Device-API-Key", auto_error=False)


# ─── Password ─────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ─── Device API keys ──────────────────────────────────────────────

def generate_api_key() -> tuple[str, str]:
    """Returns (raw_key, hashed_key). Only store the hash."""
    raw    = "ems_" + secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed

def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ─── JWT ──────────────────────────────────────────────────────────

def create_access_token(data: TokenData) -> tuple[str, str]:
    """Returns (token, jti). Store jti to enable revocation."""
    jti     = str(uuid.uuid4())
    payload = data.model_dump()
    payload["exp"]  = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_TTL)
    payload["type"] = "access"
    payload["jti"]  = jti
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM), jti


def create_refresh_token(user_id: str) -> tuple[str, str]:
    """Returns (token, jti)."""
    jti     = str(uuid.uuid4())
    payload = {
        "sub":  user_id,
        "exp":  datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_TTL),
        "type": "refresh",
        "jti":  jti,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM), jti


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def revoke_token(jti: str, expires_at: datetime, db: AsyncIOMotorDatabase):
    """Add a token's JTI to the revocation list."""
    try:
        await db["revoked_tokens"].insert_one({
            "jti":        jti,
            "revoked_at": datetime.utcnow(),
            "expires_at": expires_at,
        })
    except Exception:
        pass  # duplicate insert means already revoked — fine


async def is_token_revoked(jti: str, db: AsyncIOMotorDatabase) -> bool:
    doc = await db["revoked_tokens"].find_one({"jti": jti})
    return doc is not None


# ─── FastAPI dependencies ─────────────────────────────────────────

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    db: AsyncIOMotorDatabase = Depends(get_db),
) -> TokenData:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Access token required")
    jti = payload.get("jti")
    if jti and await is_token_revoked(jti, db):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Malformed token")
    user = await db["users"].find_one({"_id": user_id, "is_active": True})
    if not user:
        raise HTTPException(status_code=401, detail="User not found or deactivated")
    return TokenData(
        user_id=str(user["_id"]),
        email=user["email"],
        role=user.get("role", UserRole.OWNER),
        tier=payload.get("tier", SubscriptionTier.FREE),
    )


async def get_device_by_api_key(
    api_key: Annotated[str | None, Security(api_key_header)],
    db: AsyncIOMotorDatabase = Depends(get_db),
) -> dict:
    if not api_key:
        raise HTTPException(status_code=401, detail="Device API key required")
    hashed = hash_api_key(api_key)
    device = await db["devices"].find_one({"api_key_hash": hashed})
    if not device:
        raise HTTPException(status_code=401, detail="Invalid device API key")
    return device


def require_role(*roles: UserRole):
    async def _check(current_user: TokenData = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return _check


def require_tier(*tiers: SubscriptionTier):
    async def _check(current_user: TokenData = Depends(get_current_user)):
        if current_user.tier not in tiers:
            raise HTTPException(
                status_code=403,
                detail=f"This feature requires one of: {[t.value for t in tiers]}"
            )
        return current_user
    return _check
