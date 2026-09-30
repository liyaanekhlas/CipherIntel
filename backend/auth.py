"""
SentinelScope Authentication Module.

Handles in-memory user storage, password hashing with bcrypt,
JWT creation and validation, and FastAPI authentication dependencies.
Strict constraint: All data is stored in in-memory Python structures.
"""

import os
import warnings
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# Suppress key length warning if user environment secret key is slightly under 32 bytes
warnings.filterwarnings("ignore", message=".*HMAC key is.*")

# Load environment configuration (.env with fallback to api-keys.env)
load_dotenv()
load_dotenv("api-keys.env")

# JWT configuration
JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "sentinelscope_default_secret_key_2026")
JWT_ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours default validity

# In-memory storage mapping username -> {"hashed_password": str, "created_at": str}
USERS_DB: Dict[str, Dict[str, Any]] = {}

# Security scheme for Bearer token extraction
security = HTTPBearer(auto_error=True)


def hash_password(password: str) -> str:
    """Hashes a plain-text password using bcrypt with a generated salt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain-text password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Encodes a JWT token containing data payload and expiration timestamp."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decodes and validates a JWT token using the configured secret key."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """
    FastAPI dependency extracting Bearer token from the Authorization header
    and confirming user existence in USERS_DB. Returns the authenticated username.
    """
    token = credentials.credentials
    payload = decode_access_token(token)
    username: Optional[str] = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if username not in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists in session store",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username
