import os
import hashlib
import secrets
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext

SECRET_KEY = os.getenv("JWT_SECRET", "CHANGE_ME")
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    # bcrypt limit: 72 bytes
    return pwd_context.hash(password[:72])

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password[:72], hashed)

def create_user_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(days=1)
    payload = {"sub": email, "exp": expire, "scp": "user"}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_agent_token(email: str, device_id: str) -> str:
    expire = datetime.utcnow() + timedelta(days=30)
    payload = {"sub": email, "did": device_id, "exp": expire, "scp": "agent"}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def make_activation_token() -> str:
    return "kc_live_" + secrets.token_urlsafe(32)

def hash_activation_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
