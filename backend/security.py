import os
import secrets
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME")
JWT_ALG = "HS256"
ACCESS_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash((password or "")[:72])

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify((password or "")[:72], hashed)

def create_user_jwt(email: str) -> str:
    exp = datetime.utcnow() + timedelta(minutes=ACCESS_MINUTES)
    payload = {"sub": email, "scp": "user", "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def create_agent_jwt(email: str, device_id: str) -> str:
    exp = datetime.utcnow() + timedelta(days=30)
    payload = {"sub": email, "scp": "agent", "did": device_id, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def new_device_id() -> str:
    return "kc_dev_" + secrets.token_urlsafe(16)
