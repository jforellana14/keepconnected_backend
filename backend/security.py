from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import os

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME")
JWT_ALGO = "HS256"

def hash_password(p: str) -> str:
    return pwd.hash(p[:72])

def verify_password(p: str, h: str) -> bool:
    return pwd.verify(p[:72], h)

def create_token(email: str, scope: str):
    payload = {
        "sub": email,
        "scp": scope,
        "exp": datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
