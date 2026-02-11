import os
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr
from svix.webhooks import Webhook, WebhookVerificationError

from database import Base, engine, SessionLocal
from models import User, ActivationToken, Device
from security import hash_password, verify_password, create_user_token, create_agent_token, make_activation_token, hash_activation_token

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME")
JWT_ALGORITHM = "HS256"
RECURRENTE_WEBHOOK_SECRET = os.getenv("RECURRENTE_WEBHOOK_SECRET", "")
DEV_MODE = os.getenv("DEV_MODE", "0") == "1"

Base.metadata.create_all(bind=engine)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

def require_scope(token: str, scope: str) -> dict:
    try:
        payload = decode_token(token)
        if payload.get("scp") != scope:
            raise HTTPException(status_code=401, detail="Invalid token scope")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user_email(token: str = Depends(oauth2_scheme)) -> str:
    payload = require_scope(token, "user")
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token")
    return email

def get_current_agent(token: str = Depends(oauth2_scheme)) -> dict:
    return require_scope(token, "agent")

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ClaimRequest(BaseModel):
    activation_token: str
    device_id: str

class HeartbeatRequest(BaseModel):
    status: str = "ok"

class ReportRequest(BaseModel):
    window: str
    sent_at: Optional[datetime] = None

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/")
def root():
    return {"ok": True, "service": "KeepConnected API"}

@app.post("/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="User exists")
    user = User(email=payload.email, hashed_password=hash_password(payload.password), status="inactive")
    db.add(user)
    db.commit()
    return {"message": "User created", "status": user.status}

@app.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if (not user) or (not verify_password(payload.password, user.hashed_password)):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.status != "active":
        raise HTTPException(status_code=403, detail="Subscription inactive")
    token = create_user_token(user.email)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/activate/request")
def activation_request(current_email: str = Depends(get_current_user_email), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == current_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.status != "active":
        raise HTTPException(status_code=403, detail="Subscription inactive")
    token_plain = make_activation_token()
    token_hash = hash_activation_token(token_plain)
    now = datetime.utcnow()
    expires = now + timedelta(minutes=15)
    rec = ActivationToken(user_id=user.id, token_hash=token_hash, expires_at=expires, used_at=None, created_at=now)
    db.add(rec)
    db.commit()
    return {"activation_token": token_plain, "expires_at": expires.isoformat() + "Z"}

@app.post("/activate/claim")
def activation_claim(payload: ClaimRequest, db: Session = Depends(get_db)):
    token_hash = hash_activation_token(payload.activation_token)
    rec = db.query(ActivationToken).filter(ActivationToken.token_hash == token_hash).first()
    if not rec:
        raise HTTPException(status_code=400, detail="Invalid activation token")
    now = datetime.utcnow()
    if rec.used_at is not None:
        raise HTTPException(status_code=400, detail="Activation token already used")
    if rec.expires_at < now:
        raise HTTPException(status_code=400, detail="Activation token expired")
    user = db.query(User).filter(User.id == rec.user_id).first()
    if not user or user.status != "active":
        raise HTTPException(status_code=403, detail="User inactive")
    dev = db.query(Device).filter(Device.device_id == payload.device_id).first()
    if not dev:
        dev = Device(user_id=user.id, device_id=payload.device_id, created_at=now, last_seen_at=now)
        db.add(dev)
    else:
        if dev.user_id != user.id:
            raise HTTPException(status_code=400, detail="Device already claimed by another user")
        dev.last_seen_at = now
    rec.used_at = now
    db.commit()
    agent_token = create_agent_token(user.email, payload.device_id)
    return {"agent_token": agent_token, "token_type": "bearer"}

@app.get("/agent/config")
def agent_config(agent: dict = Depends(get_current_agent), db: Session = Depends(get_db)):
    email = agent.get("sub")
    device_id = agent.get("did")
    user = db.query(User).filter(User.email == email).first()
    if not user or user.status != "active":
        raise HTTPException(status_code=403, detail="User inactive")
    dev = db.query(Device).filter(Device.device_id == device_id).first()
    if not dev or dev.user_id != user.id:
        raise HTTPException(status_code=403, detail="Device not registered")
    return {"enabled": bool(user.enabled), "timezone": user.timezone,
            "morning": {"days": ["mon","tue","wed","thu","fri","sat"], "start": "09:00", "end": "11:00", "mood": "friendly"},
            "evening": {"days": ["mon","tue","wed","thu","fri"], "start": "16:00", "end": "18:00", "mood": "warm"},
            "templates": {"morning": user.morning_message, "evening": user.evening_message},
            "limits": {"max_per_window": 1}}

@app.post("/agent/heartbeat")
def agent_heartbeat(payload: HeartbeatRequest, agent: dict = Depends(get_current_agent), db: Session = Depends(get_db)):
    email = agent.get("sub")
    device_id = agent.get("did")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=403, detail="User not found")
    dev = db.query(Device).filter(Device.device_id == device_id).first()
    if not dev or dev.user_id != user.id:
        raise HTTPException(status_code=403, detail="Device not registered")
    dev.last_seen_at = datetime.utcnow()
    db.commit()
    return {"ok": True}

@app.post("/agent/report")
def agent_report(payload: ReportRequest, agent: dict = Depends(get_current_agent), db: Session = Depends(get_db)):
    email = agent.get("sub")
    device_id = agent.get("did")
    user = db.query(User).filter(User.email == email).first()
    if not user or user.status != "active":
        raise HTTPException(status_code=403, detail="User inactive")
    dev = db.query(Device).filter(Device.device_id == device_id).first()
    if not dev or dev.user_id != user.id:
        raise HTTPException(status_code=403, detail="Device not registered")
    when = payload.sent_at or datetime.utcnow()
    if payload.window == "morning":
        user.last_morning_sent = when
    elif payload.window == "evening":
        user.last_evening_sent = when
    db.commit()
    return {"ok": True}

def _dig(obj: Any, path: str) -> Optional[Any]:
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur

def extract_email(payload: dict) -> Optional[str]:
    candidates = ["customer.email","customer_email","email","metadata.email","data.customer.email","data.email","data.metadata.email"]
    for p in candidates:
        v = _dig(payload, p)
        if isinstance(v, str) and "@" in v:
            return v.strip()
    return None

@app.post("/payment/recurrente/webhook")
async def recurrente_webhook(request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    svix_id = request.headers.get("svix-id")
    svix_ts = request.headers.get("svix-timestamp")
    svix_sig = request.headers.get("svix-signature")
    if not (svix_id and svix_ts and svix_sig):
        return Response(content="Missing Svix headers", status_code=400)
    if not RECURRENTE_WEBHOOK_SECRET:
        return Response(content="Missing RECURRENTE_WEBHOOK_SECRET in .env", status_code=500)
    try:
        wh = Webhook(RECURRENTE_WEBHOOK_SECRET)
        verified = wh.verify(body, {"svix-id": svix_id, "svix-timestamp": svix_ts, "svix-signature": svix_sig})
    except WebhookVerificationError:
        return Response(content="Invalid signature", status_code=400)
    event_type = None
    if isinstance(verified, dict):
        event_type = verified.get("event_type") or verified.get("type")
    success_types = set(["payment_intent.succeeded","payment_succeeded","invoice.paid","subscription.paid"])
    if event_type and (event_type not in success_types):
        return Response(status_code=204)
    email = extract_email(verified if isinstance(verified, dict) else {})
    if not email:
        return Response(content="No email found in webhook payload", status_code=202)
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return Response(content="User not found", status_code=202)
    user.status = "active"
    db.commit()
    return Response(status_code=204)

@app.post("/dev/activate-user")
def dev_activate_user(email: str, db: Session = Depends(get_db)):
    if not DEV_MODE:
        raise HTTPException(status_code=404, detail="Not found")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.status = "active"
    db.commit()
    return {"ok": True, "email": email, "status": user.status}
