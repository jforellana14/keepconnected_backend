import os
import json
from datetime import datetime
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from svix.webhooks import Webhook, WebhookVerificationError

from .database import Base, engine, SessionLocal
from .models import User, PaymentEvent
from .security import (
    hash_password,
    verify_password,
    create_user_jwt,
    create_agent_jwt,
    new_device_id
)
from .recurrente import plan_store_link, product_ids

load_dotenv()
Base.metadata.create_all(bind=engine)

app = FastAPI(title="KeepConnected API", version="2.0.0")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME")
JWT_ALG = "HS256"
RECURRENTE_WEBHOOK_SECRET = os.getenv("RECURRENTE_WEBHOOK_SECRET", "")

def db_get():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def decode_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])

def require_scope(token: str, scope: str) -> Dict[str, Any]:
    try:
        payload = decode_token(token)
        if payload.get("scp") != scope:
            raise HTTPException(status_code=401, detail="Invalid token scope")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --------------------------
# Pydantic models
# --------------------------

class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class CheckoutRequest(BaseModel):
    plan: str
    period: str
    email: EmailStr

class CheckoutResponse(BaseModel):
    checkout_url: str
    plan: str
    period: str
    product_id: str

class AgentRegisterRequest(BaseModel):
    email: EmailStr
    device_name: Optional[str] = None

class AgentRegisterResponse(BaseModel):
    device_id: str
    agent_token: str

class SettingsUpdateRequest(BaseModel):
    settings: Dict[str, Any]

# --------------------------
# /health
# --------------------------
@app.get("/health")
def health():
    return {"ok": True, "ts": datetime.utcnow().isoformat()}

# --------------------------
# /register
# --------------------------
@app.post("/register", response_model=AuthResponse)
def register(body: RegisterRequest, db: Session = Depends(db_get)):
    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        plan="basic",
        plan_period="monthly",
        subscription_active=False,
        settings_json="{}"
    )
    db.add(user)
    db.commit()

    token = create_user_jwt(body.email)
    return AuthResponse(access_token=token)

# --------------------------
# /login
# --------------------------
@app.post("/login", response_model=AuthResponse)
def login(body: LoginRequest, db: Session = Depends(db_get)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return AuthResponse(access_token=create_user_jwt(body.email))

# --------------------------
# /me
# --------------------------
@app.get("/me")
def me(token: str = Depends(oauth2_scheme), db: Session = Depends(db_get)):
    payload = require_scope(token, "user")
    user = db.query(User).filter(User.email == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "email": user.email,
        "plan": user.plan,
        "period": user.plan_period,
        "subscription_active": user.subscription_active,
        "device_id": user.device_id,
        "settings": json.loads(user.settings_json or "{}")
    }

# --------------------------
# /settings
# --------------------------
@app.post("/settings")
def update_settings(body: SettingsUpdateRequest, token: str = Depends(oauth2_scheme), db: Session = Depends(db_get)):
    payload = require_scope(token, "user")
    user = db.query(User).filter(User.email == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.settings_json = json.dumps(body.settings or {})
    db.commit()
    return {"ok": True}
# --------------------------
# /checkout
# --------------------------
@app.post("/checkout", response_model=CheckoutResponse)
def create_checkout(body: CheckoutRequest, db: Session = Depends(db_get)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    plan = (body.plan or "basic").lower()
    period = (body.period or "monthly").lower()

    pid = product_ids().get(plan, {}).get(period, "")
    url = plan_store_link(plan, period)

    if not url:
        raise HTTPException(status_code=400, detail="Missing storefront link in env")

    user.plan = plan
    user.plan_period = period
    db.commit()

    return CheckoutResponse(
        checkout_url=url,
        plan=plan,
        period=period,
        product_id=pid
    )

# --------------------------
# /agent/register
# --------------------------
@app.post("/agent/register", response_model=AgentRegisterResponse)
def agent_register(body: AgentRegisterRequest, token: str = Depends(oauth2_scheme), db: Session = Depends(db_get)):
    payload = require_scope(token, "user")

    if payload.get("sub") != body.email:
        raise HTTPException(status_code=403, detail="Email mismatch")

    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.subscription_active:
        raise HTTPException(status_code=403, detail="Subscription inactive")

    if not user.device_id:
        user.device_id = new_device_id()
        db.commit()

    agent_token = create_agent_jwt(user.email, user.device_id)
    return AgentRegisterResponse(device_id=user.device_id, agent_token=agent_token)

# --------------------------
# /agent/reset-device
# --------------------------
@app.post("/agent/reset-device")
def agent_reset_device(token: str = Depends(oauth2_scheme), db: Session = Depends(db_get)):
    payload = require_scope(token, "user")
    user = db.query(User).filter(User.email == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.device_id = None
    db.commit()

    return {"ok": True}

# --------------------------
# /agent/config
# --------------------------
@app.get("/agent/config")
def agent_config(token: str = Depends(oauth2_scheme), db: Session = Depends(db_get)):
    payload = require_scope(token, "agent")

    user = db.query(User).filter(User.email == payload.get("sub")).first()
    if not user or user.device_id != payload.get("did"):
        raise HTTPException(status_code=401, detail="Invalid agent")

    if not user.subscription_active:
        raise HTTPException(status_code=403, detail="Subscription inactive")

    return {
        "plan": user.plan,
        "period": user.plan_period,
        "subscription_active": user.subscription_active,
        "settings": json.loads(user.settings_json or "{}")
    }

# --------------------------
# /webhooks/recurrente
# --------------------------
@app.post("/webhooks/recurrente")
async def recurrente_webhook(request: Request, db: Session = Depends(db_get)):
    raw = await request.body()
    headers = dict(request.headers)

    if RECURRENTE_WEBHOOK_SECRET:
        try:
            wh = Webhook(RECURRENTE_WEBHOOK_SECRET)
            event = wh.verify(raw, headers)
        except WebhookVerificationError:
            raise HTTPException(status_code=400, detail="Invalid webhook signature")
    else:
        try:
            event = json.loads(raw.decode("utf-8"))
        except:
            raise HTTPException(status_code=400, detail="Invalid JSON")

    db.add(PaymentEvent(event_type=str(event.get("type", "unknown")), raw_json=json.dumps(event)))
    db.commit()

    customer_email = None
    try:
        customer_email = ((event.get("intentable") or {}).get("customer") or {}).get("email")
    except:
        pass

    if not customer_email:
        return {"ok": True}

    user = db.query(User).filter(User.email == customer_email).first()
    if not user:
        return {"ok": True}

    etype = str(event.get("type", "")).lower()
    status = ""
    try:
        status = str((event.get("intentable") or {}).get("status", "")).lower()
    except:
        pass

    if ("paid" in etype) or (status == "paid") or ("payment" in etype and "succeed" in etype):
        user.subscription_active = True
        db.commit()

    return {"ok": True}
