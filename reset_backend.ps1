#requires -Version 5.1
<#
KeepConnected - Backend + Agent + UI (V2 FINAL)
Genera todo usando HERE-STRINGS sin errores.
Estructura:
 backend/
 agent/
 frontend/
 .env.example
 requirements.txt
 run_backend.ps1
 venv
#>

$ErrorActionPreference = "Stop"

Write-Host "=== KeepConnected RESET V2 (HERE-STRINGS MODE) ==="

# --------------------------
# UTILITIES
# --------------------------
function SafeRemove($p) {
    if (Test-Path $p) {
        Write-Host "Eliminando $p ..."
        Remove-Item -Recurse -Force $p
    }
}

function EnsureDir($p) {
    if (!(Test-Path $p)) {
        New-Item -ItemType Directory -Path $p | Out-Null
    }
}

# --------------------------
# CLEAN PREVIOUS STRUCTURE
# --------------------------
SafeRemove ".\venv"
SafeRemove ".\backend"
SafeRemove ".\agent"
SafeRemove ".\frontend"
SafeRemove ".\__pycache__"
SafeRemove ".\keepconnected.db"
SafeRemove ".\requirements.txt"
SafeRemove ".\.env.example"

EnsureDir ".\backend"
EnsureDir ".\agent"
EnsureDir ".\frontend"

# --------------------------
# REQUIREMENTS
# --------------------------
@'
fastapi==0.109.2
uvicorn==0.27.1
sqlalchemy==2.0.25
python-dotenv==1.0.1
python-jose==3.3.0
passlib==1.7.4
bcrypt==3.2.2
python-multipart==0.0.6
email-validator==2.1.0.post1
pydantic==2.6.1
httpx==0.27.0
svix==1.19.0
requests==2.31.0
selenium==4.18.1
webdriver-manager==4.0.1
PySide6==6.6.2
'@ | Out-File ".\requirements.txt" -Encoding utf8

# --------------------------
# .ENV.EXAMPLE
# --------------------------
@'
# ===== KeepConnected Backend =====
ENV=development
DATABASE_URL=sqlite:///./keepconnected.db
JWT_SECRET=CHANGE_ME_USE_A_LONG_RANDOM_STRING

# Recurrente storefront links
STORE_BASIC_MONTHLY_LINK=
STORE_BASIC_YEARLY_LINK=
STORE_PRO_MONTHLY_LINK=
STORE_PRO_YEARLY_LINK=
STORE_PREMIUM_MONTHLY_LINK=
STORE_PREMIUM_YEARLY_LINK=

# Product IDs (static)
PROD_BASIC_MONTHLY=prod_g5cdwqsi
PROD_BASIC_YEARLY=prod_ugd1thqh
PROD_PRO_MONTHLY=prod_ckezvswg
PROD_PRO_YEARLY=prod_kr5q0wb8
PROD_PREMIUM_MONTHLY=prod_xd2vngk9
PROD_PREMIUM_YEARLY=prod_vejxoubi

# Webhook (Svix)
RECURRENTE_WEBHOOK_SECRET=

# ===== Agent =====
BACKEND_URL=https://api.keepconnected.io
'@ | Out-File ".\.env.example" -Encoding utf8

# --------------------------
# backend/database.py
# --------------------------
@'
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./keepconnected.db")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
'@ | Out-File ".\backend\database.py" -Encoding utf8

# --------------------------
# backend/models.py
# --------------------------
@'
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    plan = Column(String, default="basic", nullable=False)
    plan_period = Column(String, default="monthly", nullable=False)
    subscription_active = Column(Boolean, default=False, nullable=False)

    device_id = Column(String, nullable=True)
    settings_json = Column(Text, default="{}", nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class PaymentEvent(Base):
    __tablename__ = "payment_events"

    id = Column(Integer, primary_key=True)
    provider = Column(String, default="recurrente", nullable=False)
    event_type = Column(String, nullable=False)
    raw_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
'@ | Out-File ".\backend\models.py" -Encoding utf8

# --------------------------
# backend/security.py
# --------------------------
@'
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
'@ | Out-File ".\backend\security.py" -Encoding utf8

# --------------------------
# backend/recurrente.py
# --------------------------
@'
import os
from typing import Dict

def plan_store_link(plan: str, period: str) -> str:
    plan = (plan or "basic").lower()
    period = (period or "monthly").lower()

    env_map = {
        "basic": {
            "monthly": os.getenv("STORE_BASIC_MONTHLY_LINK", ""),
            "yearly":  os.getenv("STORE_BASIC_YEARLY_LINK", "")
        },
        "pro": {
            "monthly": os.getenv("STORE_PRO_MONTHLY_LINK", ""),
            "yearly":  os.getenv("STORE_PRO_YEARLY_LINK", "")
        },
        "premium": {
            "monthly": os.getenv("STORE_PREMIUM_MONTHLY_LINK", ""),
            "yearly":  os.getenv("STORE_PREMIUM_YEARLY_LINK", "")
        }
    }

    return env_map.get(plan, {}).get(period, "")

def product_ids() -> Dict[str, Dict[str, str]]:
    return {
        "basic": {
            "monthly": os.getenv("PROD_BASIC_MONTHLY", ""),
            "yearly":  os.getenv("PROD_BASIC_YEARLY", "")
        },
        "pro": {
            "monthly": os.getenv("PROD_PRO_MONTHLY", ""),
            "yearly":  os.getenv("PROD_PRO_YEARLY", "")
        },
        "premium": {
            "monthly": os.getenv("PROD_PREMIUM_MONTHLY", ""),
            "yearly":  os.getenv("PROD_PREMIUM_YEARLY", "")
        }
    }
'@ | Out-File ".\backend\recurrente.py" -Encoding utf8

# --------------------------
# backend/main.py (parte 1)
# --------------------------
@'
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
'@ | Out-File ".\backend\main.py" -Encoding utf8

# --------------------------
# backend/main.py (PARTE 2)
# Append to existing file
# --------------------------
@'
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
'@ | Add-Content ".\backend\main.py" -Encoding utf8

# --------------------------
# backend/__init__.py
# --------------------------
@'
# KeepConnected backend package
'@ | Out-File ".\backend\__init__.py" -Encoding utf8


# ============================================================
# AGENT /agent/agent.py  (VERSIÓN V2 ESTABLE)
# ============================================================

@'
import os
import json
import time
import random
from datetime import datetime, timedelta
from typing import Dict, Any, List

import requests

# Selenium
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

BACKEND_URL = os.getenv("BACKEND_URL", "https://api.keepconnected.io").rstrip("/")

def now_local() -> datetime:
    return datetime.now()

def load_state(path: str) -> Dict[str, Any]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_state(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def fetch_config(agent_token: str) -> Dict[str, Any]:
    r = requests.get(
        BACKEND_URL + "/agent/config",
        headers={"Authorization": f"Bearer {agent_token}"},
        timeout=30
    )
    r.raise_for_status()
    return r.json()

def is_day_enabled(settings: Dict[str, Any], dt: datetime) -> bool:
    days = settings.get("days_enabled")
    if not days:
        days = [0,1,2,3,4,5]
    return dt.weekday() in days

def get_windows(settings: Dict[str, Any]):
    return settings.get("windows") or [
        {"key": "morning", "enabled": True, "start": "09:00", "end": "11:00"},
        {"key": "evening", "enabled": True, "start": "16:00", "end": "18:00"},
        {"key": "night",   "enabled": False, "start": "20:00", "end": "22:00"},
    ]

def parse_hhmm(s: str, base: datetime):
    hh, mm = s.split(":")
    return base.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)

def min_gap(settings: Dict[str, Any]) -> float:
    return float(settings.get("min_gap_hours", 2))

def max_per_day(settings: Dict[str, Any]) -> int:
    return int(settings.get("max_messages_per_day", 3))

def random_time(start: datetime, end: datetime) -> datetime:
    delta = int((end - start).total_seconds())
    if delta <= 0:
        delta = 60
    return start + timedelta(seconds=random.randint(1, delta))

def count_sent_today(state: Dict[str, Any], today: str) -> int:
    return len(list((state.get("sent", {}).get(today, {}) or {}).values()))

def mark_sent(state: Dict[str, Any], key: str, today: str):
    state.setdefault("sent", {}).setdefault(today, {})[key] = True
    state["last_sent_at"] = now_local().isoformat()

def last_sent(state: Dict[str, Any]):
    s = state.get("last_sent_at")
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except:
        return None

def pick_slots(settings: Dict[str, Any], plan: str) -> List[Dict[str, Any]]:
    slots = settings.get("slots") or []

    plan = (plan or "basic").lower()
    if plan == "basic":
        max_slots = 1
        max_groups = 0
    elif plan == "pro":
        max_slots = 2
        max_groups = 1
    else:
        max_slots = 5
        max_groups = 3

    contacts = [s for s in slots if s.get("type") == "contact"]
    groups = [s for s in slots if s.get("type") == "group"]

    groups = groups[:max_groups]
    merged = (contacts + groups)[:max_slots]
    return merged

def pick_message(settings: Dict[str, Any], key: str) -> str:
    msgs = (settings.get("messages") or {}).get(key) or []

    if not msgs:
        fallback = {
            "morning": ["Buenos días!"],
            "evening": ["Buenas tardes! Cómo vas?"],
            "night":   ["Buenas noches, que descanses!"],
        }
        msgs = fallback.get(key, ["Hola!"])

    return random.choice(msgs)

def open_driver(profile_dir: str):
    opts = Options()
    opts.add_argument("--disable-notifications")
    opts.add_argument(f"--user-data-dir={profile_dir}")
    opts.add_argument("--lang=es")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)

    service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=service, options=opts)

def send_whatsapp(driver, slot: Dict[str, Any], msg: str):
    driver.get("https://web.whatsapp.com/")
    time.sleep(6)

    phone = slot.get("phone")
    name = slot.get("name") or ""
    stype = slot.get("type") or "contact"

    # --- Preferred: direct send via phone
    if stype == "contact" and phone:
        import urllib.parse as up
        txt = up.quote(msg)
        driver.get(f"https://web.whatsapp.com/send?phone={phone.replace('+','')}&text={txt}")
        time.sleep(6)
        try:
            active = driver.switch_to.active_element
            active.send_keys(Keys.ENTER)
            time.sleep(2)
            return
        except:
            pass

    # --- Fallback: search bar
    search_selectors = [
        'div[contenteditable="true"][data-tab="3"]',
        'div[contenteditable="true"][role="textbox"]'
    ]

    search = None
    for css in search_selectors:
        try:
            elems = driver.find_elements(By.CSS_SELECTOR, css)
            if elems:
                search = elems[0]
                break
        except:
            pass

    if not search:
        raise RuntimeError("No pude localizar el buscador de WhatsApp Web.")

    search.click()
    time.sleep(1)
    search.send_keys(name)
    time.sleep(2)
    search.send_keys(Keys.ENTER)
    time.sleep(2)

    msg_selectors = [
        'div[contenteditable="true"][data-tab="10"]',
        'div[contenteditable="true"][role="textbox"]'
    ]

    box = None
    for css in msg_selectors:
        try:
            elems = driver.find_elements(By.CSS_SELECTOR, css)
            if elems:
                box = elems[-1]
                break
        except:
            pass

    if not box:
        raise RuntimeError("No pude encontrar el input de mensaje.")

    box.click()
    box.send_keys(msg)
    time.sleep(0.5)
    box.send_keys(Keys.ENTER)
    time.sleep(1.5)
'@ | Out-File ".\agent\agent.py" -Encoding utf8

# --------------------------
# FINAL DEL AGENTE (agent.py)
# --------------------------
@'
def loop(agent_token: str, profile_dir: str, state_path: str):
    state = load_state(state_path)
    print("Agent running with backend:", BACKEND_URL)

    while True:
        cfg = fetch_config(agent_token)
        settings = cfg.get("settings") or {}
        plan = cfg.get("plan") or "basic"

        dt = now_local()
        today = dt.strftime("%Y-%m-%d")

        # Day
        if not is_day_enabled(settings, dt):
            time.sleep(60)
            continue

        # Count today
        if count_sent_today(state, today) >= max_per_day(settings):
            time.sleep(60)
            continue

        # Gap
        last_dt = last_sent(state)
        if last_dt and (dt - last_dt).total_seconds() < (min_gap(settings) * 3600):
            time.sleep(60)
            continue

        windows = [w for w in get_windows(settings) if w.get("enabled") is True]
        sent_any = False

        for w in windows:
            key = w.get("key")
            if not key:
                continue

            if state.get("sent", {}).get(today, {}).get(key):
                continue

            start = parse_hhmm(w.get("start", "09:00"), dt)
            end   = parse_hhmm(w.get("end", "11:00"), dt)

            if dt < start or dt > end:
                continue

            # random wait inside window
            t2 = random_time(dt, end)
            wait = max(5, int((t2 - dt).total_seconds()))
            print(f"[{key}] Waiting {wait}s before sending...")
            time.sleep(wait)

            # re-check
            dt2 = now_local()
            today2 = dt2.strftime("%Y-%m-%d")

            if not is_day_enabled(settings, dt2):
                continue
            if count_sent_today(state, today2) >= max_per_day(settings):
                continue

            slots = pick_slots(settings, plan)
            if not slots:
                print("No slots configured")
                time.sleep(60)
                continue

            slot = random.choice(slots)
            msg  = pick_message(settings, key)

            try:
                driver = open_driver(profile_dir)
                send_whatsapp(driver, slot, msg)
                driver.quit()

                mark_sent(state, key, today2)
                save_state(state_path, state)
                print("Sent", key, "to", slot.get("name"))
                sent_any = True
            except Exception as e:
                try:
                    driver.quit()
                except:
                    pass
                print("Send error:", str(e))

        if not sent_any:
            time.sleep(60)

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-token", required=True)
    ap.add_argument("--profile-dir", default=os.path.abspath("./agent_profile"))
    ap.add_argument("--state", default=os.path.abspath("./agent_state.json"))
    args = ap.parse_args()

    os.makedirs(args.profile_dir, exist_ok=True)
    loop(args.agent_token, args.profile_dir, args.state)

if __name__ == "__main__":
    main()
'@ | Add-Content ".\agent\agent.py" -Encoding utf8


# ============================================================
# PySide6 UI MINIMA: agent_ui.py
# ============================================================

@'
import sys
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit
)
from PySide6.QtCore import Qt, QThread, Signal
import subprocess
import os

class AgentThread(QThread):
    log = Signal(str)

    def __init__(self, token):
        super().__init__()
        self.token = token
        self.process = None

    def run(self):
        try:
            cmd = [
                os.path.abspath("./venv/Scripts/python.exe"),
                os.path.abspath("./agent/agent.py"),
                "--agent-token", self.token
            ]
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            for line in self.process.stdout:
                self.log.emit(line)
        except Exception as e:
            self.log.emit(f"ERROR: {e}")

    def stop(self):
        if self.process:
            self.process.kill()

class AgentUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KeepConnected Agent UI")
        layout = QVBoxLayout()

        self.label = QLabel("Agent Token:")
        self.input = QLineEdit()
        self.start_btn = QPushButton("Iniciar Agente")
        self.stop_btn = QPushButton("Detener Agente")
        self.log = QTextEdit()
        self.log.setReadOnly(True)

        layout.addWidget(self.label)
        layout.addWidget(self.input)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.log)

        self.setLayout(layout)

        self.thread = None

        self.start_btn.clicked.connect(self.start_agent)
        self.stop_btn.clicked.connect(self.stop_agent)

    def start_agent(self):
        token = self.input.text().strip()
        if not token:
            self.log.append("Debes ingresar un agent_token.")
            return
        self.thread = AgentThread(token)
        self.thread.log.connect(self.log.append)
        self.thread.start()
        self.log.append("Agente iniciado…")

    def stop_agent(self):
        if self.thread:
            self.thread.stop()
            self.thread = None
            self.log.append("Agente detenido.")

def main():
    app = QApplication(sys.argv)
    ui = AgentUI()
    ui.show()
    sys.exit(app.exec())
    
if __name__ == "__main__":
    main()
'@ | Out-File ".\agent\agent_ui.py" -Encoding utf8


# ============================================================
# README AGENTE
# ============================================================
@'
KeepConnected Agent (V2)

1) Activa tu suscripción
2) Obtén tu agent_token desde /agent/register
3) Ejecuta:

   venv\Scripts\python.exe agent\agent.py --agent-token TU_TOKEN

UI opcional:
   venv\Scripts\python.exe agent\agent_ui.py

Requiere:
 - Chrome instalado
 - WhatsApp Web escaneado la primera vez
'@ | Out-File ".\agent\README_AGENT.txt" -Encoding utf8


# ============================================================
# FRONTEND PLACEHOLDER
# ============================================================
@'
KeepConnected Frontend Placeholder
Tu landing SaaS + Dashboard irá aquí.
'@ | Out-File ".\frontend\README_FRONTEND.txt" -Encoding utf8


# ============================================================
# run_backend.ps1
# ============================================================

@'
$ErrorActionPreference = "Stop"
if (!(Test-Path ".\venv")) { Write-Host "No venv found. Run reset_backend.ps1 first."; exit 1 }

.\venv\Scripts\Activate.ps1
$env:PYTHONPATH = (Get-Location).Path
python -m uvicorn backend.main:app --reload
'@ | Out-File ".\run_backend.ps1" -Encoding utf8


# ============================================================
# CREAR VENV + INSTALL REQUIREMENTS
# ============================================================

Write-Host "Creando venv nuevo…"

$py = $null
if (Get-Command "py" -ErrorAction SilentlyContinue) {
    $py = "py -3.11"
}
elseif (Get-Command "python" -ErrorAction SilentlyContinue) {
    $py = "python"
}
else {
    throw "Python no encontrado. Instala Python 3.11."
}

cmd /c "$py -m venv venv" | Out-Null

Write-Host "Instalando dependencias…"
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host "Inicializando base de datos..."

.\venv\Scripts\python.exe -Command "
from backend.database import Base, engine
import backend.models
Base.metadata.create_all(bind=engine)
print('DB OK')
"

# ============================================================
# GIT AUTO INIT + PUSH
# ============================================================

if (Get-Command "git" -ErrorAction SilentlyContinue) {
    Write-Host "Git detectado. Commit + Push…"

    if (!(Test-Path ".\.git")) {
        git init | Out-Null
	git pull
    }

    $remote = git remote -v 2>$null | Select-String "origin" | Select-Object -First 1
    if (-not $remote) {
        git remote add origin "https://github.com/jforellana14/keepconnected_backend.git" | Out-Null
    }

    git add -A
    try { git commit -m "reset_backend_v2 auto" | Out-Null } catch {}
    try { git branch -M main | Out-Null } catch {}
    try {
    		git push -u origin main --force
    		Write-Host "Push forzado a GitHub completado."
	} catch {
    			Write-Host "No se pudo hacer push (normal si el repo ya tiene commits). Continuando..."
		}
}

Write-Host ""
Write-Host "===== RESET BACKEND V2 COMPLETADO ====="
Write-Host "1) Copia .env.example → .env y completa valores."
Write-Host "2) Ejecuta backend:"
Write-Host "   .\run_backend.ps1"
Write-Host "3) Ejecuta agente con token:"
Write-Host "   .\venv\Scripts\python.exe .\agent\agent.py --agent-token XXXXX"
Write-Host "4) UI opcional:"
Write-Host "   .\venv\Scripts\python.exe .\agent\agent_ui.py"
Write-Host "========================================="