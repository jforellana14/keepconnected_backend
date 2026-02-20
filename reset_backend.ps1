# ==========================================================
# KeepConnected Backend RESET (FINAL)
# Python 3.11 | Backend + Agent (modular) | Auto Git Push
# Repo: https://github.com/jforellana14/keepconnected_backend.git
# Branch: main
# ==========================================================

$ErrorActionPreference = "Stop"

Write-Host "=== KeepConnected Backend RESET ===" -ForegroundColor Cyan

# --- Helpers ---
function Remove-IfExists($path) {
    if (Test-Path $path) {
        Write-Host "Eliminando $path ..."
        Remove-Item -Recurse -Force $path
    }
}

function WriteFile($path, $content) {
    $dir = Split-Path $path
    if ($dir -and !(Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $content | Set-Content -Path $path -Encoding UTF8
}

# --- Limpieza ---
Remove-IfExists ".\venv"
Remove-IfExists ".\__pycache__"
Remove-IfExists ".\backend"
Remove-IfExists ".\agent"
Remove-IfExists ".\frontend"

# --- Estructura ---
New-Item -ItemType Directory -Force backend | Out-Null
New-Item -ItemType Directory -Force agent | Out-Null
New-Item -ItemType Directory -Force frontend | Out-Null

# ==========================================================
# requirements.txt (COMPATIBLE PYTHON 3.11, SIN RUST)
# ==========================================================
WriteFile "backend\requirements.txt" @"
fastapi==0.109.2
uvicorn==0.27.1
SQLAlchemy==2.0.25
python-dotenv==1.0.1
python-jose==3.3.0
passlib==1.7.4
bcrypt==4.1.2
python-multipart==0.0.6
email-validator==2.1.0.post1
pydantic==1.10.13
httpx==0.27.0
svix==1.19.0
"@

# ==========================================================
# .env.example
# ==========================================================
WriteFile "backend\.env.example" @"
# Core
ENV=production
DATABASE_URL=sqlite:///./keepconnected.db
JWT_SECRET=CHANGE_ME_SUPER_SECRET

# Backend
BACKEND_URL=https://api.keepconnected.io

# Recurrente
RECURRENTE_API_KEY=rc_live_xxx
RECURRENTE_WEBHOOK_SECRET=whsec_xxx

# Plans (PRODUCT IDS)
BASIC_MONTHLY=prod_g5cdwqsi
BASIC_ANNUAL=prod_ugd1thqh

PRO_MONTHLY=prod_ckezvswg
PRO_ANNUAL=prod_kr5q0wb8

PREMIUM_MONTHLY=prod_xd2vngk9
PREMIUM_ANNUAL=prod_vejxoubi
"@

# ==========================================================
# database.py
# ==========================================================
WriteFile "backend\database.py" @"
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./keepconnected.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
"@

# ==========================================================
# models.py
# ==========================================================
WriteFile "backend\models.py" @"
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    plan = Column(String, default="basic")
    plan_expires_at = Column(DateTime, nullable=True)
    status = Column(String, default="inactive")
    created_at = Column(DateTime, server_default=func.now())

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    device_id = Column(String, unique=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
"@

# ==========================================================
# security.py
# ==========================================================
WriteFile "backend\security.py" @"
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
"@

# ==========================================================
# plans.py
# ==========================================================
WriteFile "backend\plans.py" @"
PLANS = {
  'basic': {
    'daily_messages': 3,
    'numbers': 1,
    'groups': 0,
    'ai_weekly': 1
  },
  'pro': {
    'daily_messages': 3,
    'numbers': 2,
    'groups': 1,
    'ai_unlimited': True
  },
  'premium': {
    'daily_messages': 3,
    'numbers': 5,
    'groups': 3,
    'ai_unlimited': True
  }
}
"@

# ==========================================================
# main.py
# ==========================================================
WriteFile "backend\main.py" @"
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from database import Base, engine, SessionLocal
from models import User
from security import hash_password, verify_password, create_token

Base.metadata.create_all(bind=engine)

app = FastAPI(title='KeepConnected API')

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class Register(BaseModel):
    email: EmailStr
    password: str

@app.post('/register')
def register(data: Register, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, 'User exists')
    u = User(email=data.email, password_hash=hash_password(data.password))
    db.add(u)
    db.commit()
    return {'ok': True}

@app.post('/login')
def login(data: Register, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.email == data.email).first()
    if not u or not verify_password(data.password, u.password_hash):
        raise HTTPException(401, 'Invalid')
    return {'token': create_token(u.email, 'user'), 'plan': u.plan}

@app.get('/')
def health():
    return {'status': 'ok'}
"@

# ==========================================================
# AGENT (MODULAR – BASE)
# ==========================================================
WriteFile "agent\agent.py" @"
from backend_api import ping_backend

def main():
    print('KeepConnected Agent started')
    ping_backend()

if __name__ == '__main__':
    main()
"@

WriteFile "agent\backend_api.py" @"
import requests
import os

BACKEND = os.getenv('BACKEND_URL', 'https://api.keepconnected.io')

def ping_backend():
    r = requests.get(BACKEND)
    print('Backend:', r.status_code)
"@

WriteFile "agent\schedule_engine.py" @"
# Placeholder: random scheduling (>=2h) + days config
"@

WriteFile "agent\mood_engine.py" @"
# Placeholder: friendship / professional / love / family / flirty
"@

WriteFile "agent\ai_engine.py" @"
# Placeholder: AI generation (Pro/Premium unlimited, Basic weekly)
"@

WriteFile "agent\updater.py" @"
# Placeholder: auto-update logic
"@

# ==========================================================
# VENV + INSTALL
# ==========================================================
Write-Host "Creando venv (Python 3.11) ..."
python -m venv venv
& .\venv\Scripts\python.exe -m pip install --upgrade pip
& .\venv\Scripts\pip.exe install -r backend\requirements.txt

# ==========================================================
# GIT PUSH
# ==========================================================
Write-Host "Git commit & push ..."
git add .
git commit -m "RESET backend final (Python 3.11)"
git push origin main

Write-Host "=== RESET COMPLETADO ===" -ForegroundColor Green
Write-Host "API local: http://127.0.0.1:8000" -ForegroundColor Green