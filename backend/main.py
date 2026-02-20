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
