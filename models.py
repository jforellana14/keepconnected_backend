from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    status = Column(String, default="inactive")  # inactive/active

    timezone = Column(String, default="America/Guatemala")
    enabled = Column(Boolean, default=True)
    morning_message = Column(String, default="Buenos dias!")
    evening_message = Column(String, default="Buenas tardes!")
    last_morning_sent = Column(DateTime, nullable=True)
    last_evening_sent = Column(DateTime, nullable=True)

class ActivationToken(Base):
    __tablename__ = "activation_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False)

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    device_id = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, nullable=True)
