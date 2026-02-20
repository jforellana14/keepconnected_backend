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
