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
