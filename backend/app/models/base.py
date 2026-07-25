import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=generate_uuid)
    username = Column(String, index=True)
    role = Column(String, default="User")
    
    sessions = relationship("Session", back_populates="user")

class Session(Base):
    __tablename__ = "sessions"
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"))
    start_time = Column(DateTime, default=datetime.utcnow)
    overall_risk_score = Column(Float, default=0.0)

    user = relationship("User", back_populates="sessions")
    conversations = relationship("Conversation", back_populates="session")

class Conversation(Base):
    __tablename__ = "conversations"
    id = Column(String, primary_key=True, default=generate_uuid)
    session_id = Column(String, ForeignKey("sessions.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_prompt = Column(String)
    llm_response = Column(String)
    latency_ms = Column(Integer)
    
    # Security Fields
    is_malicious = Column(Boolean, default=False)
    attack_type = Column(String, default="benign")
    confidence_score = Column(Float, default=0.0)
    severity = Column(String, default="Low")

    session = relationship("Session", back_populates="conversations")
