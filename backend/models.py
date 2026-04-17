from sqlalchemy import Column, Integer, String, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from database import Base

class Profile(Base):
    __tablename__ = "profiles"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, index=True)
    role = Column(String)
    
    ticks = relationship("Tick", back_populates="profile", cascade="all, delete-orphan", order_by="Tick.tick_num")

class Tick(Base):
    __tablename__ = "ticks"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    profile_id = Column(String, ForeignKey("profiles.id"))
    tick_num = Column(Integer)
    timestamp_str = Column(String)
    
    event_type = Column(String, nullable=True)
    event_label = Column(String, nullable=True)
    
    # Stores the raw state dict fields
    state_json = Column(JSON)
    breach_probability = Column(Float)
    risk_score = Column(Integer)
    scenarios_json = Column(JSON)
    explanations_json = Column(JSON)

    profile = relationship("Profile", back_populates="ticks")
