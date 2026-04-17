from pydantic import BaseModel
from typing import Dict, List, Optional, Any

class StateDict(BaseModel):
    passwordReuse: float
    phishingExposure: float
    patchLatency: float
    networkExposure: float
    deviceHygiene: float
    mfaCoverage: float
    backupReadiness: float
    securityFatigue: float
    dataExposure: float

class EventDeltas(BaseModel):
    passwordReuse: Optional[float] = 0.0
    phishingExposure: Optional[float] = 0.0
    patchLatency: Optional[float] = 0.0
    networkExposure: Optional[float] = 0.0
    deviceHygiene: Optional[float] = 0.0
    mfaCoverage: Optional[float] = 0.0
    backupReadiness: Optional[float] = 0.0
    securityFatigue: Optional[float] = 0.0
    dataExposure: Optional[float] = 0.0

class SimulateEventSchema(BaseModel):
    type: str
    label: str
    deltas: Optional[EventDeltas] = None
    promptLoad: Optional[int] = 0
    drift: Optional[EventDeltas] = None

class ProfileOut(BaseModel):
    id: str
    name: str
    role: str
    ticks: int
    latestRiskScore: int

    class Config:
        from_attributes = True
