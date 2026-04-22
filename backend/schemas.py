from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


FeatureScore = float

class StateDict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passwordReuse: FeatureScore = Field(ge=0.0, le=1.0)
    phishingExposure: FeatureScore = Field(ge=0.0, le=1.0)
    patchLatency: FeatureScore = Field(ge=0.0, le=1.0)
    networkExposure: FeatureScore = Field(ge=0.0, le=1.0)
    deviceHygiene: FeatureScore = Field(ge=0.0, le=1.0)
    mfaCoverage: FeatureScore = Field(ge=0.0, le=1.0)
    backupReadiness: FeatureScore = Field(ge=0.0, le=1.0)
    securityFatigue: FeatureScore = Field(ge=0.0, le=1.0)
    dataExposure: FeatureScore = Field(ge=0.0, le=1.0)

class EventDeltas(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passwordReuse: Optional[float] = Field(default=0.0, ge=-1.0, le=1.0)
    phishingExposure: Optional[float] = Field(default=0.0, ge=-1.0, le=1.0)
    patchLatency: Optional[float] = Field(default=0.0, ge=-1.0, le=1.0)
    networkExposure: Optional[float] = Field(default=0.0, ge=-1.0, le=1.0)
    deviceHygiene: Optional[float] = Field(default=0.0, ge=-1.0, le=1.0)
    mfaCoverage: Optional[float] = Field(default=0.0, ge=-1.0, le=1.0)
    backupReadiness: Optional[float] = Field(default=0.0, ge=-1.0, le=1.0)
    securityFatigue: Optional[float] = Field(default=0.0, ge=-1.0, le=1.0)
    dataExposure: Optional[float] = Field(default=0.0, ge=-1.0, le=1.0)

class SimulateEventSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=2, max_length=64)
    label: str = Field(min_length=4, max_length=240)
    deltas: Optional[EventDeltas] = None
    promptLoad: Optional[int] = Field(default=0, ge=0, le=10)
    drift: Optional[EventDeltas] = None

class ProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    role: str
    ticks: int
    latestRiskScore: int
