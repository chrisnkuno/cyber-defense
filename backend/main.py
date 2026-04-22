import os
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware

import models
import schemas
import engine
import database
import simulation
import scanner

database.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="Cyber Defense Monitor API")
sec_scanner = scanner.SecurityScanner()


def allowed_origins() -> List[str]:
    raw_origins = os.getenv(
        "CYBER_DEFENSE_ALLOWED_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173",
    )
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    db = database.SessionLocal()
    try:
        simulation.populate_database(db)
    finally:
        db.close()

@app.get("/api/profiles", response_model=dict)
def get_profiles(db: Session = Depends(database.get_db)):
    profiles = db.query(models.Profile).all()
    out = []
    for p in profiles:
        ticks_count = len(p.ticks)
        latest_score = p.ticks[-1].risk_score if ticks_count > 0 else 0
        out.append({
            "id": p.id,
            "name": p.name,
            "role": p.role,
            "ticks": ticks_count,
            "latestRiskScore": latest_score
        })
    return {"profiles": out}

@app.get("/api/dashboard")
def get_dashboard(
    profile: str = Query(..., min_length=2, max_length=64),
    tick: Optional[int] = Query(default=None, ge=0, le=365),
    db: Session = Depends(database.get_db)
):
    prof = db.query(models.Profile).filter(models.Profile.id == profile).first()
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
        
    ticks = prof.ticks
    if not ticks:
        raise HTTPException(status_code=404, detail="No timeline data for profile")
        
    total_ticks = len(ticks)
    bounded_tick = min(max(0, tick if tick is not None else total_ticks - 1), total_ticks - 1)
    
    current = ticks[bounded_tick]
    
    # Trend
    scores = [t.risk_score for t in ticks]
    trend = engine.risk_trajectory(scores, bounded_tick)
    
    # Cumulative
    future_window = [t.breach_probability for t in ticks[bounded_tick:bounded_tick+6]]
    cumulative_risk = engine.calculate_cumulative_risk(future_window)
    
    recommendations = engine.build_recommendations(current.state_json, current.scenarios_json)
    guidance = get_security_guidance(current.state_json)
    
    narrative = engine.create_narrative(
        prof.name,
        current.state_json,
        current.risk_score,
        trend,
        current.scenarios_json
    )
    
    history = [
        {
            "tick": t.tick_num,
            "timestamp": t.timestamp_str,
            "riskScore": t.risk_score,
            "breachProbability": t.breach_probability,
            "topScenario": t.scenarios_json[0]["label"] if t.scenarios_json else "",
            "eventLabel": t.event_label
        }
        for t in ticks
    ]
    
    return {
        "profile": {
            "id": prof.id,
            "name": prof.name,
            "role": prof.role,
            "totalTicks": total_ticks
        },
        "currentTick": bounded_tick,
        "state": current.state_json,
        "riskScore": current.risk_score,
        "breachProbability": current.breach_probability,
        "cumulativeRisk": cumulative_risk,
        "trend": trend,
        "scenarios": current.scenarios_json,
        "recommendations": sorted(recommendations, key=lambda x: x["priorityScore"], reverse=True),
        "guidance": guidance,
        "narrative": narrative,
        "explanations": current.explanations_json,
        "history": history,
        "latestEvent": {
            "type": current.event_type,
            "label": current.event_label
        }
    }

@app.post("/api/simulate")
def post_simulate_event(
    event: schemas.SimulateEventSchema,
    profile_id: str = Query(..., min_length=2, max_length=64),
    db: Session = Depends(database.get_db)
):
    prof = db.query(models.Profile).filter(models.Profile.id == profile_id).first()
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
        
    last_tick = prof.ticks[-1] if prof.ticks else None
    if not last_tick:
        raise HTTPException(status_code=400, detail="Cannot append to empty profile")
        
    prev_state = last_tick.state_json
    evt_dict = event.model_dump(exclude_unset=True)
    
    # Process event
    new_state = engine.apply_event(prev_state, evt_dict)
    
    p_breach = engine.calculate_breach_probability(new_state)
    risk = engine.calculate_risk_score(new_state)
    scenarios = engine.calculate_scenario_likelihoods(new_state)
    explanations = engine.explain_state(new_state)
    
    new_tick_num = last_tick.tick_num + 1
    t = models.Tick(
        profile_id=prof.id,
        tick_num=new_tick_num,
        timestamp_str=f"T+{new_tick_num}",
        event_type=event.type,
        event_label=event.label,
        state_json=new_state,
        breach_probability=p_breach,
        risk_score=risk,
        scenarios_json=scenarios,
        explanations_json=explanations
    )
    db.add(t)
    db.commit()
    return {"status": "ok", "newTick": new_tick_num}

@app.post("/api/scan")
def run_vulnerability_scan(
    profile_id: str = Query(..., min_length=2, max_length=64),
    db: Session = Depends(database.get_db)
):
    prof = db.query(models.Profile).filter(models.Profile.id == profile_id).first()
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
        
    # Run absolute "real" scan
    scan_results = sec_scanner.run_scan()
    
    # Map scan results to state transitions
    # Example: many open ports -> increase networkExposure
    # Example: world-accessible files -> increase dataExposure
    
    deltas = {
        "networkExposure": 0.08 * len(scan_results["risky_open_ports"]),
        "dataExposure": 0.08 if scan_results["summary"]["high_risk_permission_findings"] > 0 else -0.03,
        "deviceHygiene": -0.08 if scan_results["summary"]["critical_issues"] > 2 else 0.04
    }
    
    event = schemas.SimulateEventSchema(
        type="vulnerability_scan",
        label=f"System Vulnerability Scan: {scan_results['summary']['critical_issues']} issues found",
        deltas=schemas.EventDeltas(**deltas)
    )
    
    result = post_simulate_event(event=event, profile_id=profile_id, db=db)
    return {
        **result,
        "scan_results": scan_results
    }

def get_security_guidance(state: dict) -> List[dict]:
    guidance = []
    if state["passwordReuse"] > 0.6:
        guidance.append({
            "topic": "Identity",
            "advise": "High password reuse detected. Immediate password rotation and use of a password manager is recommended.",
            "urgency": "High"
        })
    if state["mfaCoverage"] < 0.5:
        guidance.append({
            "topic": "Access Control",
            "advise": "Enable Multi-Factor Authentication (MFA) on all critical accounts to prevent account takeover.",
            "urgency": "Critical"
        })
    if state["patchLatency"] > 0.5:
        guidance.append({
            "topic": "System Hardening",
            "advise": "A backlog of patches was observed. Schedule an automated update cycle to reduce exploit surface.",
            "urgency": "Medium"
        })
    if state["networkExposure"] > 0.7:
        guidance.append({
            "topic": "Network",
            "advise": "Multiple open services detected. Review firewall rules and close unnecessary ports (e.g., Telnet, unencrypted HTTP).",
            "urgency": "High"
        })
    
    # Default guidance if all good
    if not guidance:
        guidance.append({
            "topic": "General",
            "advise": "Maintain regular backup validation and keep monitoring active for behavioral drift.",
            "urgency": "Low"
        })
    return guidance

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
