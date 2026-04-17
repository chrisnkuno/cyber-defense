from sqlalchemy.orm import Session
import models
import engine

PROFILE_BLUEPRINTS = [
    {
        "id": "remote-contractor",
        "name": "Remote contractor",
        "role": "Third-party contributor",
        "seed": {
            "passwordReuse": 0.58,
            "phishingExposure": 0.62,
            "patchLatency": 0.35,
            "networkExposure": 0.71,
            "deviceHygiene": 0.41,
            "mfaCoverage": 0.44,
            "backupReadiness": 0.45,
            "securityFatigue": 0.54,
            "dataExposure": 0.47,
        },
    },
    {
        "id": "finance-manager",
        "name": "Finance manager",
        "role": "Privileged business user",
        "seed": {
            "passwordReuse": 0.32,
            "phishingExposure": 0.52,
            "patchLatency": 0.24,
            "networkExposure": 0.34,
            "deviceHygiene": 0.29,
            "mfaCoverage": 0.77,
            "backupReadiness": 0.62,
            "securityFatigue": 0.38,
            "dataExposure": 0.66,
        },
    },
    {
        "id": "student-researcher",
        "name": "Student researcher",
        "role": "Mobile-first user",
        "seed": {
            "passwordReuse": 0.51,
            "phishingExposure": 0.55,
            "patchLatency": 0.42,
            "networkExposure": 0.49,
            "deviceHygiene": 0.48,
            "mfaCoverage": 0.52,
            "backupReadiness": 0.39,
            "securityFatigue": 0.58,
            "dataExposure": 0.33,
        },
    },
]

EVENT_CATALOG = [
    {
        "type": "completed_mfa_enrollment",
        "label": "Enabled MFA on another high-value account",
        "deltas": {"mfaCoverage": 0.14, "securityFatigue": -0.03},
        "promptLoad": 1,
    },
    {
        "type": "reused_password_signup",
        "label": "Reused an existing password on a new service",
        "deltas": {"passwordReuse": 0.12, "dataExposure": 0.06},
        "promptLoad": 0,
    },
    {
        "type": "phishing_training",
        "label": "Completed phishing awareness training",
        "deltas": {"phishingExposure": -0.11, "securityFatigue": -0.04},
        "promptLoad": 1,
    },
    {
        "type": "missed_patch_cycle",
        "label": "Delayed security patch cycle",
        "deltas": {"patchLatency": 0.13, "deviceHygiene": 0.08},
        "promptLoad": 0,
    },
    {
        "type": "public_wifi_session",
        "label": "Worked repeatedly from unmanaged public Wi-Fi",
        "deltas": {"networkExposure": 0.14, "phishingExposure": 0.04},
        "promptLoad": 0,
    },
    {
        "type": "backup_check",
        "label": "Validated account and device recovery backups",
        "deltas": {"backupReadiness": 0.13},
        "promptLoad": 1,
    },
    {
        "type": "data_sharing_spike",
        "label": "Shared sensitive data across more external services",
        "deltas": {"dataExposure": 0.14, "passwordReuse": 0.04},
        "promptLoad": 0,
    },
    {
        "type": "security_prompt_overload",
        "label": "Encountered repeated security prompts and dismissed several",
        "deltas": {"securityFatigue": 0.13, "phishingExposure": 0.06},
        "promptLoad": 4,
    },
]

def create_rng(seed: int):
    value = seed & 0xFFFFFFFF
    def rng():
        nonlocal value
        value = (value * 1664525 + 1013904223) & 0xFFFFFFFF
        return value / 4294967296.0
    return rng

def choose_event(rng, profile_index: int, tick: int):
    val = (rng() + profile_index * 0.17 + tick * 0.07) % 1.0
    event_index = int(val * len(EVENT_CATALOG))
    return EVENT_CATALOG[event_index]

def create_drift(rng):
    drift = {}
    keys = [
        "passwordReuse",
        "phishingExposure",
        "patchLatency",
        "networkExposure",
        "deviceHygiene",
        "mfaCoverage",
        "backupReadiness",
        "securityFatigue",
        "dataExposure",
    ]
    for key in keys:
        centered = (rng() - 0.5) * 0.03
        drift[key] = round(centered, 3)
        
    drift["mfaCoverage"] -= 0.004
    drift["backupReadiness"] -= 0.003
    drift["securityFatigue"] += 0.004
    return drift

def populate_database(db: Session, force=False):
    # Check if we already have profiles
    count = db.query(models.Profile).count()
    if count > 0 and not force:
        return
        
    # Clear existing
    if force:
        db.query(models.Tick).delete()
        db.query(models.Profile).delete()
        db.commit()

    # Create profiles
    for profile_index, blueprint in enumerate(PROFILE_BLUEPRINTS):
        p = models.Profile(
            id=blueprint["id"],
            name=blueprint["name"],
            role=blueprint["role"]
        )
        db.add(p)
        db.commit()
        db.refresh(p)
        
        # Simulate ticks
        rng = create_rng(100 + profile_index * 97)
        state = engine.default_state(blueprint["seed"])
        
        for tick in range(28):
            event = choose_event(rng, profile_index, tick)
            full_event = {**event, "drift": create_drift(rng)}
            state = engine.apply_event(state, full_event)
            
            p_breach = engine.calculate_breach_probability(state)
            risk = engine.calculate_risk_score(state)
            scenarios = engine.calculate_scenario_likelihoods(state)
            explanations = engine.explain_state(state)
            
            t = models.Tick(
                profile_id=p.id,
                tick_num=tick,
                timestamp_str=f"T+{tick}",
                event_type=event["type"],
                event_label=event["label"],
                state_json=state,
                breach_probability=p_breach,
                risk_score=risk,
                scenarios_json=scenarios,
                explanations_json=explanations
            )
            db.add(t)
        db.commit()
