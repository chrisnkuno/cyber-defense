import math
from typing import Dict, List, Any, Callable

FEATURE_KEYS = [
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

BREACH_WEIGHTS = {
    "passwordReuse": 1.1,
    "phishingExposure": 1.2,
    "patchLatency": 0.9,
    "networkExposure": 0.8,
    "deviceHygiene": 1.0,
    "mfaCoverage": -1.15,
    "backupReadiness": -0.75,
    "securityFatigue": 1.1,
    "dataExposure": 0.95,
}

SCENARIO_MODELS = {
    "phishing_takeover": {
        "label": "Phishing to account takeover",
        "weights": {
            "phishingExposure": 1.35,
            "passwordReuse": 0.65,
            "mfaCoverage": -1.2,
            "securityFatigue": 0.95,
            "deviceHygiene": 0.45,
        },
    },
    "credential_stuffing": {
        "label": "Credential stuffing",
        "weights": {
            "passwordReuse": 1.55,
            "mfaCoverage": -1.05,
            "dataExposure": 0.85,
            "securityFatigue": 0.45,
        },
    },
    "malware_infection": {
        "label": "Malware infection",
        "weights": {
            "patchLatency": 1.2,
            "deviceHygiene": 1.3,
            "networkExposure": 0.8,
            "securityFatigue": 0.55,
        },
    },
    "data_leakage": {
        "label": "Data leakage",
        "weights": {
            "dataExposure": 1.3,
            "backupReadiness": -0.35,
            "networkExposure": 0.55,
            "phishingExposure": 0.45,
            "securityFatigue": 0.55,
        },
    },
}

class Intervention:
    def __init__(self, id: str, title: str, rationale: str, impact: int, when: Callable[[Dict[str, float]], bool]):
        self.id = id
        self.title = title
        self.rationale = rationale
        self.impact = impact
        self.when = when

INTERVENTION_LIBRARY = [
    Intervention(
        id="enable_mfa",
        title="Expand MFA coverage",
        rationale="Your projected compromise paths are strongly reduced when high-value accounts require MFA.",
        impact=18,
        when=lambda state: state.get("mfaCoverage", 0) < 0.72,
    ),
    Intervention(
        id="password_reset",
        title="Eliminate password reuse",
        rationale="Shared passwords are amplifying both phishing fallout and credential stuffing exposure.",
        impact=16,
        when=lambda state: state.get("passwordReuse", 0) > 0.48,
    ),
    Intervention(
        id="patch_routine",
        title="Reduce patch latency",
        rationale="Patch delays are keeping exploit and malware scenarios elevated over the next monitoring window.",
        impact=14,
        when=lambda state: state.get("patchLatency", 0) > 0.45 or state.get("deviceHygiene", 0) > 0.45,
    ),
    Intervention(
        id="network_hardening",
        title="Harden high-risk network usage",
        rationale="Frequent unmanaged or public-network exposure is increasing attack surface for credential and malware paths.",
        impact=11,
        when=lambda state: state.get("networkExposure", 0) > 0.5,
    ),
    Intervention(
        id="fatigue_break",
        title="Reduce security fatigue with targeted prompts",
        rationale="Behavioral drift suggests the user is more likely to ignore or mis-handle security prompts right now.",
        impact=10,
        when=lambda state: state.get("securityFatigue", 0) > 0.55,
    ),
    Intervention(
        id="backup_validation",
        title="Verify recovery backups",
        rationale="Improving recovery posture reduces the impact of malware and accidental leakage events.",
        impact=8,
        when=lambda state: state.get("backupReadiness", 0) < 0.58,
    ),
]


def clamp(value: float, min_val: float = 0.0, max_val: float = 1.0) -> float:
    return max(min_val, min(value, max_val))

def round_val(value: float, digits: int = 3) -> float:
    return round(value, digits)

def sigmoid(value: float) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-value))
    except OverflowError:
        return 0.0 if value < 0 else 1.0

def default_state(seed: Dict[str, float] = None) -> Dict[str, float]:
    if seed is None:
        seed = {}
    return {
        "passwordReuse": seed.get("passwordReuse", 0.35),
        "phishingExposure": seed.get("phishingExposure", 0.42),
        "patchLatency": seed.get("patchLatency", 0.28),
        "networkExposure": seed.get("networkExposure", 0.3),
        "deviceHygiene": seed.get("deviceHygiene", 0.32),
        "mfaCoverage": seed.get("mfaCoverage", 0.65),
        "backupReadiness": seed.get("backupReadiness", 0.58),
        "securityFatigue": seed.get("securityFatigue", 0.36),
        "dataExposure": seed.get("dataExposure", 0.3),
    }

def apply_event(previous_state: Dict[str, float], event: Dict[str, Any]) -> Dict[str, float]:
    current = previous_state.copy()
    deltas = event.get("deltas", {})
    drift = event.get("drift", {})

    for key in FEATURE_KEYS:
        d_val = drift.get(key, 0.0)
        delta = deltas.get(key, 0.0)
        current[key] = clamp(current[key] + d_val + delta)

    prompt_load = event.get("promptLoad", 0)
    current["securityFatigue"] = clamp(
        current["securityFatigue"] + max(0, prompt_load - 1) * 0.03
    )
    return current

def calculate_breach_probability(state: Dict[str, float]) -> float:
    weighted_sum = -2.05
    for key in FEATURE_KEYS:
        raw_val = 1.0 - state[key] if key in ("mfaCoverage", "backupReadiness") else state[key]
        weighted_sum += raw_val * BREACH_WEIGHTS[key]
    
    return clamp(sigmoid(weighted_sum))

def calculate_risk_score(state: Dict[str, float]) -> int:
    return int(round(calculate_breach_probability(state) * 100))

def calculate_scenario_likelihoods(state: Dict[str, float]) -> List[Dict[str, Any]]:
    scenarios = []
    for s_id, model in SCENARIO_MODELS.items():
        weighted_sum = -1.4
        for feature, weight in model["weights"].items():
            val = 1.0 - state[feature] if feature in ("mfaCoverage", "backupReadiness") else state.get(feature, 0.0)
            weighted_sum += val * weight
            
        prob = round_val(clamp(sigmoid(weighted_sum)))
        scenarios.append({
            "id": s_id,
            "label": model["label"],
            "probability": prob,
        })
    scenarios.sort(key=lambda x: x["probability"], reverse=True)
    return scenarios

def calculate_cumulative_risk(probabilities: List[float]) -> float:
    safe_window = 1.0
    for prob in probabilities:
        safe_window *= (1.0 - prob)
    return round_val(1.0 - safe_window)

def explain_state(state: Dict[str, float]) -> List[Dict[str, Any]]:
    contributions = []
    for key in FEATURE_KEYS:
        norm_val = 1.0 - state[key] if key in ("mfaCoverage", "backupReadiness") else state[key]
        contrib = round_val(norm_val * BREACH_WEIGHTS[key])
        contributions.append({
            "key": key,
            "label": key,
            "contribution": contrib,
            "value": round_val(state[key])
        })
    contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
    return contributions

def risk_trajectory(timeline_scores: List[float], current_tick: int) -> Dict[str, Any]:
    if current_tick == 0 or len(timeline_scores) < 2:
        return {"direction": "stable", "delta": 0}
    
    previous = timeline_scores[current_tick - 1]
    current = timeline_scores[current_tick]
    delta = current - previous

    if delta > 2:
        return {"direction": "degrading", "delta": delta}
    elif delta < -2:
        return {"direction": "improving", "delta": delta}
    
    return {"direction": "stable", "delta": delta}

def build_recommendations(state: Dict[str, float], scenarios: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    scenario_summary = [s["id"] for s in scenarios[:2]]
    results = []
    for item in INTERVENTION_LIBRARY:
        if item.when(state):
            priority_score = item.impact + round(state.get("securityFatigue", 0) * 4)
            results.append({
                "id": item.id,
                "title": item.title,
                "rationale": item.rationale,
                "impact": item.impact,
                "priorityScore": priority_score,
                "targetedScenarios": scenario_summary,
            })
    results.sort(key=lambda x: x["priorityScore"], reverse=True)
    return results[:4]

def create_narrative(profile_name: str, state: Dict[str, float], risk_score: int, trajectory: Dict[str, Any], scenarios: List[Dict[str, Any]]) -> str:
    if not scenarios: return ""
    top = scenarios[0]
    second = scenarios[1] if len(scenarios) > 1 else scenarios[0]
    
    posture = "high" if risk_score >= 70 else "elevated" if risk_score >= 45 else "moderate"
    direction = trajectory["direction"]
    top_prob = int(round(top["probability"] * 100))
    second_prob = int(round(second["probability"] * 100))
    
    explanations = explain_state(state)[:3]
    drivers = ", ".join([item["key"] for item in explanations])
    
    return f"{profile_name} is in a {posture} risk posture. The current trend is {direction}, with the most likely breach path being {top['label'].lower()} ({top_prob}%) followed by {second['label'].lower()} ({second_prob}%). The strongest risk drivers are {drivers}."
