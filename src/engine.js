const FEATURE_KEYS = [
  "passwordReuse",
  "phishingExposure",
  "patchLatency",
  "networkExposure",
  "deviceHygiene",
  "mfaCoverage",
  "backupReadiness",
  "securityFatigue",
  "dataExposure",
];

const BREACH_WEIGHTS = {
  passwordReuse: 1.1,
  phishingExposure: 1.2,
  patchLatency: 0.9,
  networkExposure: 0.8,
  deviceHygiene: 1.0,
  mfaCoverage: -1.15,
  backupReadiness: -0.75,
  securityFatigue: 1.1,
  dataExposure: 0.95,
};

const SCENARIO_MODELS = {
  phishing_takeover: {
    label: "Phishing to account takeover",
    weights: {
      phishingExposure: 1.35,
      passwordReuse: 0.65,
      mfaCoverage: -1.2,
      securityFatigue: 0.95,
      deviceHygiene: 0.45,
    },
  },
  credential_stuffing: {
    label: "Credential stuffing",
    weights: {
      passwordReuse: 1.55,
      mfaCoverage: -1.05,
      dataExposure: 0.85,
      securityFatigue: 0.45,
    },
  },
  malware_infection: {
    label: "Malware infection",
    weights: {
      patchLatency: 1.2,
      deviceHygiene: 1.3,
      networkExposure: 0.8,
      securityFatigue: 0.55,
    },
  },
  data_leakage: {
    label: "Data leakage",
    weights: {
      dataExposure: 1.3,
      backupReadiness: -0.35,
      networkExposure: 0.55,
      phishingExposure: 0.45,
      securityFatigue: 0.55,
    },
  },
};

const INTERVENTION_LIBRARY = [
  {
    id: "enable_mfa",
    title: "Expand MFA coverage",
    rationale:
      "Your projected compromise paths are strongly reduced when high-value accounts require MFA.",
    impact: 18,
    when: (state) => state.mfaCoverage < 0.72,
  },
  {
    id: "password_reset",
    title: "Eliminate password reuse",
    rationale:
      "Shared passwords are amplifying both phishing fallout and credential stuffing exposure.",
    impact: 16,
    when: (state) => state.passwordReuse > 0.48,
  },
  {
    id: "patch_routine",
    title: "Reduce patch latency",
    rationale:
      "Patch delays are keeping exploit and malware scenarios elevated over the next monitoring window.",
    impact: 14,
    when: (state) => state.patchLatency > 0.45 || state.deviceHygiene > 0.45,
  },
  {
    id: "network_hardening",
    title: "Harden high-risk network usage",
    rationale:
      "Frequent unmanaged or public-network exposure is increasing attack surface for credential and malware paths.",
    impact: 11,
    when: (state) => state.networkExposure > 0.5,
  },
  {
    id: "fatigue_break",
    title: "Reduce security fatigue with targeted prompts",
    rationale:
      "Behavioral drift suggests the user is more likely to ignore or mis-handle security prompts right now.",
    impact: 10,
    when: (state) => state.securityFatigue > 0.55,
  },
  {
    id: "backup_validation",
    title: "Verify recovery backups",
    rationale:
      "Improving recovery posture reduces the impact of malware and accidental leakage events.",
    impact: 8,
    when: (state) => state.backupReadiness < 0.58,
  },
];

function clamp(value, min = 0, max = 1) {
  return Math.min(max, Math.max(min, value));
}

function round(value, digits = 3) {
  return Number(value.toFixed(digits));
}

export function sigmoid(value) {
  return 1 / (1 + Math.exp(-value));
}

export function defaultState(seed = {}) {
  return {
    passwordReuse: seed.passwordReuse ?? 0.35,
    phishingExposure: seed.phishingExposure ?? 0.42,
    patchLatency: seed.patchLatency ?? 0.28,
    networkExposure: seed.networkExposure ?? 0.3,
    deviceHygiene: seed.deviceHygiene ?? 0.32,
    mfaCoverage: seed.mfaCoverage ?? 0.65,
    backupReadiness: seed.backupReadiness ?? 0.58,
    securityFatigue: seed.securityFatigue ?? 0.36,
    dataExposure: seed.dataExposure ?? 0.3,
  };
}

export function applyEvent(previousState, event) {
  const current = { ...previousState };
  const deltas = event.deltas || {};

  for (const key of FEATURE_KEYS) {
    const drift = event.drift?.[key] ?? 0;
    const delta = deltas[key] ?? 0;
    current[key] = clamp(current[key] + drift + delta);
  }

  current.securityFatigue = clamp(
    current.securityFatigue + Math.max(0, (event.promptLoad || 0) - 1) * 0.03,
  );

  return current;
}

export function calculateBreachProbability(state) {
  const weightedSum =
    -2.05 +
    FEATURE_KEYS.reduce((sum, key) => {
      const rawValue =
        key === "mfaCoverage" || key === "backupReadiness"
          ? 1 - state[key]
          : state[key];
      return sum + rawValue * BREACH_WEIGHTS[key];
    }, 0);

  return clamp(sigmoid(weightedSum));
}

export function calculateRiskScore(state) {
  return Math.round(calculateBreachProbability(state) * 100);
}

export function calculateScenarioLikelihoods(state) {
  return Object.entries(SCENARIO_MODELS)
    .map(([id, model]) => {
      const weightedSum =
        -1.4 +
        Object.entries(model.weights).reduce((sum, [feature, weight]) => {
          const value =
            feature === "mfaCoverage" || feature === "backupReadiness"
              ? 1 - state[feature]
              : state[feature];
          return sum + value * weight;
        }, 0);

      return {
        id,
        label: model.label,
        probability: round(clamp(sigmoid(weightedSum))),
      };
    })
    .sort((left, right) => right.probability - left.probability);
}

export function calculateCumulativeRisk(probabilities) {
  const safeWindow = probabilities.reduce((acc, probability) => acc * (1 - probability), 1);
  return round(1 - safeWindow);
}

export function explainState(state) {
  return FEATURE_KEYS.map((key) => {
    const normalizedValue =
      key === "mfaCoverage" || key === "backupReadiness" ? 1 - state[key] : state[key];
    return {
      key,
      label: key,
      contribution: round(normalizedValue * BREACH_WEIGHTS[key]),
      value: round(state[key]),
    };
  }).sort((left, right) => Math.abs(right.contribution) - Math.abs(left.contribution));
}

export function riskTrajectory(history, currentTick) {
  if (currentTick === 0) {
    return { direction: "stable", delta: 0 };
  }

  const previous = history[currentTick - 1].riskScore;
  const current = history[currentTick].riskScore;
  const delta = current - previous;

  if (delta > 2) {
    return { direction: "degrading", delta };
  }

  if (delta < -2) {
    return { direction: "improving", delta };
  }

  return { direction: "stable", delta };
}

export function buildRecommendations(state, scenarios) {
  const scenarioSummary = scenarios.slice(0, 2).map((scenario) => scenario.id);

  return INTERVENTION_LIBRARY.filter((item) => item.when(state))
    .map((item) => ({
      ...item,
      priorityScore: item.impact + Math.round(state.securityFatigue * 4),
      targetedScenarios: scenarioSummary,
    }))
    .sort((left, right) => right.priorityScore - left.priorityScore)
    .slice(0, 4);
}

export function createNarrative({ profile, state, riskScore, trajectory, scenarios }) {
  const topScenario = scenarios[0];
  const secondScenario = scenarios[1];
  const posture = riskScore >= 70 ? "high" : riskScore >= 45 ? "elevated" : "moderate";

  return `${profile.name} is in a ${posture} risk posture. The current trend is ${
    trajectory.direction
  }, with the most likely breach path being ${topScenario.label.toLowerCase()} (${Math.round(
    topScenario.probability * 100,
  )}%) followed by ${secondScenario.label.toLowerCase()} (${Math.round(
    secondScenario.probability * 100,
  )}%). The strongest risk drivers are ${explainState(state)
    .slice(0, 3)
    .map((item) => item.key)
    .join(", ")}.`;
}
