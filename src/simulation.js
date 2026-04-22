import {
  applyEvent,
  buildRecommendations,
  calculateBreachProbability,
  calculateCumulativeRisk,
  calculateRiskScore,
  calculateScenarioLikelihoods,
  createNarrative,
  defaultState,
  explainState,
  riskTrajectory,
} from "./engine.js";

const PROFILE_BLUEPRINTS = [
  {
    id: "remote-contractor",
    name: "Remote contractor",
    role: "Third-party contributor",
    seed: {
      passwordReuse: 0.58,
      phishingExposure: 0.62,
      patchLatency: 0.35,
      networkExposure: 0.71,
      deviceHygiene: 0.41,
      mfaCoverage: 0.44,
      backupReadiness: 0.45,
      securityFatigue: 0.54,
      dataExposure: 0.47,
    },
  },
  {
    id: "finance-manager",
    name: "Finance manager",
    role: "Privileged business user",
    seed: {
      passwordReuse: 0.32,
      phishingExposure: 0.52,
      patchLatency: 0.24,
      networkExposure: 0.34,
      deviceHygiene: 0.29,
      mfaCoverage: 0.77,
      backupReadiness: 0.62,
      securityFatigue: 0.38,
      dataExposure: 0.66,
    },
  },
  {
    id: "student-researcher",
    name: "Student researcher",
    role: "Mobile-first user",
    seed: {
      passwordReuse: 0.51,
      phishingExposure: 0.55,
      patchLatency: 0.42,
      networkExposure: 0.49,
      deviceHygiene: 0.48,
      mfaCoverage: 0.52,
      backupReadiness: 0.39,
      securityFatigue: 0.58,
      dataExposure: 0.33,
    },
  },
];

const EVENT_CATALOG = [
  {
    type: "completed_mfa_enrollment",
    label: "Enabled MFA on another high-value account",
    deltas: { mfaCoverage: 0.14, securityFatigue: -0.03 },
    promptLoad: 1,
  },
  {
    type: "reused_password_signup",
    label: "Reused an existing password on a new service",
    deltas: { passwordReuse: 0.12, dataExposure: 0.06 },
    promptLoad: 0,
  },
  {
    type: "phishing_training",
    label: "Completed phishing awareness training",
    deltas: { phishingExposure: -0.11, securityFatigue: -0.04 },
    promptLoad: 1,
  },
  {
    type: "missed_patch_cycle",
    label: "Delayed security patch cycle",
    deltas: { patchLatency: 0.13, deviceHygiene: 0.08 },
    promptLoad: 0,
  },
  {
    type: "public_wifi_session",
    label: "Worked repeatedly from unmanaged public Wi-Fi",
    deltas: { networkExposure: 0.14, phishingExposure: 0.04 },
    promptLoad: 0,
  },
  {
    type: "backup_check",
    label: "Validated account and device recovery backups",
    deltas: { backupReadiness: 0.13 },
    promptLoad: 1,
  },
  {
    type: "data_sharing_spike",
    label: "Shared sensitive data across more external services",
    deltas: { dataExposure: 0.14, passwordReuse: 0.04 },
    promptLoad: 0,
  },
  {
    type: "security_prompt_overload",
    label: "Encountered repeated security prompts and dismissed several",
    deltas: { securityFatigue: 0.13, phishingExposure: 0.06 },
    promptLoad: 4,
  },
];

function createRng(seed) {
  let value = seed >>> 0;
  return () => {
    value = (value * 1664525 + 1013904223) >>> 0;
    return value / 4294967296;
  };
}

function chooseEvent(rng, profileIndex, tick) {
  const eventIndex = Math.floor(
    ((rng() + profileIndex * 0.17 + tick * 0.07) % 1) * EVENT_CATALOG.length,
  );
  return EVENT_CATALOG[eventIndex];
}

function createDrift(rng) {
  const drift = {};
  const keys = [
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

  for (const key of keys) {
    const centered = (rng() - 0.5) * 0.03;
    drift[key] = Number(centered.toFixed(3));
  }

  drift.mfaCoverage -= 0.004;
  drift.backupReadiness -= 0.003;
  drift.securityFatigue += 0.004;
  return drift;
}

function simulateProfile(profile, profileIndex, ticks = 28) {
  const rng = createRng(100 + profileIndex * 97);
  const timeline = [];
  let state = defaultState(profile.seed);

  for (let tick = 0; tick < ticks; tick += 1) {
    const event = chooseEvent(rng, profileIndex, tick);
    state = applyEvent(state, {
      ...event,
      drift: createDrift(rng),
    });

    const breachProbability = calculateBreachProbability(state);
    const riskScore = calculateRiskScore(state);
    const scenarios = calculateScenarioLikelihoods(state);

    timeline.push({
      tick,
      timestamp: `T+${tick}`,
      event: {
        type: event.type,
        label: event.label,
      },
      state,
      breachProbability,
      riskScore,
      scenarios,
      explanations: explainState(state),
    });
  }

  return {
    ...profile,
    timeline,
  };
}

export function createSimulationDataset() {
  return {
    generatedAt: new Date().toISOString(),
    profiles: PROFILE_BLUEPRINTS.map((profile, index) => simulateProfile(profile, index)),
  };
}

export function buildDashboardState(dataset, profileId, tick) {
  const profile = dataset.profiles.find((candidate) => candidate.id === profileId) ?? dataset.profiles[0];
  const boundedTick =
    typeof tick === "number"
      ? Math.max(0, Math.min(profile.timeline.length - 1, tick))
      : profile.timeline.length - 1;
  const current = profile.timeline[boundedTick];
  const trajectory = riskTrajectory(profile.timeline, boundedTick);
  const futureWindow = profile.timeline
    .slice(boundedTick, Math.min(profile.timeline.length, boundedTick + 6))
    .map((entry) => entry.breachProbability);
  const cumulativeRisk = calculateCumulativeRisk(futureWindow);

  return {
    generatedAt: dataset.generatedAt,
    profile: {
      id: profile.id,
      name: profile.name,
      role: profile.role,
      totalTicks: profile.timeline.length,
    },
    currentTick: boundedTick,
    state: current.state,
    riskScore: current.riskScore,
    breachProbability: current.breachProbability,
    cumulativeRisk,
    trend: trajectory,
    scenarios: current.scenarios,
    recommendations: buildRecommendations(current.state, current.scenarios),
    narrative: createNarrative({
      profile,
      state: current.state,
      riskScore: current.riskScore,
      trajectory,
      scenarios: current.scenarios,
    }),
    explanations: current.explanations,
    history: profile.timeline.map((entry) => ({
      tick: entry.tick,
      timestamp: entry.timestamp,
      riskScore: entry.riskScore,
      breachProbability: entry.breachProbability,
      topScenario: entry.scenarios[0].label,
      eventLabel: entry.event.label,
    })),
    latestEvent: current.event,
  };
}
