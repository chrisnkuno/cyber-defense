import test from "node:test";
import assert from "node:assert/strict";

import {
  buildRecommendations,
  calculateBreachProbability,
  calculateCumulativeRisk,
  calculateRiskScore,
  calculateScenarioLikelihoods,
  defaultState,
} from "../src/engine.js";
import { buildDashboardState, createSimulationDataset } from "../src/simulation.js";

test("higher-risk state produces higher breach probability and score", () => {
  const safer = defaultState({
    passwordReuse: 0.1,
    phishingExposure: 0.1,
    patchLatency: 0.1,
    networkExposure: 0.1,
    deviceHygiene: 0.1,
    mfaCoverage: 0.9,
    backupReadiness: 0.9,
    securityFatigue: 0.1,
    dataExposure: 0.1,
  });
  const riskier = defaultState({
    passwordReuse: 0.8,
    phishingExposure: 0.75,
    patchLatency: 0.72,
    networkExposure: 0.7,
    deviceHygiene: 0.68,
    mfaCoverage: 0.2,
    backupReadiness: 0.22,
    securityFatigue: 0.71,
    dataExposure: 0.8,
  });

  assert.ok(calculateBreachProbability(riskier) > calculateBreachProbability(safer));
  assert.ok(calculateRiskScore(riskier) > calculateRiskScore(safer));
});

test("scenario engine ranks probabilities and intervention engine yields actions", () => {
  const state = defaultState({
    passwordReuse: 0.7,
    phishingExposure: 0.62,
    patchLatency: 0.58,
    networkExposure: 0.6,
    deviceHygiene: 0.55,
    mfaCoverage: 0.3,
    backupReadiness: 0.4,
    securityFatigue: 0.65,
    dataExposure: 0.61,
  });

  const scenarios = calculateScenarioLikelihoods(state);
  assert.equal(scenarios.length, 4);
  assert.ok(scenarios[0].probability >= scenarios[1].probability);
  assert.ok(buildRecommendations(state, scenarios).length > 0);
});

test("cumulative risk increases across repeated exposures", () => {
  assert.equal(calculateCumulativeRisk([0, 0, 0]), 0);
  assert.ok(calculateCumulativeRisk([0.3, 0.3, 0.3]) > 0.3);
});

test("dashboard state exposes narrative, explanations, and history", () => {
  const dataset = createSimulationDataset();
  const dashboard = buildDashboardState(dataset, dataset.profiles[0].id, 4);

  assert.equal(typeof dashboard.narrative, "string");
  assert.ok(dashboard.explanations.length > 0);
  assert.ok(dashboard.history.length > 4);
});
