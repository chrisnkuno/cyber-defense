# Dynamic Cyber Risk Monitor

A privacy-preserving AI system prototype that continuously models user security state, predicts likely breach scenarios, and delivers adaptive, personalized interventions.

## What is implemented

This repository contains a fully local research prototype with:

- A dynamic security state model `S_t = f(S_(t-1), B_t, E_t, C_t)`
- A Cyber Risk Score derived from `P(breach_t) = sigmoid(w · S_t)`
- Cumulative interval risk over a forward monitoring window
- Canonical attack scenario probabilities
- An intervention engine that prioritizes high-impact mitigations
- A synthetic time-series dataset generator with no PII
- A lightweight dashboard for inspecting risk evolution and explanations

## Project structure

- `server.js`: local HTTP server and API endpoints
- `src/engine.js`: risk model, scenario engine, explanations, interventions
- `src/simulation.js`: synthetic profile generation and time-series simulation
- `public/`: dashboard UI

## Run

```bash
npm start
```

Then open `http://localhost:3000`.

## API

- `GET /api/profiles`: available simulated user profiles
- `GET /api/dashboard?profile=<id>&tick=<n>`: full dashboard state for a profile at a time step
- `GET /api/dataset`: full synthetic dataset for research/export workflows

## Modeling notes

The prototype keeps the implementation interpretable on purpose:

- State features remain explicit and bounded in `[0, 1]`
- Protective controls such as MFA and backup readiness reduce risk
- Risk explanations are exposed as feature-level weighted contributions
- Scenario generation uses per-scenario logistic models instead of opaque black boxes

This makes the system suitable for open research, simulation, and later replacement with more advanced models.

## Next extensions

- Replace synthetic events with privacy-preserving local telemetry adapters
- Add offline evaluation against generated attack outcomes
- Introduce model comparison endpoints for logistic, tree-based, and LLM-assisted reasoning
- Connect recommendation delivery to A/B-tested behavior interventions
