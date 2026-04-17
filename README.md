# Dynamic Cyber Risk Monitor

A privacy-preserving AI system prototype that continuously models user security state, predicts likely breach scenarios, and delivers adaptive, personalized interventions.

> [!NOTE]
> This repository is actively maintained and will be continuously updated over time with more advanced monitoring capabilities, model refinements, and UI enhancements.

## What is implemented

This repository contains a production-ready research prototype with:

- **Python Backend (FastAPI)**: High-performance API with persistent SQLite storage.
- **React Frontend (Vite + TS)**: Modern, component-driven dashboard with real-time state hydration.
- **Active Scanning**: Local vulnerability scanner for ports and file system permissions.
- **Predictive Modeling**: Dynamic security state model `S_t = f(S_(t-1), B_t, E_t, C_t)`.
- **Intelligent Guidance**: Adaptive security best practices based on real-time risk posture.
- **Narrative Engine**: Automated risk explanation and scenario forecasting.

## Project Structure

- `backend/`: FastAPI application, SQL models, and scanning logic.
    - `main.py`: API entry point and logic orchestration.
    - `engine.py`: Mathematical risk scoring and scenario modeling.
    - `scanner.py`: Local telemetry and vulnerability scanning.
    - `database.py`: SQLAlchemy configuration.
- `frontend/`: React + TypeScript dashboard.
    - `src/App.tsx`: Core UI logic and data visualization.
    - `src/index.css`: Custom Swiss-minimalist styling.

## Getting Started

### Prerequisites
- Python 3.11+
- Node.js 18+
- [uv](https://github.com/astral-sh/uv) (Recommended for Python)

### Running the Backend
```bash
cd backend
uv run uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### Running the Frontend
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173).

## Core Functionalities

### 1. Persistent Monitoring
The system tracks security state transitions over time. Every "tick" represents a snapshot of the user's posture, reflecting events such as MFA enrollment, password reuse, or system patches.

### 2. Local Vulnerability Scanning
The built-in scanner performs non-invasive checks for:
- **Exposed Services**: Identifies common risky open ports on localhost.
- **Configuration Weaknesses**: Audits permissions for sensitive files (e.g., SSH keys, bash history).

### 3. Adaptive Intervention & Guidance
Instead of static warnings, the system provides:
- **Targeted Recommendations**: High-impact actions to reduce the probability of specific scenarios.
- **Security Guidance**: Contextual advice (e.g., "Rotate reused passwords") linked to the current risk score.

## Modeling Notes

The prototype keeps the implementation interpretable on purpose:
- State features remain explicit and bounded in `[0, 1]`.
- Risk explanations are exposed as weighted feature-level contributions.
- Scenario generation uses per-scenario logistic models.

This makes the system suitable for open research, behavioral science experiments, and later replacement with more advanced ML models.
