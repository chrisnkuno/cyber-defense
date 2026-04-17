import { useState, useEffect } from "react";
import "./index.css";

function formatPercent(value: number) {
  return `${Math.round(value * 100)}%`;
}

function featureTitle(key: string) {
  return key
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (char) => char.toUpperCase());
}

export default function App() {
  const [profiles, setProfiles] = useState<any[]>([]);
  const [currentProfileId, setCurrentProfileId] = useState("");
  const [tick, setTick] = useState(0);
  const [dashboardData, setDashboardData] = useState<any>(null);
  const [isScanning, setIsScanning] = useState(false);

  const fetchDashboard = () => {
    if (!currentProfileId) return;
    fetch(`/api/dashboard?profile=${encodeURIComponent(currentProfileId)}&tick=${tick}`)
      .then((res) => res.json())
      .then((data) => setDashboardData(data));
  };

  useEffect(() => {
    fetch("/api/profiles")
      .then((res) => res.json())
      .then((data) => {
        setProfiles(data.profiles);
        if (data.profiles.length > 0) {
          setCurrentProfileId(data.profiles[0].id);
        }
      });
  }, []);

  useEffect(() => {
    fetchDashboard();
  }, [currentProfileId, tick]);

  const handleProfileChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setCurrentProfileId(e.target.value);
    setTick(0);
  };

  const runScan = async () => {
    setIsScanning(true);
    try {
      const res = await fetch(`/api/scan?profile_id=${currentProfileId}`, { method: "POST" });
      const data = await res.json();
      setTick(data.newTick);
      fetchDashboard();
    } catch (err) {
      console.error("Scan failed", err);
    } finally {
      setIsScanning(false);
    }
  };

  if (!dashboardData) return <div>Loading...</div>;

  return (
    <main className="shell">
      <section className="hero">
        <p className="eyebrow">Privacy-preserving adaptive cyber risk prototype</p>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h1>Continuous user-state modeling for preventive security intervention.</h1>
            <p className="lede">
              A local research prototype that simulates evolving user security posture, projects breach likelihood,
              and turns that forecast into interpretable, personalized mitigation actions.
            </p>
          </div>
          <button 
            className="pill impact" 
            style={{ border: 'none', cursor: 'pointer', padding: '12px 24px', fontSize: '1rem' }}
            onClick={runScan}
            disabled={isScanning}
          >
            {isScanning ? "Scanning..." : "Run Vulnerability Scan"}
          </button>
        </div>
      </section>

      <section className="controls card">
        <div>
          <label htmlFor="profile-select">User profile</label>
          <select id="profile-select" value={currentProfileId} onChange={handleProfileChange}>
            {profiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} · {p.role} · latest CRS {p.latestRiskScore}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="tick-range">Timeline step</label>
          <input
            id="tick-range"
            type="range"
            min="0"
            max={dashboardData.profile.totalTicks - 1}
            step="1"
            value={tick}
            onChange={(e) => setTick(parseInt(e.target.value, 10))}
          />
        </div>
        <div className="tick-meta">
          <span id="tick-label">T+{dashboardData.currentTick}</span>
          <span id="event-label">{dashboardData.latestEvent?.label || "Loading state..."}</span>
        </div>
      </section>

      <section className="summary-grid">
        <article className="metric card accent">
          <span className="metric-label">Cyber Risk Score</span>
          <strong>{dashboardData.riskScore}</strong>
          <span className="metric-note">
            {dashboardData.trend?.direction} ({dashboardData.trend?.delta >= 0 ? "+" : ""}{dashboardData.trend?.delta})
          </span>
        </article>
        <article className="metric card">
          <span className="metric-label">Current breach probability</span>
          <strong>{formatPercent(dashboardData.breachProbability)}</strong>
          <span className="metric-note">sigmoid(w · S_t)</span>
        </article>
        <article className="metric card">
          <span className="metric-label">6-step cumulative risk</span>
          <strong>{formatPercent(dashboardData.cumulativeRisk)}</strong>
          <span className="metric-note">1 - ∏(1 - P(breach_i))</span>
        </article>
      </section>

      <section className="two-column">
        <article className="card">
          <h2>Security Best Practices</h2>
          <div className="stack">
            {dashboardData.guidance?.map((item: any, idx: number) => (
              <div className="item-row" key={idx}>
                <div>
                  <strong>{item.topic}</strong>
                  <p>{item.advise}</p>
                </div>
                <span className={`pill ${item.urgency === 'Critical' || item.urgency === 'High' ? 'impact' : ''}`}>
                  {item.urgency}
                </span>
              </div>
            ))}
          </div>
        </article>
        <article className="card">
          <h2>Scenario forecast</h2>
          <div className="stack">
            {dashboardData.scenarios?.map((scenario: any) => (
              <div className="item-row" key={scenario.id}>
                <div>
                  <strong>{scenario.label}</strong>
                  <p>Projected path probability based on current state.</p>
                </div>
                <span className="pill">{formatPercent(scenario.probability)}</span>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="two-column">
        <article className="card">
          <h2>Adaptive interventions</h2>
          <div className="stack">
            {dashboardData.recommendations?.map((rec: any) => (
              <div className="item-row" key={rec.id}>
                <div>
                  <strong>{rec.title}</strong>
                  <p>{rec.rationale}</p>
                </div>
                <span className="pill impact">+{rec.impact}</span>
              </div>
            ))}
          </div>
        </article>
        <article className="card">
          <h2>Risk narrative</h2>
          <p className="narrative">{dashboardData.narrative}</p>
        </article>
      </section>

      <section className="two-column">
        <article className="card">
          <h2>Top feature attributions</h2>
          <div className="stack compact">
            {dashboardData.explanations?.slice(0, 5).map((item: any) => (
              <div className="bar-row" key={item.key}>
                <div className="bar-meta">
                  <span>{featureTitle(item.key)}</span>
                  <span>{item.value}</span>
                </div>
                <div className="bar-track">
                  <div
                    className="bar-fill"
                    style={{ width: `${Math.min(100, Math.abs(item.contribution) * 42)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </article>
        <article className="card">
          <h2>Risk trajectory</h2>
        <div className="history-chart" aria-label="Risk trajectory chart">
          {dashboardData.history?.map((h: any) => {
            const maxScore = Math.max(...(dashboardData.history?.map((i: any) => i.riskScore) || [1]), 1);
            const height = Math.max(8, Math.round((h.riskScore / maxScore) * 100));
            const isActive = h.tick === dashboardData.currentTick;
            return (
              <button
                key={h.tick}
                className={`chart-bar ${isActive ? "active" : ""}`}
                style={{ height: `${height}%` }}
                onClick={() => setTick(h.tick)}
              >
                <span>{h.riskScore}</span>
              </button>
            );
          })}
        </div>
        <div className="history-list">
          {dashboardData.history
            ?.slice()
            .reverse()
            .slice(0, 8)
            .map((h: any) => (
              <div className={`history-row ${h.tick === dashboardData.currentTick ? "selected" : ""}`} key={h.tick}>
                <span>{h.timestamp}</span>
                <strong>{h.riskScore}</strong>
                <span>{h.topScenario}</span>
                <span>{h.eventLabel}</span>
              </div>
            ))}
        </div>
      </article>
      </section>
    </main>
  );
}
