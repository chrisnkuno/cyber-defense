const profileSelect = document.querySelector("#profile-select");
const tickRange = document.querySelector("#tick-range");
const tickLabel = document.querySelector("#tick-label");
const eventLabel = document.querySelector("#event-label");

let profiles = [];
let currentProfileId = "";

function formatPercent(value) {
  return `${Math.round(value * 100)}%`;
}

function featureTitle(key) {
  return key
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (char) => char.toUpperCase());
}

function renderScenarioList(items) {
  const container = document.querySelector("#scenario-list");
  container.innerHTML = items
    .map(
      (item) => `
        <div class="item-row">
          <div>
            <strong>${item.label}</strong>
            <p>Projected path probability based on current state.</p>
          </div>
          <span class="pill">${formatPercent(item.probability)}</span>
        </div>`,
    )
    .join("");
}

function renderRecommendations(items) {
  const container = document.querySelector("#recommendation-list");
  container.innerHTML = items
    .map(
      (item) => `
        <div class="item-row">
          <div>
            <strong>${item.title}</strong>
            <p>${item.rationale}</p>
          </div>
          <span class="pill impact">+${item.impact}</span>
        </div>`,
    )
    .join("");
}

function renderExplanations(items) {
  const container = document.querySelector("#explanation-list");
  container.innerHTML = items
    .slice(0, 5)
    .map(
      (item) => `
        <div class="bar-row">
          <div class="bar-meta">
            <span>${featureTitle(item.key)}</span>
            <span>${item.value}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width: ${Math.min(100, Math.abs(item.contribution) * 42)}%"></div>
          </div>
        </div>`,
    )
    .join("");
}

function renderHistory(history, activeTick) {
  const chart = document.querySelector("#history-chart");
  const list = document.querySelector("#history-list");
  const maxScore = Math.max(...history.map((item) => item.riskScore), 1);

  chart.innerHTML = history
    .map((item) => {
      const activeClass = item.tick === activeTick ? " active" : "";
      const height = Math.max(8, Math.round((item.riskScore / maxScore) * 100));
      return `<button class="chart-bar${activeClass}" data-tick="${item.tick}" style="height:${height}%"><span>${item.riskScore}</span></button>`;
    })
    .join("");

  list.innerHTML = history
    .slice()
    .reverse()
    .slice(0, 8)
    .map(
      (item) => `
        <div class="history-row ${item.tick === activeTick ? "selected" : ""}">
          <span>${item.timestamp}</span>
          <strong>${item.riskScore}</strong>
          <span>${item.topScenario}</span>
          <span>${item.eventLabel}</span>
        </div>`,
    )
    .join("");

  chart.querySelectorAll(".chart-bar").forEach((button) => {
    button.addEventListener("click", () => {
      tickRange.value = button.dataset.tick;
      loadDashboard();
    });
  });
}

function renderDashboard(data) {
  document.querySelector("#risk-score").textContent = data.riskScore;
  document.querySelector("#risk-trend").textContent = `${data.trend.direction} (${data.trend.delta >= 0 ? "+" : ""}${data.trend.delta})`;
  document.querySelector("#breach-probability").textContent = formatPercent(data.breachProbability);
  document.querySelector("#cumulative-risk").textContent = formatPercent(data.cumulativeRisk);
  document.querySelector("#narrative").textContent = data.narrative;
  tickLabel.textContent = `T+${data.currentTick}`;
  eventLabel.textContent = data.latestEvent.label;
  tickRange.max = String(data.profile.totalTicks - 1);
  tickRange.value = String(data.currentTick);

  renderScenarioList(data.scenarios);
  renderRecommendations(data.recommendations);
  renderExplanations(data.explanations);
  renderHistory(data.history, data.currentTick);
}

async function loadProfiles() {
  const response = await fetch("/api/profiles");
  const data = await response.json();
  profiles = data.profiles;
  currentProfileId = profiles[0]?.id || "";

  profileSelect.innerHTML = profiles
    .map(
      (profile) =>
        `<option value="${profile.id}">${profile.name} · ${profile.role} · latest CRS ${profile.latestRiskScore}</option>`,
    )
    .join("");
}

async function loadDashboard() {
  if (!currentProfileId) {
    return;
  }

  const response = await fetch(
    `/api/dashboard?profile=${encodeURIComponent(currentProfileId)}&tick=${encodeURIComponent(tickRange.value)}`,
  );
  const data = await response.json();
  renderDashboard(data);
}

profileSelect.addEventListener("change", async () => {
  currentProfileId = profileSelect.value;
  tickRange.value = "0";
  await loadDashboard();
});

tickRange.addEventListener("input", () => {
  loadDashboard();
});

await loadProfiles();
await loadDashboard();
