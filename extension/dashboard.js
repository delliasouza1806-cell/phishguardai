const API_BASE = "http://127.0.0.1:5500";

const els = {
  exportBtn: document.getElementById("export-btn"),
  refreshBtn: document.getElementById("refresh-btn"),
  clearBtn: document.getElementById("clear-btn"),
  dashError: document.getElementById("dash-error"),
  statTotal: document.getElementById("stat-total"),
  statHigh: document.getElementById("stat-high"),
  statCaution: document.getElementById("stat-caution"),
  statAvg: document.getElementById("stat-avg"),
  lastUpdated: document.getElementById("last-updated"),
  reportsContainer: document.getElementById("reports-container"),
};

let currentFilter = "all";
let latestPayload = null;

function badgeClassForVerdict(verdict) {
  if (verdict === "high_risk") return "badge bg-rose-500/15 text-rose-300 border border-rose-500/30";
  if (verdict === "caution") return "badge bg-amber-500/15 text-amber-300 border border-amber-500/30";
  return "badge bg-emerald-500/15 text-emerald-300 border border-emerald-500/30";
}

function renderReports(data) {
  latestPayload = data;
  const stats = data.stats || {};
  els.statTotal.textContent = String(stats.total_scans ?? 0);
  els.statHigh.textContent = String(stats.high_risk ?? 0);
  els.statCaution.textContent = String(stats.caution ?? 0);
  els.statAvg.textContent = String(stats.average_risk_score ?? 0);
  els.lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;

  els.reportsContainer.innerHTML = "";
  const allReports = data.reports || [];
  const reports = currentFilter === "all" ? allReports : allReports.filter((r) => r.verdict === currentFilter);

  if (reports.length === 0) {
    const empty = document.createElement("div");
    empty.className = "p-4 rounded-lg bg-card-soft border text-center text-xs text-slate-400";
    empty.textContent = "No matching scans recorded yet. Run a scan from the popup, Web Console, or browse with On-Page Alerts enabled.";
    els.reportsContainer.appendChild(empty);
    return;
  }

  for (const r of reports) {
    const card = document.createElement("div");
    card.className = "p-3 rounded-lg bg-card-soft border flex flex-col gap-2";

    const topRow = document.createElement("div");
    topRow.className = "flex items-center justify-between gap-2";

    const left = document.createElement("div");
    left.className = "flex items-center gap-2";

    const badge = document.createElement("span");
    badge.className = badgeClassForVerdict(r.verdict);
    badge.textContent = `${r.verdict.replace("_", " ")} · ${r.risk_score}`;

    const vector = document.createElement("span");
    vector.className = "text-xs font-semibold text-white";
    vector.textContent = r.attack_vector || "Threat Scan";

    const host = document.createElement("span");
    host.className = "text-xs font-mono text-blue-300";
    host.textContent = `${r.source_host} (${r.channel})`;

    left.appendChild(badge);
    left.appendChild(vector);
    left.appendChild(host);

    const time = document.createElement("span");
    time.className = "text-xs text-slate-400 font-mono";
    time.textContent = new Date(r.scanned_at).toLocaleTimeString();

    topRow.appendChild(left);
    topRow.appendChild(time);

    const preview = document.createElement("div");
    preview.className = "text-xs text-slate-200 leading-relaxed";
    preview.textContent = r.preview;

    const meta = document.createElement("div");
    meta.className = "flex items-center justify-between text-xs text-slate-400";
    const topSig = document.createElement("span");
    topSig.textContent = r.top_signal ? `Top signal: ${r.top_signal}` : "No threat signals";
    const bd = r.breakdown || {};
    const breakdownText = document.createElement("span");
    breakdownText.className = "font-mono";
    breakdownText.textContent = `H:${bd.heuristics ?? 0} · R:${bd.regex ?? 0} · AI:${bd.ai_semantic ?? 0}`;

    meta.appendChild(topSig);
    meta.appendChild(breakdownText);

    card.appendChild(topRow);
    card.appendChild(preview);
    card.appendChild(meta);
    els.reportsContainer.appendChild(card);
  }
}

async function loadDashboard() {
  els.dashError.classList.add("hidden");
  try {
    const res = await fetch(`${API_BASE}/reports`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderReports(data);
  } catch (err) {
    els.dashError.textContent = `Unable to fetch reports from ${API_BASE}/reports (${err.message})`;
    els.dashError.classList.remove("hidden");
  }
}

document.querySelectorAll(".filter-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    currentFilter = btn.dataset.filter;
    document.querySelectorAll(".filter-btn").forEach((b) => {
      b.className = b === btn ? "btn btn-primary px-2.5 py-1 text-xs filter-btn" : "btn btn-ghost px-2.5 py-1 text-xs filter-btn";
    });
    if (latestPayload) renderReports(latestPayload);
  });
});

els.exportBtn.addEventListener("click", () => {
  if (!latestPayload) return;
  const blob = new Blob([JSON.stringify(latestPayload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishguard-threat-report-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

els.refreshBtn.addEventListener("click", loadDashboard);
els.clearBtn.addEventListener("click", async () => {
  try {
    await fetch(`${API_BASE}/reports`, { method: "DELETE" });
    loadDashboard();
  } catch {
    loadDashboard();
  }
});

document.addEventListener("DOMContentLoaded", () => {
  loadDashboard();
  setInterval(loadDashboard, 5000);
});
