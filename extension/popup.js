const API_BASE = "http://127.0.0.1:8000";

const SAMPLE_PHISH = `Subject: Urgent Action Required: Invoice #INV-8942 Wire Update

Hi Alex,
I am currently in back-to-back board meetings and need your immediate assistance finalizing an urgent vendor settlement before 4:00 PM today. Please update our remittance details and confirm the wire transfer via the secure portal below:

http://198.51.100.42/auth/sso-verify?session=portal

Kindly keep this confidential until the audit closes and reply with your OTP verification code once submitted.

Best regards,
CFO Office`;

const SAMPLE_SAFE = `Hey Alex,
Sharing the notes from this morning's design sync. We agreed to move the sprint demo to Thursday at 2:00 PM in the main conference room. No action needed before then—let me know if that time works for your team.

Thanks,
Priya`;

const elements = {
  apiDot: document.getElementById("api-dot"),
  apiStatusText: document.getElementById("api-status-text"),
  captureBtn: document.getElementById("capture-btn"),
  dashboardBtn: document.getElementById("dashboard-btn"),
  consoleBtn: document.getElementById("console-btn"),
  demoBtn: document.getElementById("demo-btn"),
  alertsToggle: document.getElementById("alerts-toggle"),
  messageInput: document.getElementById("message-input"),
  samplePhishBtn: document.getElementById("sample-phish-btn"),
  sampleSafeBtn: document.getElementById("sample-safe-btn"),
  clearBtn: document.getElementById("clear-btn"),
  scanBtn: document.getElementById("scan-btn"),
  errorBox: document.getElementById("error-box"),
  resultPanel: document.getElementById("result-panel"),
  verdictHeadline: document.getElementById("verdict-headline"),
  riskScore: document.getElementById("risk-score"),
  verdictBadge: document.getElementById("verdict-badge"),
  attackVector: document.getElementById("attack-vector"),
  riskBar: document.getElementById("risk-bar"),
  recommendedAction: document.getElementById("recommended-action"),
  breakdownRow: document.getElementById("breakdown-row"),
  scoreHeuristics: document.getElementById("score-heuristics"),
  scoreRegex: document.getElementById("score-regex"),
  scoreSemantic: document.getElementById("score-semantic"),
  linksSection: document.getElementById("links-section"),
  linksList: document.getElementById("links-list"),
  signalsList: document.getElementById("signals-list"),
};

let currentSourceUrl = null;

async function checkBackendHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    elements.apiDot.className = "w-2 h-2 rounded-full bg-emerald-500";
    elements.apiStatusText.textContent = "ready";
    elements.apiStatusText.className = "text-xs text-emerald-400 font-mono";
  } catch {
    elements.apiDot.className = "w-2 h-2 rounded-full bg-rose-500";
    elements.apiStatusText.textContent = "offline";
    elements.apiStatusText.className = "text-xs text-rose-400 font-mono";
  }
}

async function captureActiveTabText() {
  hideError();
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      showError("No active browser tab found.");
      return;
    }
    currentSourceUrl = tab.url || null;

    if (tab.url && (tab.url.startsWith("chrome://") || tab.url.startsWith("edge://"))) {
      showError("Cannot read browser settings pages. Paste a message directly below.");
      return;
    }

    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const selected = window.getSelection()?.toString().trim();
        if (selected && selected.length > 0) {
          return { text: selected, mode: "selection" };
        }
        const mainNode = document.querySelector("main, article, [role='main']") || document.body;
        const bodyText = (mainNode?.innerText || "").trim().slice(0, 4000);
        return { text: bodyText, mode: "page" };
      },
    });

    const payload = results?.[0]?.result;
    if (payload?.text) {
      elements.messageInput.value = payload.text;
    } else {
      showError("No readable text found on this page.");
    }
  } catch (err) {
    showError(`Could not grab text: ${err.message}`);
  }
}

function showError(message) {
  elements.errorBox.textContent = message;
  elements.errorBox.classList.remove("hidden");
}

function hideError() {
  elements.errorBox.textContent = "";
  elements.errorBox.classList.add("hidden");
}

function applyRiskTheme(score, verdict) {
  let badgeClass = "badge bg-emerald-500/15 text-emerald-300 border border-emerald-500/30";
  let barClass = "progress-fill bg-emerald-500";
  let label = "Looks Safe";
  let headline = "Looks Safe to Read";

  if (score >= 65 || verdict === "high_risk") {
    badgeClass = "badge bg-rose-500/15 text-rose-300 border border-rose-500/30";
    barClass = "progress-fill bg-rose-500";
    label = "Likely Scam";
    headline = "Danger — Likely a Scam";
  } else if (score >= 30 || verdict === "caution") {
    badgeClass = "badge bg-amber-500/15 text-amber-300 border border-amber-500/30";
    barClass = "progress-fill bg-amber-500";
    label = "Be Careful";
    headline = "Caution — Verify Sender";
  }

  elements.verdictHeadline.textContent = headline;
  elements.verdictBadge.className = badgeClass;
  elements.verdictBadge.textContent = label;
  elements.riskBar.className = barClass;
  elements.riskBar.style.width = `${Math.max(4, Math.min(100, score))}%`;
}

function renderLinks(links) {
  elements.linksList.innerHTML = "";
  if (!links || links.length === 0) {
    elements.linksSection.classList.add("hidden");
    return;
  }
  elements.linksSection.classList.remove("hidden");
  for (const lk of links) {
    const row = document.createElement("div");
    row.className = "signal-chip";
    const top = document.createElement("div");
    top.className = "flex items-center justify-between gap-2";
    const host = document.createElement("span");
    host.className = "font-mono text-xs text-white";
    host.textContent = lk.host;
    const status = document.createElement("span");
    status.className =
      lk.status === "malicious"
        ? "badge bg-rose-500/15 text-rose-300"
        : lk.status === "suspicious"
          ? "badge bg-amber-500/15 text-amber-300"
          : "badge bg-emerald-500/15 text-emerald-300";
    status.textContent = lk.status;
    top.appendChild(host);
    top.appendChild(status);

    const reason = document.createElement("div");
    reason.className = "text-xs text-slate-400 mt-1";
    reason.textContent = lk.reason;

    row.appendChild(top);
    row.appendChild(reason);
    elements.linksList.appendChild(row);
  }
}

function renderSignals(signals) {
  elements.signalsList.innerHTML = "";
  if (!signals || signals.length === 0) {
    const empty = document.createElement("div");
    empty.className = "signal-chip text-slate-400";
    empty.textContent = "No scam warning signs found in this message.";
    elements.signalsList.appendChild(empty);
    return;
  }

  for (const sig of signals) {
    const item = document.createElement("div");
    item.className = "signal-chip text-slate-200";
    const title = document.createElement("div");
    title.className = "font-semibold text-white";
    title.textContent = `${sig.label} (+${sig.weight})`;
    const detail = document.createElement("div");
    detail.className = "text-xs text-slate-400 mt-1";
    detail.textContent = sig.evidence || sig.category || "";
    item.appendChild(title);
    item.appendChild(detail);
    elements.signalsList.appendChild(item);
  }
}

function renderResult(data) {
  elements.resultPanel.classList.remove("hidden");
  elements.riskScore.textContent = String(data.risk_score ?? 0);
  elements.attackVector.textContent = data.attack_vector || "";
  elements.recommendedAction.textContent = data.recommended_action
    ? `What to do: ${data.recommended_action}`
    : data.summary || "";
  applyRiskTheme(data.risk_score ?? 0, data.verdict);

  if (data.breakdown) {
    elements.breakdownRow.classList.remove("hidden");
    elements.scoreHeuristics.textContent = String(data.breakdown.heuristics ?? 0);
    elements.scoreRegex.textContent = String(data.breakdown.regex ?? 0);
    elements.scoreSemantic.textContent = String(data.breakdown.ai_semantic ?? 0);
  } else {
    elements.breakdownRow.classList.add("hidden");
  }

  renderLinks(data.inspected_links);
  renderSignals(data.signals);
}

async function runScan() {
  hideError();
  const text = elements.messageInput.value.trim();
  if (!text) {
    showError("Paste a message or click 'Grab Page Text' first.");
    return;
  }

  elements.scanBtn.disabled = true;
  elements.scanBtn.textContent = "Checking...";

  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text,
        source_url: currentSourceUrl,
        channel: "popup",
      }),
    });

    if (!response.ok) {
      throw new Error(`API returned HTTP ${response.status}`);
    }

    const data = await response.json();
    renderResult(data);
  } catch (err) {
    showError(`Local PhishGuard server is offline. Start uvicorn on 127.0.0.1:8000 first. (${err.message})`);
  } finally {
    elements.scanBtn.disabled = false;
    elements.scanBtn.textContent = "Check If This Is Safe";
  }
}

async function initAlertToggle() {
  if (!chrome?.storage?.local) return;
  const stored = await chrome.storage.local.get({ onPageAlertsEnabled: true });
  elements.alertsToggle.classList.toggle("active", Boolean(stored.onPageAlertsEnabled));

  elements.alertsToggle.addEventListener("click", async () => {
    const next = !elements.alertsToggle.classList.contains("active");
    elements.alertsToggle.classList.toggle("active", next);
    await chrome.storage.local.set({ onPageAlertsEnabled: next });

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id) {
        chrome.tabs.sendMessage(tab.id, { type: "PHISHGUARD_TOGGLE_ALERTS", enabled: next }).catch(() => {});
      }
    } catch {
      // Ignore tabs without content script attached
    }
  });
}

elements.captureBtn.addEventListener("click", captureActiveTabText);
elements.scanBtn.addEventListener("click", runScan);
elements.samplePhishBtn.addEventListener("click", () => {
  elements.messageInput.value = SAMPLE_PHISH;
  hideError();
  runScan();
});
elements.sampleSafeBtn.addEventListener("click", () => {
  elements.messageInput.value = SAMPLE_SAFE;
  hideError();
  runScan();
});
elements.clearBtn.addEventListener("click", () => {
  elements.messageInput.value = "";
  elements.resultPanel.classList.add("hidden");
  hideError();
});
elements.dashboardBtn.addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
});
elements.consoleBtn.addEventListener("click", () => {
  chrome.tabs.create({ url: `${API_BASE}/` });
});
elements.demoBtn.addEventListener("click", () => {
  chrome.tabs.create({ url: `${API_BASE}/demo` });
});

document.addEventListener("DOMContentLoaded", async () => {
  checkBackendHealth();
  initAlertToggle();

  try {
    const stored = await chrome.storage.local.get("lastContextScan");
    const last = stored?.lastContextScan;
    if (last && Date.now() - last.capturedAt < 30000) {
      elements.messageInput.value = last.text;
      renderResult(last.result);
      await chrome.storage.local.remove("lastContextScan");
      return;
    }
  } catch {
    // Ignore storage error
  }

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id && tab.url && !tab.url.startsWith("chrome://")) {
      currentSourceUrl = tab.url;
      const res = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => window.getSelection()?.toString().trim() || "",
      });
      const selected = res?.[0]?.result;
      if (selected) {
        elements.messageInput.value = selected;
      }
    }
  } catch {
    // Silent fallback when active tab cannot be scripted
  }
});
