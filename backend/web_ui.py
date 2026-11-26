WEB_CONSOLE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PhishGuard AI — Check Any Message Before You Click</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    :root {
      --bg: #070c18;
      --card: #0f172a;
      --card-2: #162038;
      --border: rgba(148, 163, 184, 0.2);
      --blue: #2563eb;
      --blue-soft: rgba(37, 99, 235, 0.16);
      --text: #f8fafc;
      --muted: #94a3b8;
      --red: #f43f5e;
      --amber: #f59e0b;
      --green: #10b981;
    }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
      background: radial-gradient(circle at top right, rgba(37, 99, 235, 0.18), transparent 45%), var(--bg);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.5;
    }
    .shell { max-width: 1180px; margin: 0 auto; padding: 24px 20px 48px; display: grid; gap: 18px; }
    .topbar {
      display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px;
      padding: 16px 20px; background: var(--card); border: 1px solid var(--border); border-radius: 14px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .logo {
      width: 42px; height: 42px; border-radius: 11px;
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      display: grid; place-items: center; font-weight: 800; font-size: 19px; color: #fff;
      box-shadow: 0 6px 20px rgba(37, 99, 235, 0.4);
    }
    .pill {
      display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px;
      border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: 0.03em; text-transform: uppercase;
    }
    .pill-blue { background: var(--blue-soft); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.35); }
    .pill-green { background: rgba(16, 185, 129, 0.14); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.35); }
    .pill-amber { background: rgba(245, 158, 11, 0.15); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.35); }
    .pill-red { background: rgba(244, 63, 94, 0.16); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.35); }

    .nav-links { display: flex; flex-wrap: wrap; gap: 8px; }
    .btn {
      border: 1px solid var(--border); background: var(--card-2); color: var(--text);
      padding: 8px 14px; border-radius: 8px; font-size: 12.5px; font-weight: 600; cursor: pointer;
      text-decoration: none; display: inline-flex; align-items: center; gap: 6px; transition: 0.15s ease;
    }
    .btn:hover { border-color: rgba(96, 165, 250, 0.55); background: #1e2b48; }
    .btn-primary {
      background: linear-gradient(135deg, #2563eb, #1d4ed8); border-color: transparent;
      box-shadow: 0 4px 16px rgba(37, 99, 235, 0.35);
    }
    .btn-primary:hover { background: linear-gradient(135deg, #3b82f6, #2563eb); }

    /* Friendly 3-Step Intro Banner */
    .how-it-works {
      display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px;
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.12), rgba(15, 23, 42, 0.95));
      border: 1px solid rgba(59, 130, 246, 0.28); border-radius: 14px; padding: 14px 18px;
    }
    .step-item { display: flex; align-items: flex-start; gap: 10px; }
    .step-num {
      width: 24px; height: 24px; border-radius: 999px; background: #2563eb; color: #fff;
      font-size: 12px; font-weight: 800; display: grid; place-items: center; flex-shrink: 0; margin-top: 2px;
    }
    .step-title { font-size: 13px; font-weight: 700; color: #fff; }
    .step-desc { font-size: 12px; color: var(--muted); }

    .kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
    .kpi { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; }
    .kpi-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); font-weight: 600; }
    .kpi-val { font-size: 26px; font-weight: 800; margin-top: 4px; }

    .grid-2 { display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 18px; align-items: start; }
    @media (max-width: 900px) {
      .how-it-works, .kpis { grid-template-columns: 1fr; }
      .grid-2 { grid-template-columns: 1fr; }
    }
    .panel {
      background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 18px;
      display: flex; flex-direction: column; gap: 14px;
    }
    .panel h2 { margin: 0; font-size: 16px; }
    .sub { margin: 2px 0 0; font-size: 12.5px; color: var(--muted); }

    .presets { display: flex; flex-wrap: wrap; gap: 6px; }
    textarea {
      width: 100%; min-height: 140px; background: #090f1d; color: var(--text);
      border: 1px solid var(--border); border-radius: 10px; padding: 12px;
      font-family: inherit; font-size: 13.5px; line-height: 1.55; resize: vertical; outline: none;
    }
    textarea:focus { border-color: #3b82f6; box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.22); }

    .verdict-banner {
      border-radius: 12px; padding: 14px 16px; display: flex; flex-direction: column; gap: 10px;
      border: 1px solid var(--border); background: var(--card-2);
    }
    .verdict-banner.is-high { border-color: rgba(244, 63, 94, 0.45); background: rgba(244, 63, 94, 0.08); }
    .verdict-banner.is-caution { border-color: rgba(245, 158, 11, 0.45); background: rgba(245, 158, 11, 0.08); }
    .verdict-banner.is-safe { border-color: rgba(16, 185, 129, 0.45); background: rgba(16, 185, 129, 0.08); }

    .score-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
    .score-num { font-size: 34px; font-weight: 800; line-height: 1; }
    .bar-track { height: 8px; background: #090f1d; border-radius: 999px; overflow: hidden; }
    .bar-fill { height: 100%; width: 0%; transition: width 0.35s ease, background-color 0.35s ease; border-radius: 999px; }

    .tri { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
    .tri-card { background: #0b1222; border: 1px solid var(--border); border-radius: 10px; padding: 10px; text-align: center; }
    .tri-card .lbl { font-size: 11px; color: #cbd5e1; font-weight: 600; }
    .tri-card .hint { font-size: 10.5px; color: var(--muted); }
    .tri-card .val { font-size: 18px; font-weight: 800; margin-top: 4px; }

    .highlighted-preview {
      background: #090f1d; border: 1px solid var(--border); border-radius: 10px; padding: 12px;
      font-size: 13px; line-height: 1.6; white-space: pre-wrap; color: #cbd5e1;
    }
    mark.pg-hit {
      background: rgba(244, 63, 94, 0.28); color: #fecdd3;
      border-bottom: 1px solid #f43f5e; padding: 1px 4px; border-radius: 4px;
    }

    .list-item {
      background: var(--card-2); border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px;
      display: flex; flex-direction: column; gap: 4px; font-size: 12.5px;
    }
    .feed { display: flex; flex-direction: column; gap: 10px; max-height: 520px; overflow-y: auto; }
    .muted { color: var(--muted); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }

    .setup-card {
      background: #0b1222; border: 1px dashed rgba(59, 130, 246, 0.4); border-radius: 12px; padding: 12px 14px;
      font-size: 12px; color: #cbd5e1;
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="logo">P</div>
        <div>
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <strong style="font-size:18px;">PhishGuard AI</strong>
            <span class="pill pill-blue">Logic Bombs · BuildX</span>
            <span id="health-pill" class="pill pill-green">Protection Active</span>
          </div>
          <p class="sub">Spot AI-written scams, fake urgent requests, and risky links before you click or reply.</p>
        </div>
      </div>
      <div class="nav-links">
        <a href="/demo" class="btn btn-primary" target="_blank">Try Live Inbox Demo</a>
        <button id="toggle-setup-btn" class="btn" type="button">Chrome Extension Setup</button>
        <a href="/docs" class="btn" target="_blank">API Docs</a>
      </div>
    </header>

    <!-- Plain-English 3-step explanation -->
    <section class="how-it-works">
      <div class="step-item">
        <div class="step-num">1</div>
        <div>
          <div class="step-title">Paste or Browse Normally</div>
          <div class="step-desc">Paste any email/DM below, or let the Chrome extension watch Gmail, LinkedIn &amp; Slack automatically.</div>
        </div>
      </div>
      <div class="step-item">
        <div class="step-num">2</div>
        <div>
          <div class="step-title">Instant 3-Layer AI Check</div>
          <div class="step-desc">Checks pressure tactics, dangerous links/OTP asks, and polite AI-written scam phrasing in milliseconds.</div>
        </div>
      </div>
      <div class="step-item">
        <div class="step-num">3</div>
        <div>
          <div class="step-title">Clear "Safe or Scam" Advice</div>
          <div class="step-desc">Highlights suspicious phrases and tells you exactly what to do — zero passwords or private data saved.</div>
        </div>
      </div>
    </section>

    <!-- Collapsible Chrome Extension Setup Guide -->
    <section id="extension-setup-card" class="setup-card" style="display:none;">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px;">
        <strong style="color:#fff;font-size:13px;">Install the Chrome Extension in 30 Seconds</strong>
        <button id="copy-ext-path-btn" class="btn" type="button" style="padding:5px 10px;font-size:11px;">Copy Extension Folder Path</button>
      </div>
      <div>
        1. Open <span class="mono">chrome://extensions</span> in Google Chrome and turn on <strong>Developer mode</strong> (top-right).<br />
        2. Click <strong>Load unpacked</strong> and choose: <span id="ext-path-text" class="mono" style="color:#93c5fd;">C:\\Users\\91839\\Desktop\\BuildX hackathon\\phishguard-ai\\extension</span><br />
        3. Open <a href="/demo" target="_blank" style="color:#60a5fa;">the Live Inbox Demo</a> to see red/amber scam banners appear right inside the page!
      </div>
    </section>

    <section class="kpis">
      <div class="kpi">
        <div class="kpi-label">Messages Checked</div>
        <div id="kpi-total" class="kpi-val">0</div>
      </div>
      <div class="kpi" style="border-color:rgba(244,63,94,0.35);">
        <div class="kpi-label" style="color:#fda4af;">Likely Scams Blocked</div>
        <div id="kpi-high" class="kpi-val" style="color:#fb7185;">0</div>
      </div>
      <div class="kpi" style="border-color:rgba(245,158,11,0.35);">
        <div class="kpi-label" style="color:#fcd34d;">Needs Caution</div>
        <div id="kpi-caution" class="kpi-val" style="color:#fbbf24;">0</div>
      </div>
      <div class="kpi" style="border-color:rgba(59,130,246,0.35);">
        <div class="kpi-label" style="color:#93c5fd;">Average Risk Score</div>
        <div id="kpi-avg" class="kpi-val" style="color:#60a5fa;">0</div>
      </div>
    </section>

    <div class="grid-2">
      <!-- Left: Interactive Scanner -->
      <section class="panel">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap;">
          <div>
            <h2>Check a Message Right Now</h2>
            <p class="sub">Pick a realistic example below or paste your own email, LinkedIn message, or text.</p>
          </div>
          <div style="display:flex;gap:6px;">
            <button id="paste-btn" class="btn" type="button" style="padding:6px 10px;font-size:11.5px;">Paste Clipboard</button>
            <button id="clear-input-btn" class="btn" type="button" style="padding:6px 10px;font-size:11.5px;">Clear</button>
          </div>
        </div>

        <div class="presets">
          <button class="btn" data-preset="bec" type="button">Fake Boss Wire Request</button>
          <button class="btn" data-preset="linkedin" type="button">Fake LinkedIn Job</button>
          <button class="btn" data-preset="sso" type="button">Fake Microsoft Login</button>
          <button class="btn" data-preset="crypto" type="button">Crypto Wallet Scam</button>
          <button class="btn" data-preset="safe" type="button">Normal Colleague Email</button>
        </div>

        <textarea id="scan-input" placeholder="Paste any suspicious email, LinkedIn DM, or SMS here to check if it's safe..."></textarea>

        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <button id="run-scan-btn" class="btn btn-primary" type="button" style="padding:10px 20px;font-size:13.5px;">
            Check If This Message Is Safe
          </button>
          <span id="scan-latency" class="sub mono"></span>
        </div>

        <div id="result-area" class="verdict-banner" style="display:none;">
          <div class="score-head">
            <div>
              <div id="res-headline" style="font-size:17px;font-weight:800;color:#fff;">--</div>
              <div id="res-vector" class="sub" style="color:#cbd5e1;font-weight:600;"></div>
            </div>
            <div style="text-align:right;">
              <span id="res-verdict" class="pill">--</span>
              <div style="margin-top:4px;font-size:12px;" class="muted">
                Risk: <strong id="res-score" style="color:#fff;font-size:15px;">0</strong>/100
              </div>
            </div>
          </div>

          <div class="bar-track"><div id="res-bar" class="bar-fill"></div></div>

          <div id="res-action" class="list-item" style="border-color:rgba(59,130,246,0.4);background:rgba(37,99,235,0.14);color:#e2e8f0;"></div>

          <div class="tri">
            <div class="tri-card">
              <div class="lbl">Pressure Tactics</div>
              <div class="hint">Urgency &amp; secrecy</div>
              <div id="bd-h" class="val">0</div>
            </div>
            <div class="tri-card">
              <div class="lbl">Links &amp; Codes</div>
              <div class="hint">URLs, OTP &amp; money</div>
              <div id="bd-r" class="val">0</div>
            </div>
            <div class="tri-card">
              <div class="lbl">AI Phishing Tone</div>
              <div class="hint">Polite scam cues</div>
              <div id="bd-ai" class="val">0</div>
            </div>
          </div>

          <div>
            <div class="kpi-label" style="margin-bottom:6px;">Suspicious Parts Highlighted</div>
            <div id="highlighted-box" class="highlighted-preview"></div>
          </div>

          <div id="links-section" style="display:none;">
            <div class="kpi-label" style="margin-bottom:6px;">Links Found in Message</div>
            <div id="links-list" style="display:flex;flex-direction:column;gap:6px;"></div>
          </div>

          <div>
            <div class="kpi-label" style="margin-bottom:6px;">Why It Was Flagged</div>
            <div id="signals-list" style="display:flex;flex-direction:column;gap:6px;"></div>
          </div>
        </div>
      </section>

      <!-- Right: Real-Time Telemetry Feed -->
      <section class="panel">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
          <div>
            <h2>Recent Activity</h2>
            <p class="sub">Live history from this page &amp; your Chrome extension (sensitive details masked).</p>
          </div>
          <div style="display:flex;gap:6px;">
            <button id="refresh-reports-btn" class="btn" type="button" style="padding:6px 10px;font-size:11.5px;">Refresh</button>
            <button id="clear-reports-btn" class="btn" type="button" style="padding:6px 10px;font-size:11.5px;">Clear</button>
          </div>
        </div>
        <div id="reports-feed" class="feed"></div>
      </section>
    </div>
  </div>

  <script>
    const PRESETS = {
      bec: `I hope this message finds you well. Kindly note that I am in back-to-back board meetings and need your immediate assistance finalizing an urgent vendor settlement before 4:00 PM today. Please keep this confidential, confirm the wire transfer via http://198.51.100.42/auth/sso-verify?tok=99182, and reply with your OTP verification code once submitted.`,
      linkedin: `Hi Alex — our executive team was impressed by your background and would like to invite you to a confidential search for an exclusive role. Kindly verify your portfolio and sign the NDA via https://bit.ly/verify-nda before the portal expires today.`,
      sso: `Action Required: Your Microsoft SSO session will be suspended today due to an unverified login. In order to ensure uninterrupted access, kindly confirm your MFA details at https://sso-check.xyz/login-confirm`,
      crypto: `Rest assured your wallet is eligible! Claim your reward before it expires today — connect your wallet via https://airdrop-claim.top/wallet to verify your recovery phrase and gas fee refund.`,
      safe: `Hey team, sharing the notes from this morning's design sync. We moved the sprint demo to Thursday at 2:00 PM in Conference Room B. No action needed before then—let me know if that time works.`
    };

    const scanInput = document.getElementById("scan-input");
    const runScanBtn = document.getElementById("run-scan-btn");
    const resultArea = document.getElementById("result-area");

    function escapeHtml(str) {
      return str.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    }

    function renderHighlightedText(rawText, phrases) {
      let safe = escapeHtml(rawText);
      const sorted = [...(phrases || [])].sort((a, b) => b.length - a.length);
      for (const p of sorted) {
        if (!p || p.length < 2) continue;
        const escaped = escapeHtml(p).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        safe = safe.replace(new RegExp(escaped, "gi"), (m) => `<mark class="pg-hit">${m}</mark>`);
      }
      return safe;
    }

    function themeForVerdict(v) {
      if (v === "high_risk") return ["is-high", "pill pill-red", "Likely Scam", "Danger — Likely a Scam", "#f43f5e"];
      if (v === "caution") return ["is-caution", "pill pill-amber", "Be Careful", "Caution — Double-Check Sender", "#f59e0b"];
      return ["is-safe", "pill pill-green", "Looks Safe", "Looks Safe to Read", "#10b981"];
    }

    async function analyzeCurrent() {
      const text = scanInput.value.trim();
      if (!text) return;
      runScanBtn.disabled = true;
      runScanBtn.textContent = "Checking message...";
      const t0 = performance.now();

      try {
        const res = await fetch("/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text, source_url: window.location.href, channel: "web-console" }),
        });
        const data = await res.json();
        const ms = Math.round(performance.now() - t0);
        document.getElementById("scan-latency").textContent = `Checked in ${ms}ms`;

        resultArea.style.display = "flex";
        const [boxClass, pClass, pText, headline, color] = themeForVerdict(data.verdict);
        resultArea.className = `verdict-banner ${boxClass}`;
        document.getElementById("res-headline").textContent = headline;
        document.getElementById("res-score").textContent = data.risk_score;

        const vEl = document.getElementById("res-verdict");
        vEl.className = pClass;
        vEl.textContent = pText;
        document.getElementById("res-vector").textContent = `Category: ${data.attack_vector || "General"}`;

        const bar = document.getElementById("res-bar");
        bar.style.width = `${Math.max(4, data.risk_score)}%`;
        bar.style.background = color;

        document.getElementById("res-action").innerHTML = `<strong>What you should do:</strong> ${escapeHtml(data.recommended_action || data.summary)}`;
        document.getElementById("bd-h").textContent = data.breakdown?.heuristics ?? 0;
        document.getElementById("bd-r").textContent = data.breakdown?.regex ?? 0;
        document.getElementById("bd-ai").textContent = data.breakdown?.ai_semantic ?? 0;

        document.getElementById("highlighted-box").innerHTML = renderHighlightedText(text, data.matched_phrases);

        const linksSection = document.getElementById("links-section");
        const linksList = document.getElementById("links-list");
        linksList.innerHTML = "";
        if (data.inspected_links && data.inspected_links.length > 0) {
          linksSection.style.display = "block";
          for (const lk of data.inspected_links) {
            const div = document.createElement("div");
            div.className = "list-item";
            const cls = lk.status === "malicious" ? "pill-red" : lk.status === "suspicious" ? "pill-amber" : "pill-green";
            div.innerHTML = `<div style="display:flex;justify-content:space-between;gap:8px;"><span class="mono">${escapeHtml(lk.host)}</span><span class="pill ${cls}">${lk.status}</span></div><span class="muted">${escapeHtml(lk.reason)}</span>`;
            linksList.appendChild(div);
          }
        } else {
          linksSection.style.display = "none";
        }

        const sigList = document.getElementById("signals-list");
        sigList.innerHTML = "";
        if (!data.signals || data.signals.length === 0) {
          sigList.innerHTML = `<div class="list-item muted">No scam warning signs found in this message.</div>`;
        } else {
          for (const s of data.signals) {
            const div = document.createElement("div");
            div.className = "list-item";
            div.innerHTML = `<div style="display:flex;justify-content:space-between;"><strong>${escapeHtml(s.label)}</strong><span class="mono">+${s.weight}</span></div><span class="muted">${escapeHtml(s.evidence)}</span>`;
            sigList.appendChild(div);
          }
        }

        await refreshReports();
      } finally {
        runScanBtn.disabled = false;
        runScanBtn.textContent = "Check If This Message Is Safe";
      }
    }

    async function refreshReports() {
      const res = await fetch("/reports");
      const data = await res.json();
      const s = data.stats || {};
      document.getElementById("kpi-total").textContent = s.total_scans ?? 0;
      document.getElementById("kpi-high").textContent = s.high_risk ?? 0;
      document.getElementById("kpi-caution").textContent = s.caution ?? 0;
      document.getElementById("kpi-avg").textContent = s.average_risk_score ?? 0;

      const feed = document.getElementById("reports-feed");
      feed.innerHTML = "";
      if (!data.reports || data.reports.length === 0) {
        feed.innerHTML = `<div class="list-item muted">Nothing checked yet. Click any example on the left or paste a message to begin.</div>`;
        return;
      }
      for (const r of data.reports) {
        const [, pClass, pText] = themeForVerdict(r.verdict);
        const card = document.createElement("div");
        card.className = "list-item";
        card.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;gap:6px;">
            <span class="${pClass}">${pText} · ${r.risk_score}</span>
            <span class="mono muted">${escapeHtml(r.source_host)}</span>
          </div>
          <div style="font-weight:600;color:#e2e8f0;">${escapeHtml(r.attack_vector || "Message Check")}</div>
          <div class="muted">${escapeHtml(r.preview)}</div>
        `;
        feed.appendChild(card);
      }
    }

    document.querySelectorAll("[data-preset]").forEach((btn) => {
      btn.addEventListener("click", () => {
        scanInput.value = PRESETS[btn.dataset.preset];
        analyzeCurrent();
      });
    });

    document.getElementById("paste-btn").addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          scanInput.value = text;
          analyzeCurrent();
        }
      } catch {
        scanInput.focus();
      }
    });

    document.getElementById("clear-input-btn").addEventListener("click", () => {
      scanInput.value = "";
      resultArea.style.display = "none";
      document.getElementById("scan-latency").textContent = "";
      scanInput.focus();
    });

    document.getElementById("toggle-setup-btn").addEventListener("click", () => {
      const box = document.getElementById("extension-setup-card");
      box.style.display = box.style.display === "none" ? "block" : "none";
    });

    document.getElementById("copy-ext-path-btn").addEventListener("click", async (e) => {
      const path = document.getElementById("ext-path-text").textContent;
      try {
        await navigator.clipboard.writeText(path);
        e.target.textContent = "Copied!";
        setTimeout(() => { e.target.textContent = "Copy Extension Folder Path"; }, 1500);
      } catch {
        // Ignore clipboard errors
      }
    });

    runScanBtn.addEventListener("click", analyzeCurrent);
    document.getElementById("refresh-reports-btn").addEventListener("click", refreshReports);
    document.getElementById("clear-reports-btn").addEventListener("click", async () => {
      await fetch("/reports", { method: "DELETE" });
      refreshReports();
    });

    // Run an automatic first demo check so first-time visitors immediately see how PhishGuard works
    scanInput.value = PRESETS.bec;
    analyzeCurrent();
    setInterval(refreshReports, 5000);
  </script>
</body>
</html>
"""
