(() => {
  const API_BASE = "http://127.0.0.1:8000";
  const MESSAGE_SELECTORS = [
    ".a3s", // Gmail message body
    "[aria-label*='Message body']", // Outlook
    ".msg-s-event-listitem__body", // LinkedIn messaging
    "[data-qa='message-text']", // Slack
    "[data-pg-message]", // Mock inbox & explicit test containers
    "article",
    "blockquote",
  ].join(",");

  let alertsEnabled = true;
  let scanTimer = null;
  let nextId = 1;
  const scannedHashes = new WeakMap();
  const nodeById = new Map();

  function hashText(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) {
      h = (h * 31 + str.charCodeAt(i)) | 0;
    }
    return String(h);
  }

  function clearAllAlerts() {
    document.querySelectorAll(".pg-alert-banner, .pg-floating-pill").forEach((el) => el.remove());
    document.querySelectorAll(".pg-flagged-high, .pg-flagged-caution").forEach((el) => {
      el.classList.remove("pg-flagged-high", "pg-flagged-caution");
    });
  }

  function updateFloatingPill(highCount, cautionCount) {
    let pill = document.getElementById("pg-floating-pill");
    if (!alertsEnabled) {
      if (pill) pill.remove();
      return;
    }
    if (!pill) {
      pill = document.createElement("button");
      pill.type = "button";
      pill.id = "pg-floating-pill";
      pill.className = "pg-floating-pill";
      pill.title = "Click to open PhishGuard AI Risk Dashboard";
      pill.innerHTML = `<span class="pg-pill-dot"></span><span class="pg-pill-label"></span>`;
      pill.addEventListener("click", () => {
        chrome?.runtime?.sendMessage?.({ type: "PHISHGUARD_OPEN_DASHBOARD" });
      });
      document.body.appendChild(pill);
    }

    pill.classList.remove("pg-has-high", "pg-has-caution");
    const label = pill.querySelector(".pg-pill-label");
    if (highCount > 0) {
      pill.classList.add("pg-has-high");
      label.textContent = `PhishGuard: ${highCount} High-Risk Alert${highCount > 1 ? "s" : ""}`;
    } else if (cautionCount > 0) {
      pill.classList.add("pg-has-caution");
      label.textContent = `PhishGuard: ${cautionCount} Caution`;
    } else {
      label.textContent = "PhishGuard Active · Safe";
    }

    chrome?.runtime?.sendMessage?.({
      type: "PHISHGUARD_TAB_RISK_COUNT",
      highCount,
      cautionCount,
    });
  }

  function applyColorAlert(el, result) {
    const existingBanner = el.previousElementSibling;
    if (existingBanner && existingBanner.classList.contains("pg-alert-banner")) {
      existingBanner.remove();
    }
    el.classList.remove("pg-flagged-high", "pg-flagged-caution");

    if (result.verdict !== "high_risk" && result.verdict !== "caution") {
      return;
    }

    const isHigh = result.verdict === "high_risk";
    el.classList.add(isHigh ? "pg-flagged-high" : "pg-flagged-caution");

    const banner = document.createElement("div");
    banner.className = `pg-alert-banner ${isHigh ? "pg-high" : "pg-caution"}`;

    const badge = document.createElement("span");
    badge.className = "pg-alert-badge";
    badge.textContent = isHigh ? `HIGH RISK · ${result.risk_score}` : `CAUTION · ${result.risk_score}`;

    const text = document.createElement("span");
    text.className = "pg-alert-text";
    const vectorPrefix = result.attack_vector ? `[${result.attack_vector}] ` : "";
    const detail = result.top_signal ? `${result.top_signal} — ${result.recommended_action || result.summary}` : result.summary;
    text.textContent = `${vectorPrefix}${detail}`;

    const dismiss = document.createElement("button");
    dismiss.className = "pg-alert-dismiss";
    dismiss.textContent = "Dismiss";
    dismiss.addEventListener("click", () => {
      banner.remove();
      el.classList.remove("pg-flagged-high", "pg-flagged-caution");
    });

    banner.appendChild(badge);
    banner.appendChild(text);
    banner.appendChild(dismiss);
    el.parentNode?.insertBefore(banner, el);
  }

  async function scanVisibleMessages() {
    if (!alertsEnabled || !document.body) return;

    const candidates = Array.from(document.querySelectorAll(MESSAGE_SELECTORS));
    const targets = candidates.length > 0 ? candidates : Array.from(document.querySelectorAll("p"));

    const batchItems = [];
    for (const el of targets) {
      if (el.closest("#pg-floating-pill, .pg-alert-banner")) continue;
      const text = (el.innerText || "").trim();
      if (text.length < 50 || text.length > 8000) continue;

      const h = hashText(text);
      if (scannedHashes.get(el) === h) continue;
      scannedHashes.set(el, h);

      const id = `pg-${nextId++}`;
      nodeById.set(id, el);
      batchItems.push({ id, text });
      if (batchItems.length >= 15) break;
    }

    if (batchItems.length === 0) return;

    try {
      const resp = await fetch(`${API_BASE}/scan/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_url: window.location.href,
          items: batchItems,
        }),
      });
      if (!resp.ok) return;
      const results = await resp.json();

      for (const res of results) {
        const el = nodeById.get(res.id);
        nodeById.delete(res.id);
        if (!el || !el.isConnected) continue;
        applyColorAlert(el, res);
      }

      const highCount = document.querySelectorAll(".pg-flagged-high").length;
      const cautionCount = document.querySelectorAll(".pg-flagged-caution").length;
      updateFloatingPill(highCount, cautionCount);
    } catch {
      // Backend offline — remain unobtrusive on host page
    }
  }

  function scheduleScan() {
    if (!alertsEnabled) return;
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scanVisibleMessages, 400);
  }

  async function init() {
    if (chrome?.storage?.local) {
      const stored = await chrome.storage.local.get({ onPageAlertsEnabled: true });
      alertsEnabled = Boolean(stored.onPageAlertsEnabled);
    }

    chrome?.runtime?.onMessage?.addListener((msg) => {
      if (msg?.type === "PHISHGUARD_TOGGLE_ALERTS") {
        alertsEnabled = Boolean(msg.enabled);
        if (!alertsEnabled) {
          clearAllAlerts();
        } else {
          scheduleScan();
        }
      }
    });

    if (alertsEnabled) {
      scheduleScan();
    }

    const observer = new MutationObserver((mutations) => {
      const hasAddedNodes = mutations.some((m) => m.addedNodes.length > 0);
      if (hasAddedNodes) scheduleScan();
    });
    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true });
    }
  }

  init();
})();
