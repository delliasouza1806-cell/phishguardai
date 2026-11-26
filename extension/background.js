const API_BASE = "http://127.0.0.1:8000";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishguard-scan-selection",
    title: "Scan selection with PhishGuard AI",
    contexts: ["selection"],
  });
});

function setTabBadge(tabId, highCount, cautionCount) {
  if (!tabId) return;
  if (highCount > 0) {
    chrome.action.setBadgeText({ tabId, text: String(highCount) });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#dc2626" });
  } else if (cautionCount > 0) {
    chrome.action.setBadgeText({ tabId, text: String(cautionCount) });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#d97706" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "OK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#059669" });
  }
}

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg?.type === "PHISHGUARD_TAB_RISK_COUNT" && sender?.tab?.id) {
    setTabBadge(sender.tab.id, msg.highCount || 0, msg.cautionCount || 0);
  }
  if (msg?.type === "PHISHGUARD_OPEN_DASHBOARD") {
    chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
  }
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "phishguard-scan-selection" || !info.selectionText) return;
  const text = info.selectionText.trim();
  if (!text) return;

  try {
    const resp = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text,
        source_url: tab?.url || null,
        channel: "context-menu",
      }),
    });
    if (!resp.ok) return;
    const data = await resp.json();

    await chrome.storage.local.set({
      lastContextScan: {
        text,
        result: data,
        capturedAt: Date.now(),
      },
    });

    if (tab?.id) {
      const isHigh = data.verdict === "high_risk";
      const isCaution = data.verdict === "caution";
      chrome.action.setBadgeText({ tabId: tab.id, text: String(data.risk_score) });
      chrome.action.setBadgeBackgroundColor({
        tabId: tab.id,
        color: isHigh ? "#dc2626" : isCaution ? "#d97706" : "#059669",
      });
    }
  } catch {
    // Ignore when local backend is offline
  }
});
