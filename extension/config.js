// PhishGuard AI — API endpoint configuration
// When deployed to Render, set DEPLOYED_URL to your Render URL.
// The extension auto-prefers the deployed URL and falls back to localhost.
const DEPLOYED_URL = ""; // e.g. "https://phishguard-ai.onrender.com"
const LOCAL_URL = "http://127.0.0.1:8000";

async function resolveApiBase() {
  if (DEPLOYED_URL) {
    try {
      const r = await fetch(`${DEPLOYED_URL}/health`, { signal: AbortSignal.timeout(3000) });
      if (r.ok) return DEPLOYED_URL;
    } catch { /* fall through */ }
  }
  return LOCAL_URL;
}
