# PhishGuard AI (Logic Bombs · BuildX)

A live trust layer for every workspace that detects Gen-AI social engineering in real time.

## Architecture

- **`backend/main.py` & `backend/web_ui.py`** — FastAPI detection core + **Interactive Web Trust Console** (`GET /`) + **Mock Inbox Demo** (`GET /demo`) + Swagger API Docs (`GET /docs`).
- **`backend/analyzer.py`** — Tri-lane real-time detection engine:
  - **Heuristics**: Urgency deadlines, executive BEC impersonation, secrecy/bypass coercion, Web3 wallet lures.
  - **Localized Regex & URL Inspector**: Raw IP hosts, punycode (`xn--`), URL shorteners, risky TLDs, credential paths, brand-domain mismatch, invisible zero-width Unicode & mixed-script homoglyph evasion, OTP/wire asks.
  - **AI-vs-AI Semantic Analytics**: LLM formal-politeness + urgency pivots, templated cadence clustering, hyper-personalized recruiter lures, and typo-free synthetic polish detection.
  - **Privacy-First Telemetry**: Masks emails, long numeric tokens, and URL query secrets before storing in the live report feed.
- **`extension/`** — Chrome Extension (Manifest V3):
  - `popup.html` / `popup.js` — Interactive popup with page/selection capture, risk gauge, tri-lane score breakdown, inspected link verdicts, and actionable guidance.
  - `content.js` / `content.css` — Real-time on-page Red/Amber color alerts, dismissible warning banners, and a clickable floating trust pill.
  - `background.js` — Right-click context menu ("Scan selection with PhishGuard AI") and live toolbar badge counters.
  - `dashboard.html` / `dashboard.js` — Risk Dashboard with live KPIs, verdict filters, and JSON report export.

## Quick Start (1 Command + Extension)

### 1. Start the Backend & Web Console
```powershell
cd "C:\Users\91839\Desktop\BuildX hackathon\phishguard-ai\backend"
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
Then open:
- **Live Web Command Center**: `http://127.0.0.1:8000/`
- **Simulated Workspace Inbox Demo**: `http://127.0.0.1:8000/demo`
- **API Docs**: `http://127.0.0.1:8000/docs`

### 2. Load the Chrome Extension
1. Open `chrome://extensions` in Chrome.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select `C:\Users\91839\Desktop\BuildX hackathon\phishguard-ai\extension`.
4. Open `http://127.0.0.1:5500/demo` in Chrome to see real-time Red/Amber on-page color alerts, toolbar badge counters, and right-click context menu scanning.
