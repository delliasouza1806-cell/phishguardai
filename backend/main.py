from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from analyzer import analyze_message
from web_ui import WEB_CONSOLE_HTML

app = FastAPI(
    title="PhishGuard AI API",
    description="Real-time social engineering and Gen-AI phishing detection core",
    version="1.1.0",
)

# Enable CORS so Chrome extensions (chrome-extension://...) and web pages can call the local trust layer.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Privacy-first in-memory ring buffer storing only redacted scan metadata for the risk dashboard.
RECENT_REPORTS: deque[dict] = deque(maxlen=50)
DEMO_INBOX_PATH = Path(__file__).resolve().parent.parent / "demo" / "mock_inbox.html"


class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000, description="On-page or selected message text to inspect")
    source_url: str | None = Field(default=None, description="Optional active tab URL for domain mismatch checks")
    channel: str | None = Field(default="popup", description="Scan origin (popup, content_script, web-console, context-menu)")


class SignalOut(BaseModel):
    category: str
    code: str
    label: str
    weight: int
    evidence: str
    phrase: str = ""


class InspectedLinkOut(BaseModel):
    url: str
    host: str
    status: str
    reason: str


class ScanResponse(BaseModel):
    risk_score: int
    verdict: str
    attack_vector: str
    recommended_action: str
    summary: str
    breakdown: dict[str, int]
    signals: list[SignalOut]
    matched_phrases: list[str]
    inspected_links: list[InspectedLinkOut]
    scanned_at: str


class BatchItem(BaseModel):
    id: str
    text: str = Field(..., min_length=1, max_length=8000)


class BatchScanRequest(BaseModel):
    source_url: str | None = None
    items: list[BatchItem] = Field(..., max_length=25)


class BatchScanResult(BaseModel):
    id: str
    risk_score: int
    verdict: str
    attack_vector: str
    recommended_action: str
    summary: str
    top_signal: str | None = None
    matched_phrases: list[str] = Field(default_factory=list)


def _record_report(
    result_score: int,
    verdict: str,
    attack_vector: str,
    breakdown: dict[str, int],
    signals_count: int,
    top_signal: str | None,
    redacted_preview: str,
    text_hash: str,
    source_url: str | None,
    channel: str | None,
    scanned_at: str,
) -> None:
    host = urlparse(source_url).hostname if source_url else None
    if RECENT_REPORTS and RECENT_REPORTS[0]["text_hash"] == text_hash and RECENT_REPORTS[0]["channel"] == channel:
        return
    RECENT_REPORTS.appendleft(
        {
            "id": f"{text_hash}-{len(RECENT_REPORTS) + 1}",
            "text_hash": text_hash,
            "risk_score": result_score,
            "verdict": verdict,
            "attack_vector": attack_vector,
            "breakdown": breakdown,
            "signals_count": signals_count,
            "top_signal": top_signal,
            "preview": redacted_preview,
            "source_host": host or "manual-paste",
            "channel": channel or "popup",
            "scanned_at": scanned_at,
        }
    )


@app.get("/", response_class=HTMLResponse)
def web_console() -> HTMLResponse:
    return HTMLResponse(content=WEB_CONSOLE_HTML)


@app.get("/demo", response_class=HTMLResponse)
def demo_inbox() -> HTMLResponse:
    if DEMO_INBOX_PATH.exists():
        return HTMLResponse(content=DEMO_INBOX_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Demo inbox file not found</h1>", status_code=404)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "phishguard-ai", "mode": "real-time-detection"}


@app.post("/scan", response_model=ScanResponse)
def scan_text(payload: ScanRequest) -> ScanResponse:
    result = analyze_message(payload.text, source_url=payload.source_url)
    scanned_at = datetime.now(timezone.utc).isoformat()
    top_signal = result.signals[0].label if result.signals else None

    _record_report(
        result_score=result.risk_score,
        verdict=result.verdict,
        attack_vector=result.attack_vector,
        breakdown=result.breakdown,
        signals_count=len(result.signals),
        top_signal=top_signal,
        redacted_preview=result.redacted_preview,
        text_hash=result.text_hash,
        source_url=payload.source_url,
        channel=payload.channel,
        scanned_at=scanned_at,
    )

    return ScanResponse(
        risk_score=result.risk_score,
        verdict=result.verdict,
        attack_vector=result.attack_vector,
        recommended_action=result.recommended_action,
        summary=result.summary,
        breakdown=result.breakdown,
        signals=[SignalOut(**sig.to_dict()) for sig in result.signals],
        matched_phrases=result.matched_phrases,
        inspected_links=[InspectedLinkOut(**lk.to_dict()) for lk in result.inspected_links],
        scanned_at=scanned_at,
    )


@app.post("/scan/batch", response_model=list[BatchScanResult])
def scan_batch(payload: BatchScanRequest) -> list[BatchScanResult]:
    scanned_at = datetime.now(timezone.utc).isoformat()
    responses: list[BatchScanResult] = []

    for item in payload.items:
        result = analyze_message(item.text, source_url=payload.source_url)
        top_signal = result.signals[0].label if result.signals else None
        if result.risk_score >= 30:
            _record_report(
                result_score=result.risk_score,
                verdict=result.verdict,
                attack_vector=result.attack_vector,
                breakdown=result.breakdown,
                signals_count=len(result.signals),
                top_signal=top_signal,
                redacted_preview=result.redacted_preview,
                text_hash=result.text_hash,
                source_url=payload.source_url,
                channel="on-page",
                scanned_at=scanned_at,
            )
        responses.append(
            BatchScanResult(
                id=item.id,
                risk_score=result.risk_score,
                verdict=result.verdict,
                attack_vector=result.attack_vector,
                recommended_action=result.recommended_action,
                summary=result.summary,
                top_signal=top_signal,
                matched_phrases=result.matched_phrases,
            )
        )

    return responses


@app.get("/reports")
def list_reports() -> dict:
    reports = list(RECENT_REPORTS)
    total = len(reports)
    high_risk_count = sum(1 for r in reports if r["verdict"] == "high_risk")
    caution_count = sum(1 for r in reports if r["verdict"] == "caution")
    safe_count = sum(1 for r in reports if r["verdict"] == "safe")
    avg_score = round(sum(r["risk_score"] for r in reports) / total) if total else 0

    return {
        "stats": {
            "total_scans": total,
            "high_risk": high_risk_count,
            "caution": caution_count,
            "safe": safe_count,
            "average_risk_score": avg_score,
        },
        "reports": reports,
    }


@app.delete("/reports")
def clear_reports() -> dict[str, str]:
    RECENT_REPORTS.clear()
    return {"status": "cleared"}
