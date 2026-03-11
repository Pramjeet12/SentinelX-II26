"""FastAPI scoring server — receives URLs, returns phishing scores."""

from fastapi import FastAPI
from pydantic import BaseModel

from scorer.openai_scorer import score_url

app = FastAPI(title="SentinelX Scorer", version="0.1.0")


class ScanRequest(BaseModel):
    url: str


class ScanResponse(BaseModel):
    url: str
    score: float
    reasons: list[str]
    verdict: str
    error: str | None = None


@app.post("/scan", response_model=ScanResponse)
async def scan_url(req: ScanRequest):
    result = await score_url(req.url)
    score = result["score"]

    if score > 0.7:
        verdict = "block"
    elif score > 0.3:
        verdict = "warn"
    else:
        verdict = "allow"

    return ScanResponse(
        url=req.url,
        score=score,
        reasons=result["reasons"],
        verdict=verdict,
        error=result.get("error"),
    )


@app.get("/health")
async def health():
    return {"status": "ok"}
