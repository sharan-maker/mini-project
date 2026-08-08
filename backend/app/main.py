"""
main.py
-------
FastAPI entrypoint. Exposes a single core endpoint:

    POST /scan   { "url": "https://example.com" }
    -> returns classification, threat score, and explanation reasons

No database is required at this stage (see requirements.txt note).
Runs entirely on free/open-source packages — no paid API keys needed.
"""

import sys
import os
import time

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from models.predict import predict_url  # noqa: E402
from schemas import ScanRequest, ScanResponse, HealthResponse  # noqa: E402

app = FastAPI(
    title="AI-Based Website Threat Detection API",
    description="Analyzes a website's SSL/TLS, URL, headers, WHOIS, and DNS "
                "features to classify it as Safe, Suspicious, or Malicious.",
    version="0.1.0",
)

# CORS: allows the React frontend (running on a different port during dev)
# to call this API. Free, built into FastAPI, no external service.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_model=HealthResponse)
def root():
    """Basic health check endpoint."""
    return {"status": "ok", "message": "AI Website Threat Detection API is running"}


@app.get("/health", response_model=HealthResponse)
def health():
    return {"status": "ok", "message": "healthy"}


@app.post("/scan", response_model=ScanResponse)
def scan_website(request: ScanRequest):
    """
    Runs the full analysis pipeline (SSL, URL, headers, WHOIS, DNS)
    on the given URL and returns a threat classification with
    explanation reasons.
    """
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL must not be empty")

    start = time.time()
    try:
        result = predict_url(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

    result["scan_duration_seconds"] = round(time.time() - start, 2)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)