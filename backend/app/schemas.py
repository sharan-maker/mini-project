"""
schemas.py
----------
Pydantic models defining the shape of API requests/responses.
Used by main.py for automatic validation and OpenAPI docs generation
(FastAPI gives you free interactive docs at /docs using these models).
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Request body for POST /scan"""
    url: str = Field(
        ...,
        description="The website URL to analyze",
        examples=["https://example.com"],
    )


class ScanDetails(BaseModel):
    """Nested detail block inside the scan response."""
    ssl: Optional[Dict[str, Any]] = None
    domain_age_days: Optional[int] = None
    tls_version: Optional[str] = None
    security_headers_present: Optional[Dict[str, Any]] = None
    security_headers_missing: Optional[List[str]] = None


class ScanResponse(BaseModel):
    """Response body for POST /scan"""
    url: str
    classification: str = Field(..., description="'safe', 'suspicious', or 'malicious'")
    threat_score: float = Field(..., description="0-100 threat score, higher = riskier")
    model_used: str = Field(..., description="'random_forest' or 'rule_based_fallback'")
    reasons: List[str] = Field(default_factory=list)
    details: Optional[ScanDetails] = None
    scan_duration_seconds: Optional[float] = None


class HealthResponse(BaseModel):
    """Response body for GET / and GET /health"""
    status: str
    message: str