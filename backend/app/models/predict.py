"""
predict.py
----------
Loads the trained Random Forest model (.pkl) and runs prediction on a
single URL. Produces a threat score, classification (Safe/Suspicious/
Malicious), and a human-readable list of reasons — the "Explainable AI"
piece described in the README.

If no trained model exists yet (models/threat_model.pkl missing),
falls back to a simple rule-based scorer so the API still works
end-to-end before you've trained anything.
"""

import os
import sys
import joblib
import numpy as np

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from feature_pipeline import extract_features, features_to_vector, FEATURE_NAMES  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # backend/
PROJECT_ROOT = os.path.dirname(BASE_DIR)
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "threat_model.pkl")

REVERSE_LABEL_MAP = {0: "safe", 1: "suspicious", 2: "malicious"}

# Threshold bands used only by the rule-based fallback (matches README table)
SCORE_BANDS = [(30, "safe"), (65, "suspicious"), (100, "malicious")]

_model_cache = {"model": None, "feature_names": None, "loaded": False}


def _load_model():
    """Loads the .pkl model once and caches it in memory (free — no DB needed)."""
    if _model_cache["loaded"]:
        return _model_cache["model"], _model_cache["feature_names"]

    if os.path.exists(MODEL_PATH):
        bundle = joblib.load(MODEL_PATH)
        _model_cache["model"] = bundle["model"]
        _model_cache["feature_names"] = bundle["feature_names"]
    else:
        _model_cache["model"] = None
        _model_cache["feature_names"] = FEATURE_NAMES

    _model_cache["loaded"] = True
    return _model_cache["model"], _model_cache["feature_names"]


def _rule_based_score(features: dict) -> float:
    """
    Simple weighted fallback used only when no trained model exists yet.
    Lets the API return real results before File 12/13 (dataset + training)
    are done. Replaced entirely once threat_model.pkl is trained.
    """
    score = 0
    if not features.get("ssl_available"):
        score += 25
    if features.get("self_signed"):
        score += 20
    if not features.get("issuer_trusted"):
        score += 10
    if features.get("tls_version_weak"):
        score += 10
    if features.get("signature_algorithm_weak"):
        score += 5
    if features.get("has_ip_address"):
        score += 15
    if features.get("suspicious_keyword_count", 0) > 0:
        score += min(15, features["suspicious_keyword_count"] * 5)
    if features.get("is_new_domain"):
        score += 15
    score += min(10, features.get("missing_header_count", 0) * 2)
    if not features.get("dns_resolves"):
        score += 10
    return min(100, score)


def _score_to_label(score: float) -> str:
    for upper_bound, label in SCORE_BANDS:
        if score <= upper_bound:
            return label
    return "malicious"


def _generate_reasons(raw: dict, features: dict) -> list:
    """Builds the human-readable explanation list shown in the README example."""
    reasons = []

    ssl_data = raw.get("ssl", {})
    whois_data = raw.get("whois", {})
    header_data = raw.get("headers", {})
    url_data = raw.get("url", {})
    dns_data = raw.get("dns", {})

    if not ssl_data.get("ssl_available"):
        reasons.append("No valid SSL/TLS certificate found")
    if ssl_data.get("self_signed"):
        reasons.append("Self-signed SSL certificate")
    if ssl_data.get("tls_version_weak"):
        reasons.append(f"Weak TLS version ({ssl_data.get('tls_version')})")
    if ssl_data.get("signature_algorithm_weak"):
        reasons.append(f"Weak signature algorithm ({ssl_data.get('signature_algorithm')})")
    if ssl_data.get("days_until_expiry") is not None and ssl_data["days_until_expiry"] < 0:
        reasons.append("SSL certificate has expired")

    if whois_data.get("is_new_domain"):
        age = whois_data.get("domain_age_days")
        reasons.append(f"Domain created {age} days ago" if age is not None else "Recently registered domain")

    if header_data.get("missing_count", 0) > 0:
        missing = header_data.get("headers_missing", [])
        if "Strict-Transport-Security" in missing:
            reasons.append("Missing HSTS header")
        if "Content-Security-Policy" in missing:
            reasons.append("Missing Content-Security-Policy header")
        if header_data.get("missing_count", 0) >= 4:
            reasons.append(f"{header_data['missing_count']} security headers missing")

    if url_data.get("has_ip_address"):
        reasons.append("URL uses an IP address instead of a domain name")
    if url_data.get("suspicious_keyword_count", 0) > 0:
        kws = ", ".join(url_data.get("suspicious_keywords_found", []))
        reasons.append(f"URL contains suspicious keywords ({kws})")

    if not dns_data.get("dns_resolves"):
        reasons.append("Domain does not resolve via DNS")

    if not reasons:
        reasons.append("No major security issues detected")

    return reasons


def predict_url(url: str) -> dict:
    """
    Full end-to-end prediction: extract features -> score -> classify -> explain.
    Works whether or not a trained model exists yet.
    """
    extraction = extract_features(url)
    raw = extraction["raw"]
    features = extraction["features"]

    model, feature_names = _load_model()

    if model is not None:
        vector = np.array([features_to_vector(features)])
        pred_class = int(model.predict(vector)[0])
        proba = model.predict_proba(vector)[0]
        # Threat score = probability mass on suspicious + malicious classes
        threat_score = round(float(proba[1] + proba[2]) * 100, 1) if len(proba) >= 3 else round(float(proba[pred_class]) * 100, 1)
        classification = REVERSE_LABEL_MAP.get(pred_class, "suspicious")
        model_used = "random_forest"
    else:
        threat_score = round(_rule_based_score(features), 1)
        classification = _score_to_label(threat_score)
        model_used = "rule_based_fallback"

    reasons = _generate_reasons(raw, features)

    return {
        "url": url,
        "classification": classification,
        "threat_score": threat_score,
        "model_used": model_used,
        "reasons": reasons,
        "details": {
            "ssl": raw.get("ssl"),
            "domain_age_days": raw.get("whois", {}).get("domain_age_days"),
            "tls_version": raw.get("ssl", {}).get("tls_version"),
            "security_headers_present": raw.get("headers", {}).get("headers_present"),
            "security_headers_missing": raw.get("headers", {}).get("headers_missing"),
        },
    }


if __name__ == "__main__":
    import json
    for site in ["https://google.com", "http://192.168.1.1/account/verify"]:
        print(json.dumps(predict_url(site), indent=2, default=str))
        print("-" * 40)