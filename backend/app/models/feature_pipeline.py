"""
feature_pipeline.py
--------------------
Runs all 5 analyzers (SSL, URL, Headers, WHOIS, DNS) on a given URL
and converts their combined output into a single numeric feature
dict/vector suitable for the Random Forest model.

This is the glue layer between raw analysis and the ML model.
"""

import sys
import os

# Allow running this file directly for testing (adjusts import path)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.ssl_analyzer import analyze_ssl
from analyzers.url_analyzer import analyze_url
from analyzers.header_analyzer import analyze_headers
from analyzers.whois_analyzer import analyze_whois
from analyzers.dns_analyzer import analyze_dns

# Ordered list of feature names — this order MUST match training data
# columns exactly. Keep this list in sync with train_model.py.
FEATURE_NAMES = [
    "ssl_available",
    "self_signed",
    "issuer_trusted",
    "tls_version_weak",
    "signature_algorithm_weak",
    "cert_age_days",
    "days_until_expiry",
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_special_chars",
    "num_subdomains",
    "has_ip_address",
    "https_used",
    "suspicious_keyword_count",
    "missing_header_count",
    "domain_age_days",
    "is_new_domain",
    "days_until_domain_expiry",
    "dns_resolves",
    "has_spf_record",
    "has_dmarc_record",
    "num_ns_records",
]


def _bool_to_int(value) -> int:
    """Converts True/False/None to 1/0/0 for ML input."""
    if value is True:
        return 1
    return 0


def _safe_num(value, default: int = 0) -> float:
    """Converts None/missing numeric values to a safe default."""
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def extract_features(url: str) -> dict:
    """
    Runs every analyzer on the given URL and returns:
    {
        "raw": { ...full analyzer outputs, useful for explanations... },
        "features": { ...flat numeric dict matching FEATURE_NAMES... }
    }
    """
    ssl_data = analyze_ssl(url.replace("https://", "").replace("http://", "").split("/")[0])
    url_data = analyze_url(url)
    header_data = analyze_headers(url)
    whois_data = analyze_whois(url)
    dns_data = analyze_dns(url)

    features = {
        "ssl_available": _bool_to_int(ssl_data.get("ssl_available")),
        "self_signed": _bool_to_int(ssl_data.get("self_signed")),
        "issuer_trusted": _bool_to_int(ssl_data.get("issuer_trusted")),
        "tls_version_weak": _bool_to_int(ssl_data.get("tls_version_weak")),
        "signature_algorithm_weak": _bool_to_int(ssl_data.get("signature_algorithm_weak")),
        "cert_age_days": _safe_num(ssl_data.get("cert_age_days"), default=0),
        "days_until_expiry": _safe_num(ssl_data.get("days_until_expiry"), default=0),

        "url_length": _safe_num(url_data.get("url_length")),
        "num_dots": _safe_num(url_data.get("num_dots")),
        "num_hyphens": _safe_num(url_data.get("num_hyphens")),
        "num_special_chars": _safe_num(url_data.get("num_special_chars")),
        "num_subdomains": _safe_num(url_data.get("num_subdomains")),
        "has_ip_address": _bool_to_int(url_data.get("has_ip_address")),
        "https_used": _bool_to_int(url_data.get("https_used")),
        "suspicious_keyword_count": _safe_num(url_data.get("suspicious_keyword_count")),

        "missing_header_count": _safe_num(header_data.get("missing_count"), default=6),

        "domain_age_days": _safe_num(whois_data.get("domain_age_days"), default=0),
        "is_new_domain": _bool_to_int(whois_data.get("is_new_domain")),
        "days_until_domain_expiry": _safe_num(whois_data.get("days_until_domain_expiry"), default=0),

        "dns_resolves": _bool_to_int(dns_data.get("dns_resolves")),
        "has_spf_record": _bool_to_int(dns_data.get("has_spf_record")),
        "has_dmarc_record": _bool_to_int(dns_data.get("has_dmarc_record")),
        "num_ns_records": _safe_num(dns_data.get("num_ns_records")),
    }

    return {
        "raw": {
            "ssl": ssl_data,
            "url": url_data,
            "headers": header_data,
            "whois": whois_data,
            "dns": dns_data,
        },
        "features": features,
    }


def features_to_vector(features: dict) -> list:
    """Converts the feature dict into an ordered list matching FEATURE_NAMES,
    ready to feed into scikit-learn."""
    return [features.get(name, 0) for name in FEATURE_NAMES]


if __name__ == "__main__":
    import json
    result = extract_features("https://google.com")
    print("FEATURES:")
    print(json.dumps(result["features"], indent=2))
    print("\nVECTOR (order matches FEATURE_NAMES):")
    print(features_to_vector(result["features"]))