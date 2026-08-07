"""
url_analyzer.py
----------------
Extracts lexical/structural features directly from a URL string.
No network calls required — this is the fastest and cheapest signal
in the pipeline. Uses only the free `tldextract` library plus
Python's built-in re/urllib.
"""

import re
from urllib.parse import urlparse
import tldextract

# Common keywords seen in phishing URLs (brand impersonation, urgency, etc.)
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "signin", "webscr", "password", "suspend", "urgent",
    "click", "free", "bonus", "gift", "security", "alert", "limited",
}

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)


def analyze_url(url: str) -> dict:
    """
    Returns a dict of URL-based lexical features.
    Never raises — malformed URLs just produce mostly-empty/default features.
    """
    result = {
        "url_length": 0,
        "num_dots": 0,
        "num_hyphens": 0,
        "num_special_chars": 0,
        "num_subdomains": 0,
        "has_ip_address": False,
        "https_used": False,
        "suspicious_keyword_count": 0,
        "suspicious_keywords_found": [],
        "domain": None,
        "subdomain": None,
        "suffix": None,
        "error": None,
    }

    try:
        # Ensure scheme so urlparse works consistently
        normalized = url if "://" in url else f"http://{url}"
        parsed = urlparse(normalized)

        result["url_length"] = len(url)
        result["https_used"] = parsed.scheme == "https"

        # Dots, hyphens, special characters (in full URL)
        result["num_dots"] = url.count(".")
        result["num_hyphens"] = url.count("-")
        result["num_special_chars"] = len(re.findall(r"[^a-zA-Z0-9./:_-]", url))

        # Domain breakdown via tldextract (handles multi-part TLDs like .co.uk)
        ext = tldextract.extract(normalized)
        result["domain"] = ext.domain
        result["subdomain"] = ext.subdomain
        result["suffix"] = ext.suffix
        result["num_subdomains"] = len(ext.subdomain.split(".")) if ext.subdomain else 0

        # IP address instead of domain name (common phishing tactic)
        hostname = parsed.hostname or ""
        result["has_ip_address"] = bool(IP_PATTERN.match(hostname))

        # Suspicious keyword scan (case-insensitive, on full URL)
        url_lower = url.lower()
        found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        result["suspicious_keyword_count"] = len(found)
        result["suspicious_keywords_found"] = found

    except Exception as e:
        result["error"] = f"unexpected_error: {e}"

    return result


if __name__ == "__main__":
    import json
    tests = [
        "https://google.com",
        "https://google-login-security-update123.com/verify",
        "http://192.168.1.1/account/confirm",
    ]
    for t in tests:
        print(t)
        print(json.dumps(analyze_url(t), indent=2))
        print("-" * 40)