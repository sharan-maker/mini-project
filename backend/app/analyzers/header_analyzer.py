"""
header_analyzer.py
-------------------
Checks presence/absence of important HTTP security headers.
Uses only the free `requests` library — no paid API required.
"""

import requests

# Headers we check for, and why each matters (used in explanations later)
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces browsers to use HTTPS (prevents downgrade attacks).",
    "Content-Security-Policy": "Restricts which resources (scripts/styles) can load, mitigates XSS.",
    "X-Frame-Options": "Prevents clickjacking by blocking the site from being framed.",
    "X-Content-Type-Options": "Stops browsers from MIME-sniffing responses.",
    "Referrer-Policy": "Controls how much referrer info is leaked to other sites.",
    "Permissions-Policy": "Restricts access to browser features (camera, mic, geolocation, etc.).",
}

REQUEST_TIMEOUT = 6.0


def analyze_headers(url: str) -> dict:
    """
    Fetches the URL (HEAD first, falls back to GET) and checks which
    security headers are present. Never raises — on failure returns
    reachable: False and all headers marked missing.
    """
    if "://" not in url:
        url = f"https://{url}"

    result = {
        "reachable": False,
        "status_code": None,
        "headers_present": {},
        "headers_missing": [],
        "missing_count": 0,
        "error": None,
    }

    try:
        try:
            resp = requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            # Some servers don't support HEAD properly (405/empty headers) — fall back to GET
            if resp.status_code >= 400 or not resp.headers:
                resp = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except requests.exceptions.RequestException:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)

        result["reachable"] = True
        result["status_code"] = resp.status_code

        missing = []
        for header, description in SECURITY_HEADERS.items():
            if header in resp.headers:
                result["headers_present"][header] = resp.headers[header]
            else:
                missing.append(header)

        result["headers_missing"] = missing
        result["missing_count"] = len(missing)

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        result["headers_missing"] = list(SECURITY_HEADERS.keys())
        result["missing_count"] = len(SECURITY_HEADERS)
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"connection_error: {e}"
        result["headers_missing"] = list(SECURITY_HEADERS.keys())
        result["missing_count"] = len(SECURITY_HEADERS)
    except Exception as e:
        result["error"] = f"unexpected_error: {e}"
        result["headers_missing"] = list(SECURITY_HEADERS.keys())
        result["missing_count"] = len(SECURITY_HEADERS)

    return result


if __name__ == "__main__":
    import json
    for site in ["https://google.com", "https://example.com"]:
        print(site)
        print(json.dumps(analyze_headers(site), indent=2))
        print("-" * 40)