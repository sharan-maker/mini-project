"""
whois_analyzer.py
------------------
Extracts domain registration info (age, registrar, expiry, country)
using the free `python-whois` library. No API key, no paid service —
queries public WHOIS servers directly.
"""

from datetime import datetime, timezone
import whois
import tldextract

# Domains newer than this are treated as a strong risk signal
NEW_DOMAIN_THRESHOLD_DAYS = 90


def _first_if_list(value):
    """WHOIS libraries sometimes return a list of dates/names instead of one."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _ensure_utc(dt):
    """Normalize naive datetimes to UTC so subtraction always works."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def analyze_whois(url_or_hostname: str) -> dict:
    """
    Returns WHOIS-derived domain features.
    Never raises — on lookup failure (rate-limited registrar, privacy-
    protected domain, etc.) returns whois_available: False with defaults.
    """
    result = {
        "whois_available": False,
        "domain_age_days": None,
        "is_new_domain": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "days_until_domain_expiry": None,
        "country": None,
        "error": None,
    }

    try:
        ext = tldextract.extract(url_or_hostname)
        registrable_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

        w = whois.whois(registrable_domain)

        creation_date = _ensure_utc(_first_if_list(w.creation_date))
        expiration_date = _ensure_utc(_first_if_list(w.expiration_date))
        now = datetime.now(timezone.utc)

        if creation_date:
            result["whois_available"] = True
            result["creation_date"] = creation_date.isoformat()
            age_days = (now - creation_date).days
            result["domain_age_days"] = age_days
            result["is_new_domain"] = age_days < NEW_DOMAIN_THRESHOLD_DAYS

        if expiration_date:
            result["expiration_date"] = expiration_date.isoformat()
            result["days_until_domain_expiry"] = (expiration_date - now).days

        registrar = _first_if_list(w.registrar)
        result["registrar"] = registrar

        country = getattr(w, "country", None)
        result["country"] = _first_if_list(country)

        if not creation_date and not registrar:
            # whois returned essentially nothing useful
            result["error"] = "no_whois_data_found"

    except Exception as e:
        result["error"] = f"whois_lookup_failed: {e}"

    return result


if __name__ == "__main__":
    import json
    for site in ["google.com", "wikipedia.org"]:
        print(site)
        print(json.dumps(analyze_whois(site), indent=2))
        print("-" * 40)