"""
dns_analyzer.py
----------------
Resolves basic DNS records for a domain (A, MX, NS, TXT).
Uses the free `dnspython` library — queries public DNS resolvers
directly, no API key, no paid service.
"""

import dns.resolver
import tldextract

RESOLVE_TIMEOUT = 4.0
RECORD_TYPES = ["A", "MX", "NS", "TXT"]


def analyze_dns(url_or_hostname: str) -> dict:
    """
    Returns basic DNS features for the given domain.
    Never raises — unresolvable domains return dns_resolves: False.
    """
    result = {
        "dns_resolves": False,
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "has_spf_record": False,
        "has_dmarc_record": False,
        "num_a_records": 0,
        "num_ns_records": 0,
        "error": None,
    }

    try:
        ext = tldextract.extract(url_or_hostname)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

        resolver = dns.resolver.Resolver()
        resolver.timeout = RESOLVE_TIMEOUT
        resolver.lifetime = RESOLVE_TIMEOUT

        # A records (IP resolution) — if this fails, domain effectively doesn't resolve
        try:
            answers = resolver.resolve(domain, "A")
            result["a_records"] = [str(r) for r in answers]
            result["num_a_records"] = len(result["a_records"])
            result["dns_resolves"] = True
        except Exception:
            pass

        # MX records (mail servers)
        try:
            answers = resolver.resolve(domain, "MX")
            result["mx_records"] = [str(r.exchange).rstrip(".") for r in answers]
        except Exception:
            pass

        # NS records (name servers)
        try:
            answers = resolver.resolve(domain, "NS")
            result["ns_records"] = [str(r).rstrip(".") for r in answers]
            result["num_ns_records"] = len(result["ns_records"])
        except Exception:
            pass

        # TXT records — check for SPF / DMARC presence (email security signals)
        try:
            answers = resolver.resolve(domain, "TXT")
            txt_values = [b"".join(r.strings).decode(errors="ignore") for r in answers]
            result["has_spf_record"] = any(v.startswith("v=spf1") for v in txt_values)
        except Exception:
            pass

        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_values = [b"".join(r.strings).decode(errors="ignore") for r in dmarc_answers]
            result["has_dmarc_record"] = any(v.startswith("v=DMARC1") for v in dmarc_values)
        except Exception:
            pass

        if not result["dns_resolves"]:
            result["error"] = "domain_did_not_resolve"

    except Exception as e:
        result["error"] = f"unexpected_error: {e}"

    return result


if __name__ == "__main__":
    import json
    for site in ["google.com", "wikipedia.org"]:
        print(site)
        print(json.dumps(analyze_dns(site), indent=2))
        print("-" * 40)