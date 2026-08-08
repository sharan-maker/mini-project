"""
dns_analyzer.py
----------------
Resolves basic DNS records for a domain (A, MX, NS, TXT).
Uses the free `dnspython` library — queries public DNS resolvers
directly, no API key, no paid service.

FIX NOTE: dns_resolves is now determined primarily by Python's built-in
OS-level resolver (socket.getaddrinfo) — the same mechanism `requests`
and `whois` already use successfully elsewhere in this pipeline. Some
networks/VPNs/antivirus setups block dnspython's raw UDP queries to
arbitrary nameservers even when normal DNS lookups work fine, which
was previously causing false "does not resolve" results (e.g. for
github.com). MX/NS/TXT/SPF/DMARC still come from dnspython as bonus
data and can fail independently without affecting dns_resolves.
"""

import socket
import dns.resolver
import tldextract

RESOLVE_TIMEOUT = 3.0
RECORD_TYPES = ["A", "MX", "NS", "TXT"]

# Public fallback nameservers — used only if the system's configured
# resolver doesn't respond via dnspython. Free, no API key.
FALLBACK_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]


def _resolves_via_os(domain: str) -> list:
    """
    Reliable primary check using Python's built-in OS-level resolver
    (same mechanism `requests` and `whois` use). Works even on
    networks/VPNs/antivirus setups that block dnspython's raw UDP
    queries to arbitrary nameservers.
    """
    try:
        infos = socket.getaddrinfo(domain, None)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def _build_resolver(nameservers=None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = RESOLVE_TIMEOUT
    resolver.lifetime = RESOLVE_TIMEOUT
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


def analyze_dns(url_or_hostname: str) -> dict:
    """
    Returns basic DNS features for the given domain.
    Never raises — genuinely unresolvable domains return dns_resolves: False.
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

        # --- Primary, reliable check via OS resolver ---
        ips = _resolves_via_os(domain)
        if ips:
            result["dns_resolves"] = True
            result["a_records"] = ips
            result["num_a_records"] = len(ips)

        # --- dnspython for the same A record, only if OS check found nothing ---
        if not result["dns_resolves"]:
            for nameservers in (None, FALLBACK_NAMESERVERS):
                try:
                    resolver = _build_resolver(nameservers)
                    answers = resolver.resolve(domain, "A")
                    result["a_records"] = [str(r) for r in answers]
                    result["num_a_records"] = len(result["a_records"])
                    result["dns_resolves"] = True
                    break
                except Exception:
                    continue

        # --- Bonus records (best-effort, don't affect dns_resolves) ---
        resolver = _build_resolver()

        try:
            answers = resolver.resolve(domain, "MX")
            result["mx_records"] = [str(r.exchange).rstrip(".") for r in answers]
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, "NS")
            result["ns_records"] = [str(r).rstrip(".") for r in answers]
            result["num_ns_records"] = len(result["ns_records"])
        except Exception:
            pass

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
    for site in ["google.com", "github.com", "wikipedia.org"]:
        print(site)
        print(json.dumps(analyze_dns(site), indent=2))
        print("-" * 40)