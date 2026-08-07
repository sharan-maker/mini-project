"""
ssl_analyzer.py
----------------
Extracts SSL/TLS certificate features for a given hostname.
Uses only Python's built-in ssl/socket modules + the free `cryptography`
library. No paid API, no external service required.
"""

import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# Trusted / well-known CAs — used as a simple heuristic signal.
# (In production you'd validate against the system trust store instead.)
KNOWN_TRUSTED_ISSUERS = {
    "DigiCert", "Google Trust Services", "Let's Encrypt",
    "Cloudflare", "Sectigo", "GlobalSign", "GoDaddy", "Amazon",
}

WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
WEAK_SIGNATURE_ALGOS = {"sha1", "md5"}


def _get_certificate_der(hostname: str, port: int = 443, timeout: float = 5.0):
    """Open a TLS connection and return (der_bytes, negotiated_tls_version, cipher_tuple)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we inspect manually; not trusting blindly

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            tls_version = ssock.version()
            cipher = ssock.cipher()  # (name, protocol, secret_bits)
            return der_cert, tls_version, cipher


def analyze_ssl(hostname: str) -> dict:
    """
    Returns a dict of SSL/TLS features for the given hostname.
    On any failure (no SSL, connection error, timeout) returns
    ssl_available: False and safe defaults so the pipeline doesn't break.
    """
    result = {
        "ssl_available": False,
        "issuer": None,
        "issuer_trusted": False,
        "self_signed": False,
        "issued_date": None,
        "expiry_date": None,
        "cert_age_days": None,
        "days_until_expiry": None,
        "tls_version": None,
        "tls_version_weak": None,
        "signature_algorithm": None,
        "signature_algorithm_weak": None,
        "cipher_suite": None,
        "error": None,
    }

    try:
        der_cert, tls_version, cipher = _get_certificate_der(hostname)
        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        result["ssl_available"] = True
        result["tls_version"] = tls_version
        result["tls_version_weak"] = tls_version in WEAK_TLS_VERSIONS
        result["cipher_suite"] = cipher[0] if cipher else None

        # Issuer
        try:
            issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            issuer_name = issuer_org[0].value if issuer_org else str(cert.issuer)
        except Exception:
            issuer_name = str(cert.issuer)
        result["issuer"] = issuer_name
        result["issuer_trusted"] = any(k.lower() in issuer_name.lower() for k in KNOWN_TRUSTED_ISSUERS)

        # Self-signed check: issuer == subject
        result["self_signed"] = cert.issuer == cert.subject

        # Validity dates
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)

        result["issued_date"] = not_before.isoformat()
        result["expiry_date"] = not_after.isoformat()
        result["cert_age_days"] = (now - not_before).days
        result["days_until_expiry"] = (not_after - now).days

        # Signature algorithm
        sig_algo = cert.signature_algorithm_oid._name  # e.g. 'sha256WithRSAEncryption'
        result["signature_algorithm"] = sig_algo
        result["signature_algorithm_weak"] = any(w in sig_algo.lower() for w in WEAK_SIGNATURE_ALGOS)

    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        result["error"] = f"connection_error: {e}"
    except ssl.SSLError as e:
        result["error"] = f"ssl_error: {e}"
    except Exception as e:
        result["error"] = f"unexpected_error: {e}"

    return result


if __name__ == "__main__":
    # quick manual test
    import json
    print(json.dumps(analyze_ssl("google.com"), indent=2))