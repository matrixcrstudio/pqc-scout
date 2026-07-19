"""Live TLS certificate scanner.

Passive by design: a standard TLS handshake against a host you name — no
probing, no enumeration, no protocol downgrade attempts. Suitable for
scanning infrastructure you operate or are authorized to assess.
"""

from __future__ import annotations

import logging
import socket
import ssl
from typing import Any, Dict, List

from .horizon import exposure_tier, qday_nominal

_log = logging.getLogger("pqc_scout.tls")

#: Cipher-suite substrings that indicate a post-quantum KEM was negotiated.
_PQC_INDICATORS = ("KYBER", "MLKEM", "ML_KEM", "ML-KEM", "X25519MLKEM")


def scan_tls_cert(domain: str, port: int = 443, timeout: float = 10.0) -> Dict[str, Any]:
    """Handshake with ``domain:port`` and classify its key-exchange exposure.

    Returns a dict with the certificate subject/issuer/expiry, negotiated
    cipher suite and protocol, the inferred quantum-vulnerable algorithm
    family, and its exposure tier. On failure, ``error`` is set and the
    remaining fields are absent — a failed scan is never silently scored.
    """
    result: Dict[str, Any] = {"domain": domain, "port": port, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()  # (name, protocol, bits)

                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                result["subject"] = subject.get("commonName", "")
                result["issuer"] = issuer.get("organizationName", issuer.get("commonName", ""))
                result["not_after"] = cert.get("notAfter", "")
                result["serial"] = cert.get("serialNumber", "")
                result["cipher_suite"] = cipher[0] if cipher else ""
                result["protocol"] = cipher[1] if cipher else ""
                result["cipher_bits"] = cipher[2] if cipher else 0

                cs = (cipher[0] or "").upper() if cipher else ""
                proto = (cipher[1] or "").upper() if cipher else ""

                # TLS 1.3 cipher suites (TLS_AES_*) don't name the key
                # exchange — it is X25519/ECDHE unless a PQC KEM was
                # negotiated, so the classical default is what gets scored.
                if "TLSV1.3" in proto or cs.startswith("TLS_"):
                    result["algorithm"] = "ECDH-P256"
                    result["key_exchange"] = "X25519 or ECDHE-P256 (TLS 1.3 default)"
                    result["bulk_cipher"] = cs
                    result["key_size"] = 256
                elif "ECDSA" in cs or "ECDHE" in cs:
                    result["algorithm"] = "ECDSA-P256"
                    result["key_size"] = 256
                elif "RSA" in cs:
                    result["algorithm"] = "RSA-2048"
                    result["key_size"] = 2048
                elif "CHACHA" in cs:
                    result["algorithm"] = "ChaCha20-Poly1305"
                    result["key_size"] = 256
                else:
                    result["algorithm"] = cs or "UNKNOWN"
                    result["key_size"] = cipher[2] if cipher else 0

                result["pqc_detected"] = any(pq in cs for pq in _PQC_INDICATORS)
                result["exposure_tier"] = exposure_tier(result["algorithm"], 10)
                result["qday_horizon"] = qday_nominal(result["algorithm"])

    except Exception as e:  # noqa: BLE001 — surface every failure mode to the caller
        result["error"] = str(e)
        _log.warning("TLS scan failed for %s:%s — %s", domain, port, e)

    return result


def scan_tls_multi(domains: List[str]) -> List[Dict[str, Any]]:
    """Scan several domains; returns one result dict per domain."""
    results = []
    for domain in domains:
        r = scan_tls_cert(domain)
        results.append(r)
        _log.info(
            "%s -> %s | %s | tier=%s",
            domain, r.get("algorithm", "ERR"),
            r.get("cipher_suite", ""), r.get("exposure_tier", "?"),
        )
    return results
