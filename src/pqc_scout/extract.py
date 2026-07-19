"""Cryptographic-surface extraction from a free-text stack description.

Two extraction paths, deliberately NOT interchangeable:

* DETERMINISTIC (default): a regex extractor that recognizes standard
  algorithm literals. It only reports what it can literally match — a
  limited result is logged as such and never dressed up as exhaustive.
* LLM (opt-in, requires the ``llm`` extra and an ``ANTHROPIC_API_KEY``):
  model-driven extraction that FAILS LOUD. A truncated or invalid response
  raises ``ExtractionError`` instead of silently degrading to the regex
  baseline — a degenerate report that reads like a real assessment is worse
  than a loud failure.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import List, Optional

from .horizon import (
    apply_sector_floor,
    exposure_tier,
    migration_target,
    priority_score,
    qday_nominal,
)
from .models import CryptographicSurface

_log = logging.getLogger("pqc_scout.extract")

DEFAULT_LLM_MODEL = os.getenv("PQC_SCOUT_MODEL", "claude-sonnet-4-5")


class ExtractionError(RuntimeError):
    """LLM surface extraction failed (truncation / invalid JSON / empty result)."""


def _build_surface(
    category: str, algo: str, location: str, retention_yrs: int, sector: Optional[str]
) -> CryptographicSurface:
    retention = apply_sector_floor(retention_yrs, sector)
    tier = exposure_tier(algo, retention)
    horizon = qday_nominal(algo)
    return CryptographicSurface(
        category=category,
        algorithm=algo,
        location=location,
        data_retention_yrs=retention,
        exposure_tier=tier,
        qday_horizon_yrs=horizon,
        migration_target=migration_target(algo),
        priority_score=priority_score(tier, retention, horizon),
    )


# ── Deterministic extractor ──────────────────────────────────────────────────

_PATTERNS = {
    r"\bRSA[-\s]?2048\b":         ("KEY_EXCHANGE", "RSA-2048", 10),
    r"\bRSA[-\s]?4096\b":         ("PKI_HIERARCHY", "RSA-4096", 15),
    r"\bECDSA[-\s]?P[-]?256\b":   ("CODE_SIGNING", "ECDSA-P256", 10),
    r"\bECDSA[-\s]?P[-]?384\b":   ("CODE_SIGNING", "ECDSA-P384", 12),
    r"\bECDH[-\s]?P[-]?256\b":    ("KEY_EXCHANGE", "ECDH-P256", 10),
    r"\bDH[-\s]?2048\b":          ("VPN_TUNNELS", "DH-2048", 10),
    r"\bAES[-\s]?128\b":          ("STORAGE_ENCRYPTION", "AES-128", 10),
    r"\bTLS\s*1\.[23]\b":         ("TLS_CERTIFICATES", "ECDH-P256", 10),
    r"\bEd25519\b":               ("CODE_SIGNING", "ECDSA-P256", 10),
    r"\bX25519\b":                ("KEY_EXCHANGE", "ECDH-P256", 10),
    r"\bsecp256k1\b":             ("KEY_EXCHANGE", "ECDSA-P256", 10),
}


def extract_deterministic(
    stack_description: str, sector: Optional[str] = None
) -> List[CryptographicSurface]:
    """Regex extraction of standard algorithm literals.

    Non-standard primitives are MISSED, not inferred. When nothing at all is
    detected, a minimum classical baseline (TLS + code signing) is assumed —
    an internet-connected stack without either is vanishingly rare, and
    assuming zero crypto would under-report exposure.
    """
    surfaces: List[CryptographicSurface] = []
    for pattern, (cat, algo, ret) in _PATTERNS.items():
        if re.search(pattern, stack_description, re.IGNORECASE):
            surfaces.append(_build_surface(cat, algo, "detected in stack", ret, sector))
    if not surfaces:
        _log.info("no algorithm literals detected — assuming classical TLS + code-signing baseline")
        surfaces = [
            _build_surface("TLS_CERTIFICATES", "ECDSA-P256", "web infrastructure", 10, sector),
            _build_surface("CODE_SIGNING", "RSA-2048", "release pipeline", 10, sector),
        ]
    return surfaces


# ── LLM extractor (opt-in) ───────────────────────────────────────────────────

_LLM_SYSTEM = (
    "You are a post-quantum cryptography migration specialist. "
    "Given a technology stack description, extract all cryptographic surfaces "
    "that could be affected by quantum computing (Shor's algorithm attacks on "
    "asymmetric crypto, Grover's algorithm attacks on symmetric). "
    "Return ONLY valid, COMPLETE JSON — an array of objects. Each object has fields: "
    "category (e.g. TLS_CERTIFICATES, CODE_SIGNING, STORAGE_ENCRYPTION, KEY_EXCHANGE, "
    "ZK_PROVING, CONSENSUS_SIGNING, TX_SIGNATURES, PKI_HIERARCHY, HARDWARE_KEYS), "
    "algorithm (normalise to the nearest classical hardness family — e.g. ECDSA-P256 "
    "for ANY ~256-bit elliptic-curve primitive incl. Ed25519 / BLS12-381 / pairing "
    "curves; RSA-2048; AES-256), "
    "location (service or system name from the description), "
    "data_retention_yrs (integer: estimated years this data must remain confidential). "
    "Be exhaustive but keep the JSON compact so it is never truncated. If the algorithm "
    "isn't mentioned, infer the most common default. No markdown, no prose — just the JSON array."
)

_MAX_ATTEMPTS = 2


def extract_llm(
    target: str,
    stack_description: str,
    sector: Optional[str] = None,
    model: str = DEFAULT_LLM_MODEL,
    _attempt: int = 1,
) -> List[CryptographicSurface]:
    """LLM-backed extraction that fails loud.

    Raises ``ExtractionError`` on missing dependency/key, API error,
    truncation, invalid JSON, or an empty result. Retries once with a larger
    token budget before giving up.
    """
    try:
        import anthropic
    except ImportError as e:
        raise ExtractionError(
            "LLM extraction requires the 'llm' extra: pip install pqc-scout[llm]"
        ) from e

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ExtractionError("LLM extraction requires ANTHROPIC_API_KEY to be set")

    client = anthropic.Anthropic(api_key=api_key)
    max_tokens = 4096 * _attempt  # 4096 -> 8192

    user = (
        f"Target: {target}\n\n"
        f"Technology Stack:\n{stack_description}\n\n"
        "Extract all cryptographic surfaces as a single compact JSON array."
    )

    def _retry(reason: str) -> List[CryptographicSurface]:
        _log.warning("LLM extraction %s; retry %d/%d", reason, _attempt + 1, _MAX_ATTEMPTS)
        return extract_llm(target, stack_description, sector, model, _attempt + 1)

    try:
        resp = client.messages.create(
            model=model, max_tokens=max_tokens,
            system=_LLM_SYSTEM, messages=[{"role": "user", "content": user}],
        )
    except Exception as e:
        if _attempt < _MAX_ATTEMPTS:
            return _retry(f"API error ({e})")
        raise ExtractionError(f"extraction API call failed after {_attempt} attempts: {e}") from e

    raw = resp.content[0].text.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    if getattr(resp, "stop_reason", None) == "max_tokens":
        if _attempt < _MAX_ATTEMPTS:
            return _retry(f"hit max_tokens ({max_tokens})")
        raise ExtractionError(
            f"extraction truncated at max_tokens ({max_tokens}) after {_attempt} attempts; "
            f"stack too large for one response — split it or use deterministic extraction."
        )

    try:
        items = json.loads(raw)
    except Exception as parse_err:
        if _attempt < _MAX_ATTEMPTS:
            return _retry(f"JSON parse failed ({parse_err})")
        preview = raw[:240].replace("\n", " ")
        raise ExtractionError(
            f"extraction returned invalid JSON after {_attempt} attempts "
            f"({parse_err}); raw[:240]={preview!r}"
        ) from parse_err

    if not isinstance(items, list) or not items:
        raise ExtractionError(
            f"extraction produced no surfaces (got {type(items).__name__}); "
            f"refusing to emit an empty/degenerate report."
        )

    surfaces = [
        _build_surface(
            item.get("category", "TLS_CERTIFICATES"),
            item.get("algorithm", "RSA-2048"),
            item.get("location", "unknown"),
            int(item.get("data_retention_yrs", 10)),
            sector,
        )
        for item in items
    ]
    _log.info("extracted %d surfaces for %s", len(surfaces), target)
    return surfaces
