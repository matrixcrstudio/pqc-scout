"""Q-Day horizon model, exposure tiering, and sector data-retention priors.

The model answers one question per cryptographic surface: given how long the
data behind it must remain confidential, is the surface already inside the
harvest-now-decrypt-later (HNDL) window?

Sources for the horizon bands (years until a cryptanalytically relevant
quantum computer credibly breaks the primitive):

* NIST IR 8547 §3.1 (migration guidance) and Mosca's theorem.
* NSA/CISA CNSA 2.0 milestone timeline for critical infrastructure.
* Gidney & Ekerå 2019 (arXiv:1905.09749): RSA-2048 in ~8h on ~20M noisy
  qubits — the long-standing resource baseline.
* Gidney 2025 (arXiv:2505.15917): RSA-2048 under <1M noisy qubits (~1 week),
  a ~20x hardware-barrier reduction supporting the ~2030-2035 CRQC consensus.
* Cain, Bluvstein, Preskill et al. 2026 (arXiv:2603.28627): EC discrete-log
  on P-256 in days on ~26k physical neutral-atom qubits via high-rate qLDPC
  codes; RSA-2048 remains 1-2 orders of magnitude harder. Consequence:
  256-bit EC discrete-log breaks FIRST — EC horizons here are tighter than
  RSA/finite-field-DLP horizons, which track 2048/3072-bit hardness.

The optimistic (earliest-credible) compression applied for HNDL tiering
follows the Regev 2023 (arXiv:2308.06572) / Ragavan-Vaikuntanathan CRYPTO
2024 (arXiv:2310.00899) line, which shortens Shor-class horizons only.
Grover-bound symmetric/hash primitives are deliberately NOT compressed —
those algorithm families provide no equivalent speedup.
"""

from __future__ import annotations

from typing import Dict, Optional

#: Nominal years-to-break per algorithm family (see module docstring sources).
QDAY_HORIZON: Dict[str, int] = {
    "RSA-2048":          8,   # factoring — 1-2 orders harder than P-256 ECDLP
    "RSA-4096":          12,
    "ECDSA-P256":        5,   # EC discrete-log — first credible target (~2029)
    "ECDSA-P384":        7,
    "ECDH-P256":         5,
    "ECDH-P384":         7,
    "DH-2048":           8,   # finite-field DLP tracks 2048-bit hardness, not ECDLP
    "DH-3072":           10,
    "AES-128":           20,  # Grover halves effective key space -> 64-bit PQ security
    "AES-256":           30,  # 128-bit PQ security — acceptable long-term
    "SHA-256":           15,
    "SHA-384":           25,
    "SHA-512":           30,
    "SHA3-256":          25,
    "SHA3-512":          35,
    "CHACHA20-POLY1305": 20,
    "ML-KEM-768":        50,  # NIST FIPS 203 — already post-quantum
    "ML-DSA-65":         50,  # NIST FIPS 204 — already post-quantum
    "SLH-DSA-128F":      50,  # NIST FIPS 205 — already post-quantum
}

#: Default horizon for unrecognized algorithms — deliberately pessimistic.
DEFAULT_HORIZON_YRS: int = 8

#: Already-post-quantum schemes (never tiered above SAFE).
PQC_SAFE_ALGORITHMS = frozenset({"ML-KEM-768", "ML-DSA-65", "SLH-DSA-128F"})

# Earliest-credible compression for HNDL tiering. A security-policy margin
# choice motivated by the widened uncertainty band in the cited cryptanalysis
# literature — NOT an empirical prediction of a CRQC arrival date.
HNDL_OPTIMISTIC_FACTOR: float = 0.60

# Shor-class prefixes: asymmetric primitives whose horizons the
# Regev/Ragavan-Vaikuntanathan line compresses. Grover-bound primitives
# (AES/SHA/ChaCha) keep their nominal horizon on purpose.
_SHOR_CLASS_PREFIXES = ("RSA-", "ECDSA-", "ECDH-", "DH-")


def normalize_algorithm(algo: str) -> str:
    """Canonical uppercase-hyphenated key for an algorithm name."""
    return algo.upper().replace(" ", "-").replace("_", "-")


def qday_nominal(algo: str) -> int:
    """Nominal years-to-break for `algo` (pessimistic default if unknown)."""
    return QDAY_HORIZON.get(normalize_algorithm(algo), DEFAULT_HORIZON_YRS)


def qday_optimistic(algo: str) -> int:
    """Earliest-credible years-to-break, used for HNDL tiering.

    Shor-class horizons are compressed by ``HNDL_OPTIMISTIC_FACTOR``;
    Grover-bound and already-PQC schemes keep their nominal horizon.
    """
    key = normalize_algorithm(algo)
    nominal = QDAY_HORIZON.get(key, DEFAULT_HORIZON_YRS)
    if key.startswith(_SHOR_CLASS_PREFIXES):
        return max(1, round(nominal * HNDL_OPTIMISTIC_FACTOR))
    return nominal


def exposure_tier(algo: str, data_retention_years: int) -> str:
    """Tier a surface: CRITICAL | HIGH | MONITOR | SAFE.

    CRITICAL — earliest-credible horizon <= retention: HNDL is live; data
               harvested today is decryptable within its confidentiality
               window under the compressed resource line.
    HIGH     — nominal horizon <= retention + 3y migration buffer.
    MONITOR  — adequate margin for a planned migration.
    SAFE     — already a NIST-standardized post-quantum scheme.
    """
    key = normalize_algorithm(algo)
    if key in PQC_SAFE_ALGORITHMS:
        return "SAFE"
    if qday_optimistic(algo) <= data_retention_years:
        return "CRITICAL"
    if qday_nominal(algo) <= data_retention_years + 3:
        return "HIGH"
    return "MONITOR"


# ── Sector data-retention priors ─────────────────────────────────────────────
# The exposure tier turns on one number per surface: how many years its data
# must stay confidential. A flat default mis-tiers the extremes, so sector
# hints floor the horizon. The extreme tail is genomic/germline data: a genome
# never changes and implicates non-consenting relatives indefinitely, so its
# true retention horizon is effectively unbounded. It is modeled as a
# conservative 100-year (>=3 generation) floor — a proxy for "unbounded", not
# a literal cap. Under that prior every classical Shor-vulnerable surface
# tiers CRITICAL by construction; that is the honest consequence of the HNDL
# doctrine, not a tuning artifact.

PERMANENT_RETENTION_YRS: int = 100
DEFAULT_RETENTION_YRS: int = 10

SECTOR_RETENTION: Dict[str, int] = {
    "genomic":           PERMANENT_RETENTION_YRS,
    "germline":          PERMANENT_RETENTION_YRS,
    "genomics":          PERMANENT_RETENTION_YRS,
    "national-security": 25,
    "healthcare":        30,  # clinical records — long-lived but bounded
    "clinical":          30,
    "financial":         15,
    "legal":             15,
    "industrial":        10,
    "marketing":         3,
}

_GENOMIC_TOKENS = ("genom", "germline", "dna", "exome", "biobank")


def sector_retention_years(sector: Optional[str]) -> int:
    """Resolve a sector hint to its default data-retention horizon (years).

    Case- and separator-tolerant ("Clinical Genomics", "national_security").
    Unknown or empty sectors fall back to ``DEFAULT_RETENTION_YRS`` — the
    resolver never silently mis-tiers by guessing. Any token naming a genomic
    surface resolves to the permanent floor (see module note).
    """
    if not sector:
        return DEFAULT_RETENTION_YRS
    key = sector.strip().lower().replace("_", "-").replace(" ", "-")
    if key in SECTOR_RETENTION:
        return SECTOR_RETENTION[key]
    if any(tok in key for tok in _GENOMIC_TOKENS):
        return PERMANENT_RETENTION_YRS
    for known, yrs in SECTOR_RETENTION.items():
        if known in key:
            return yrs
    return DEFAULT_RETENTION_YRS


def apply_sector_floor(retention_yrs: int, sector: Optional[str]) -> int:
    """Floor a per-surface retention estimate by the sector prior.

    The sector prior is a floor, never a ceiling: it can only raise exposure
    severity (the safe direction for a security tool). An explicitly higher
    per-surface estimate still wins via max().
    """
    return max(int(retention_yrs), sector_retention_years(sector))


# ── Migration guidance ───────────────────────────────────────────────────────

MIGRATION_TARGETS: Dict[str, str] = {
    "RSA-2048":          "ML-KEM-768 (NIST FIPS 203) for key encapsulation; ML-DSA-65 (FIPS 204) for signatures",
    "RSA-4096":          "ML-DSA-87 (NIST FIPS 204) for signatures; ML-KEM-1024 for high-assurance key exchange",
    "ECDSA-P256":        "ML-DSA-65 (NIST FIPS 204) or SLH-DSA-128f (FIPS 205)",
    "ECDSA-P384":        "ML-DSA-65 (NIST FIPS 204) — Level 3 equivalent security",
    "ECDH-P256":         "ML-KEM-768 (NIST FIPS 203) — hybrid X25519 + ML-KEM-768 for the transition period",
    "ECDH-P384":         "ML-KEM-768 (NIST FIPS 203) or ML-KEM-1024 for extended security margin",
    "DH-2048":           "ML-KEM-768 (NIST FIPS 203); disable all DH-based cipher suites",
    "DH-3072":           "ML-KEM-768 (NIST FIPS 203)",
    "AES-128":           "Upgrade to AES-256 (Grover reduces AES-128 to 64-bit security)",
    "AES-256":           "No migration required — AES-256 provides 128-bit post-quantum security",
    "SHA-256":           "SHA-384 or SHA3-256 for critical applications; SHA-256 acceptable for non-critical",
    "SHA-384":           "SHA3-384 preferred for new systems; SHA-384 acceptable",
    "SHA-512":           "No migration required",
    "SHA3-256":          "No migration required",
    "SHA3-512":          "No migration required",
    "CHACHA20-POLY1305": "No migration required for data confidentiality; upgrade the key exchange",
}

DEFAULT_MIGRATION_TARGET = (
    "ML-KEM-768 (NIST FIPS 203) for key exchange; ML-DSA-65 (FIPS 204) for signatures"
)


def migration_target(algo: str) -> str:
    """Recommended NIST-standardized replacement for `algo`."""
    return MIGRATION_TARGETS.get(normalize_algorithm(algo), DEFAULT_MIGRATION_TARGET)


# ── Priority score ───────────────────────────────────────────────────────────

# Urgency weight per year of gap between retention need and break horizon.
URGENCY_WEIGHT: float = 1.6
MAX_URGENCY_BOOST: float = 15.0

_TIER_BASE = {"CRITICAL": 85.0, "HIGH": 55.0, "MONITOR": 20.0, "SAFE": 0.0}


def priority_score(tier: str, data_retention_yrs: int, qday_horizon_yrs: int) -> float:
    """0-100 remediation priority.

    CRITICAL maps to 85-100, HIGH 55-84, MONITOR 20-54, SAFE 0-19; within a
    tier, urgency rises with the gap between retention need and break horizon.
    """
    base = _TIER_BASE.get(tier, 20.0)
    gap = max(0, data_retention_yrs - qday_horizon_yrs)
    boost = min(MAX_URGENCY_BOOST, gap * URGENCY_WEIGHT)
    return round(min(100.0, base + boost), 2)
