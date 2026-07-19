"""Horizon model, tiering, and sector-prior tests."""

import pytest

from pqc_scout.horizon import (
    DEFAULT_RETENTION_YRS,
    HNDL_OPTIMISTIC_FACTOR,
    PERMANENT_RETENTION_YRS,
    QDAY_HORIZON,
    apply_sector_floor,
    exposure_tier,
    migration_target,
    priority_score,
    qday_nominal,
    qday_optimistic,
    sector_retention_years,
)


def test_ec_breaks_before_rsa():
    # The 2026 cryptanalysis line: 256-bit EC discrete-log falls first.
    assert qday_nominal("ECDSA-P256") < qday_nominal("RSA-2048")
    assert qday_nominal("ECDH-P256") < qday_nominal("DH-2048")


def test_optimistic_compresses_shor_class_only():
    assert qday_optimistic("RSA-2048") == max(1, round(QDAY_HORIZON["RSA-2048"] * HNDL_OPTIMISTIC_FACTOR))
    # Grover-bound primitives are deliberately NOT compressed.
    assert qday_optimistic("AES-256") == qday_nominal("AES-256")
    assert qday_optimistic("SHA3-256") == qday_nominal("SHA3-256")


def test_normalization_tolerance():
    assert qday_nominal("ecdsa p256") == qday_nominal("ECDSA-P256")
    assert qday_nominal("ml_kem_768") == qday_nominal("ML-KEM-768")


def test_unknown_algorithm_pessimistic_default():
    assert qday_nominal("FROBNICATE-9000") == 8


def test_pqc_schemes_tier_safe():
    for algo in ("ML-KEM-768", "ML-DSA-65", "SLH-DSA-128f"):
        assert exposure_tier(algo, 100) == "SAFE"


def test_hndl_critical_when_retention_exceeds_optimistic():
    # ECDH-P256: nominal 5y, optimistic 3y — 10y retention is CRITICAL.
    assert exposure_tier("ECDH-P256", 10) == "CRITICAL"


def test_short_retention_tiers_lower():
    assert exposure_tier("AES-256", 3) == "MONITOR"
    assert exposure_tier("RSA-4096", 3) == "MONITOR"


@pytest.mark.parametrize("sector", ["genomic", "Germline", "clinical-genomics", "DNA biobank"])
def test_genomic_sector_resolves_permanent(sector):
    assert sector_retention_years(sector) == PERMANENT_RETENTION_YRS


def test_genomic_prior_makes_every_shor_surface_critical():
    # The sharp, correct consequence of HNDL under an unbounded retention
    # horizon: every classical Shor-vulnerable surface is CRITICAL.
    retention = sector_retention_years("genomic")
    for algo in ("RSA-2048", "RSA-4096", "ECDSA-P256", "ECDH-P384", "DH-3072"):
        assert exposure_tier(algo, retention) == "CRITICAL"


def test_unknown_sector_falls_back_to_default():
    assert sector_retention_years("floristry") == DEFAULT_RETENTION_YRS
    assert sector_retention_years(None) == DEFAULT_RETENTION_YRS
    assert sector_retention_years("") == DEFAULT_RETENTION_YRS


def test_sector_separator_tolerance():
    assert sector_retention_years("national_security") == 25
    assert sector_retention_years("National Security") == 25


def test_sector_floor_only_raises():
    assert apply_sector_floor(5, "healthcare") == 30
    assert apply_sector_floor(50, "healthcare") == 50  # higher estimate wins
    assert apply_sector_floor(5, None) == DEFAULT_RETENTION_YRS


def test_migration_targets_cite_fips():
    assert "FIPS 203" in migration_target("ECDH-P256")
    assert "FIPS 204" in migration_target("ECDSA-P256")
    assert "No migration required" in migration_target("AES-256")
    # Unknown algorithms still get a standards-cited default.
    assert "FIPS 203" in migration_target("FROBNICATE-9000")


def test_priority_score_bounds_and_ordering():
    critical = priority_score("CRITICAL", 30, 3)
    high = priority_score("HIGH", 15, 8)
    monitor = priority_score("MONITOR", 5, 20)
    safe = priority_score("SAFE", 5, 50)
    assert 0.0 <= safe < monitor < high < critical <= 100.0
