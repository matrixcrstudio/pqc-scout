"""Deterministic extractor tests."""

from pqc_scout.extract import extract_deterministic
from pqc_scout.horizon import PERMANENT_RETENTION_YRS


def test_detects_standard_literals():
    stack = "nginx with TLS 1.3, RSA-2048 legacy VPN on DH-2048, releases signed with ECDSA P-256"
    surfaces = extract_deterministic(stack)
    algos = {s.algorithm for s in surfaces}
    assert "ECDH-P256" in algos   # TLS 1.3 default key exchange
    assert "RSA-2048" in algos
    assert "DH-2048" in algos
    assert "ECDSA-P256" in algos


def test_modern_curve_literals_normalize_to_ec_family():
    surfaces = extract_deterministic("SSH keys are Ed25519; wallet uses secp256k1; X25519 for transport")
    algos = [s.algorithm for s in surfaces]
    assert all(a in ("ECDSA-P256", "ECDH-P256") for a in algos)
    assert len(algos) == 3


def test_empty_stack_gets_classical_baseline():
    surfaces = extract_deterministic("a static brochure site")
    assert len(surfaces) == 2
    assert {s.category for s in surfaces} == {"TLS_CERTIFICATES", "CODE_SIGNING"}


def test_sector_floor_applied_per_surface():
    surfaces = extract_deterministic("TLS 1.3 API", sector="genomic")
    assert all(s.data_retention_yrs == PERMANENT_RETENTION_YRS for s in surfaces)
    assert all(s.exposure_tier == "CRITICAL" for s in surfaces)


def test_surfaces_are_scored():
    surfaces = extract_deterministic("RSA-2048 everywhere")
    for s in surfaces:
        assert s.priority_score > 0
        assert s.migration_target
        assert s.qday_horizon_yrs > 0
