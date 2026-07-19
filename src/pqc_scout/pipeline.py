"""Assessment pipeline: extract -> score -> summarize -> persist."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from .extract import extract_deterministic, extract_llm
from .models import AssessmentReport
from . import store

_log = logging.getLogger("pqc_scout.pipeline")


def deterministic_summary(report: AssessmentReport) -> str:
    """Template executive summary derived only from scored counts."""
    tier_msg = {
        "CRITICAL": "immediate exposure to harvest-now-decrypt-later attacks",
        "HIGH": "high exposure with a 3-year migration window before Q-Day risk matures",
        "MONITOR": "moderate exposure requiring planned migration within 5+ years",
        "SAFE": "no classical quantum-vulnerable surfaces detected",
    }
    return (
        f"{report.target} cryptographic assessment: {report.critical_count} CRITICAL, "
        f"{report.high_count} HIGH, {report.monitor_count} MONITOR surfaces identified. "
        f"Overall classification: {report.overall_tier} — "
        f"{tier_msg.get(report.overall_tier, 'review required')}. "
        f"NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) migration recommended "
        f"as the primary path. Full roadmap follows."
    )


def deterministic_roadmap(report: AssessmentReport) -> List[Dict[str, Any]]:
    """Three-phase migration roadmap assembled from the scored surfaces."""
    critical_actions = [
        f"Migrate {s.category}/{s.algorithm} ({s.location}) -> {s.migration_target}"
        for s in report.surfaces if s.exposure_tier == "CRITICAL"
    ] or ["Audit TLS certificate inventory", "Replace ECDH key exchange with ML-KEM-768"]

    high_actions = [
        f"Plan migration: {s.category}/{s.algorithm} ({s.location}) -> {s.migration_target}"
        for s in report.surfaces if s.exposure_tier == "HIGH"
    ] or ["Update code signing to ML-DSA-65", "Migrate VPN cipher suites"]

    return [
        {
            "phase": "Phase 1 — Immediate Remediation",
            "timeline": "0-3 months",
            "priority": "CRITICAL",
            "actions": critical_actions[:5],
            "nist_refs": ["NIST FIPS 203 (ML-KEM-768)", "NIST FIPS 204 (ML-DSA-65)"],
        },
        {
            "phase": "Phase 2 — Strategic Migration",
            "timeline": "3-12 months",
            "priority": "HIGH",
            "actions": high_actions[:5] + [
                "Deploy hybrid key exchange (X25519 + ML-KEM-768) on all external TLS",
                "Update internal CA hierarchy to include ML-DSA-65 intermediate CAs",
                "Adopt an ML-KEM-768 reference library in the CI/CD pipeline",
            ],
            "nist_refs": ["NIST FIPS 203", "NIST IR 8547 §4"],
        },
        {
            "phase": "Phase 3 — Continuous Hardening",
            "timeline": "12-24 months",
            "priority": "MONITOR",
            "actions": [
                "Retire all RSA/ECDH classical-only cipher suites",
                "Schedule a recurring automated cryptographic inventory scan",
                "SLH-DSA-128f (NIST FIPS 205) for firmware signing on hardware assets",
                "CNSA 2.0 compliance checkpoint (NSA deadline: 2030)",
            ],
            "nist_refs": ["NIST FIPS 205 (SLH-DSA)", "CISA CNSA 2.0"],
        },
    ]


def run_assessment(
    target: str,
    stack_description: str,
    sector: Optional[str] = None,
    use_llm: bool = False,
    persist: bool = True,
) -> AssessmentReport:
    """Run a full assessment and (by default) persist it.

    Deterministic extraction is the default. Pass ``use_llm=True`` to use the
    opt-in LLM extractor, which raises ``ExtractionError`` rather than
    silently degrading — the caller decides how to proceed.
    """
    _log.info("assessing %s (sector=%s, llm=%s)", target, sector or "generic", use_llm)
    report = AssessmentReport(
        target=target, stack_description=stack_description, sector=sector or ""
    )

    if use_llm:
        report.surfaces = extract_llm(target, stack_description, sector)
    else:
        report.surfaces = extract_deterministic(stack_description, sector)

    report.recount()
    report.executive_summary = deterministic_summary(report)
    report.roadmap = deterministic_roadmap(report)
    report.report_digest = report.compute_digest()

    if persist:
        store.save_report(report)
        _log.info("persisted report_id=%s", report.report_id)

    return report
