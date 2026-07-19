"""Pipeline, persistence, and CLI smoke tests."""

import json

import pytest

from pqc_scout import store
from pqc_scout.cli import main
from pqc_scout.pipeline import run_assessment


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("PQC_SCOUT_DB", str(tmp_path / "test.db"))


def test_assessment_end_to_end():
    report = run_assessment(
        "ExampleCo", "TLS 1.3 web tier, RSA-2048 code signing, AES-128 backups",
        persist=True,
    )
    assert report.overall_tier == "CRITICAL"  # ECDH-P256 @ 10y retention is HNDL-live
    assert report.critical_count >= 1
    assert report.report_digest == report.compute_digest()
    assert len(report.roadmap) == 3
    assert "ExampleCo" in report.executive_summary

    loaded = store.load_report(report.report_id)
    assert loaded is not None
    assert loaded.target == "ExampleCo"
    assert len(loaded.surfaces) == len(report.surfaces)


def test_dry_run_not_persisted():
    report = run_assessment("DryCo", "TLS 1.3", persist=False)
    assert store.load_report(report.report_id) is None


def test_recount_overall_tier_precedence():
    report = run_assessment("SafeCo", "ML-KEM-768 everywhere", persist=False)
    # Deterministic extractor finds no classical literal -> classical baseline
    # is assumed, so the overall tier reflects the baseline, not SAFE.
    assert report.overall_tier in ("CRITICAL", "HIGH", "MONITOR")


def test_cli_assess_json(capsys):
    rc = main([
        "assess", "--target", "CliCo", "--stack",
        "TLS 1.3 and RSA-2048", "--dry-run", "--json",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out[: out.rindex("}") + 1])
    assert payload["target"] == "CliCo"
    assert payload["surfaces"]


def test_cli_status(capsys):
    rc = main(["status"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_reports"] == 0
    assert any("FIPS 203" in s for s in payload["standards"])


def test_cli_missing_report_exits_nonzero():
    assert main(["score", "--report-id", "nonexistent"]) == 1


def test_cli_long_inline_stack_description(capsys):
    # A stack description longer than the filesystem name limit must be
    # treated as inline text, not crash the file-path check (OSError ENAMETOOLONG).
    long_stack = "TLS 1.3 plus " + "very detailed infrastructure notes " * 20
    rc = main(["assess", "--target", "LongCo", "--stack", long_stack, "--dry-run"])
    assert rc == 0
    assert "LongCo" in capsys.readouterr().out
