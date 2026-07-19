"""SQLite persistence for assessment reports.

Default location: ``~/.pqc-scout/pqc_scout.db`` (override with the
``PQC_SCOUT_DB`` environment variable).
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import AssessmentReport

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pqc_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id       TEXT NOT NULL UNIQUE,
    target          TEXT NOT NULL,
    assessed_at     TEXT NOT NULL,
    overall_tier    TEXT DEFAULT 'MONITOR',
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    monitor_count   INTEGER DEFAULT 0,
    safe_count      INTEGER DEFAULT 0,
    executive_summary TEXT DEFAULT '',
    report_digest   TEXT DEFAULT '',
    payload_json    TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_pqc_target    ON pqc_reports(target);
CREATE INDEX IF NOT EXISTS idx_pqc_tier      ON pqc_reports(overall_tier);
CREATE INDEX IF NOT EXISTS idx_pqc_assessed  ON pqc_reports(assessed_at);
"""


def db_path() -> Path:
    env = os.getenv("PQC_SCOUT_DB")
    if env:
        return Path(env)
    return Path.home() / ".pqc-scout" / "pqc_scout.db"


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    for stmt in _SCHEMA.strip().split(";"):
        if stmt.strip():
            conn.execute(stmt)
    conn.commit()
    return conn


def save_report(report: AssessmentReport) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO pqc_reports
                (report_id, target, assessed_at, overall_tier, critical_count,
                 high_count, monitor_count, safe_count, executive_summary,
                 report_digest, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.report_id, report.target, report.assessed_at,
                report.overall_tier, report.critical_count, report.high_count,
                report.monitor_count, report.safe_count, report.executive_summary,
                report.report_digest, report.model_dump_json(),
            ),
        )
        conn.commit()


def load_report(report_id: str) -> Optional[AssessmentReport]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM pqc_reports WHERE report_id=?", (report_id,)
        ).fetchone()
    if not row:
        return None
    return AssessmentReport.model_validate_json(row["payload_json"])


def list_reports(limit: int = 20) -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT report_id, target, assessed_at, overall_tier,
                   critical_count, high_count, monitor_count
            FROM pqc_reports ORDER BY assessed_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def stats() -> Dict[str, Any]:
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM pqc_reports").fetchone()[0]
        by_tier = {
            row["overall_tier"]: row["n"]
            for row in conn.execute(
                "SELECT overall_tier, COUNT(*) as n FROM pqc_reports GROUP BY overall_tier"
            ).fetchall()
        }
    return {"total_reports": total, "by_tier": by_tier, "db": str(db_path())}
