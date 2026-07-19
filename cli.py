"""pqc-scout command-line interface.

Commands:
  assess   Run a full PQC assessment from a stack description (text or file)
  scan     Live TLS scan of one or more domains
  score    Show per-surface scoring for a saved report
  roadmap  Print the migration roadmap for a saved report
  list     List recent assessments
  status   Database statistics and standards references
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__, store
from .extract import ExtractionError
from .pipeline import run_assessment
from .tls import scan_tls_multi

STANDARDS = [
    "NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)", "NIST FIPS 205 (SLH-DSA)",
    "NIST IR 8547", "CISA CNSA 2.0",
]


def _print_report(report, as_json: bool) -> None:
    if as_json:
        print(report.model_dump_json(indent=2))
        return
    print(f"\n{'=' * 70}")
    print(f"PQC-SCOUT ASSESSMENT — {report.target}")
    print(f"{'=' * 70}")
    print(f"Report ID  : {report.report_id}")
    print(f"Assessed   : {report.assessed_at[:19]}")
    print(f"Overall    : {report.overall_tier}")
    print(
        f"Surfaces   : {len(report.surfaces)} total | "
        f"CRITICAL={report.critical_count} HIGH={report.high_count} "
        f"MONITOR={report.monitor_count} SAFE={report.safe_count}"
    )
    print("\nEXECUTIVE SUMMARY:")
    print(f"  {report.executive_summary}")
    print("\nSURFACES (by priority):")
    for s in sorted(report.surfaces, key=lambda x: -x.priority_score):
        print(
            f"  [{s.exposure_tier:8}] {s.category:<25} {s.algorithm:<18} "
            f"score={s.priority_score:5.1f} | {s.location}"
        )
    print(f"\nReport digest: {report.report_digest}")


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="[pqc-scout] %(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(
        prog="pqc-scout",
        description="Post-quantum cryptography migration scanner",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_assess = sub.add_parser("assess", help="Run full PQC assessment")
    p_assess.add_argument("--target", "-t", required=True, help="Target/organization name")
    p_assess.add_argument("--stack", "-s", required=True, help="Stack description (text or file path)")
    p_assess.add_argument("--sector", help="Sector hint floors the retention horizon "
                          "(e.g. genomic, healthcare, financial, national-security)")
    p_assess.add_argument("--llm", action="store_true",
                          help="Use LLM extraction (requires pqc-scout[llm] + ANTHROPIC_API_KEY). "
                               "Default is deterministic literal matching.")
    p_assess.add_argument("--dry-run", "-d", action="store_true", help="Don't persist to DB")
    p_assess.add_argument("--json", action="store_true", help="Emit the full report as JSON")

    p_scan = sub.add_parser("scan", help="Live TLS scan of one or more domains")
    p_scan.add_argument("domains", nargs="+", help="Domains to scan (authorized targets only)")
    p_scan.add_argument("--json", action="store_true", help="Emit results as JSON")

    p_score = sub.add_parser("score", help="Show scoring for a saved report")
    p_score.add_argument("--report-id", "-r", required=True)

    p_road = sub.add_parser("roadmap", help="Print migration roadmap for a saved report")
    p_road.add_argument("--report-id", "-r", required=True)

    p_list = sub.add_parser("list", help="List recent assessments")
    p_list.add_argument("--limit", "-l", type=int, default=20)

    sub.add_parser("status", help="Database statistics and standards references")

    args = parser.parse_args(argv)

    if args.command == "assess":
        stack_input = args.stack
        try:
            is_file = Path(stack_input).exists()
        except OSError:  # inline descriptions can exceed filename length limits
            is_file = False
        if is_file:
            stack_input = Path(stack_input).read_text()
        try:
            report = run_assessment(
                args.target, stack_input, sector=args.sector,
                use_llm=args.llm, persist=not args.dry_run,
            )
        except ExtractionError as e:
            print(f"\nEXTRACTION FAILED — {e}", file=sys.stderr)
            print("  No report was produced; the deterministic baseline was NOT "
                  "silently substituted. Re-run without --llm for deterministic "
                  "literal-matching extraction.", file=sys.stderr)
            return 2
        _print_report(report, args.json)
        if args.dry_run:
            print("DRY RUN — not persisted to DB")

    elif args.command == "scan":
        results = scan_tls_multi(args.domains)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                if r.get("error"):
                    print(f"  {r['domain']:<30} ERROR: {r['error']}")
                else:
                    pqc = " [PQC KEM detected]" if r.get("pqc_detected") else ""
                    print(
                        f"  [{r['exposure_tier']:8}] {r['domain']:<30} "
                        f"{r['algorithm']:<12} {r['protocol']:<8} "
                        f"{r['cipher_suite']}{pqc}"
                    )

    elif args.command == "score":
        report = store.load_report(args.report_id)
        if not report:
            print(f"Report {args.report_id} not found.", file=sys.stderr)
            return 1
        for s in sorted(report.surfaces, key=lambda x: -x.priority_score):
            print(
                f"[{s.exposure_tier:8}] priority={s.priority_score:5.1f} | "
                f"{s.algorithm:<18} | {s.category:<25} | {s.location}"
            )

    elif args.command == "roadmap":
        report = store.load_report(args.report_id)
        if not report:
            print(f"Report {args.report_id} not found.", file=sys.stderr)
            return 1
        print(f"\nMIGRATION ROADMAP — {report.target} ({report.overall_tier})")
        print("=" * 70)
        for phase in report.roadmap:
            print(f"\n{phase.get('phase', 'Phase')} [{phase.get('timeline', '')}] — {phase.get('priority', '')}")
            for action in phase.get("actions", []):
                print(f"  * {action}")
            refs = phase.get("nist_refs", [])
            if refs:
                print(f"  NIST: {', '.join(refs)}")

    elif args.command == "list":
        reports = store.list_reports(limit=args.limit)
        print(f"\nPQC-SCOUT REPORTS — {len(reports)} records")
        print("=" * 90)
        for r in reports:
            print(
                f"  {r['report_id'][:12]}  {r['target']:<30}  {r['overall_tier']:8}  "
                f"C={r['critical_count']} H={r['high_count']} M={r['monitor_count']}  "
                f"{r['assessed_at'][:19]}"
            )

    elif args.command == "status":
        s = store.stats()
        s["standards"] = STANDARDS
        s["version"] = __version__
        print(json.dumps(s, indent=2))

    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    sys.exit(main())
