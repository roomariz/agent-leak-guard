"""
Configuration C: Layered security evaluation and 3-way comparative benchmark.

Runs all 15 layered scenarios with deterministic fixtures across:
  - Configuration A: PII redaction only.
  - Configuration B: Tool-level permission checks + PII redaction.
  - Configuration C: Layered security (input filtering, output filtering, response guard).

Usage:
    python evaluate_c.py
    python evaluate_c.py --redactor presidio
    python evaluate_c.py --output evaluation_results
"""
from __future__ import annotations

import argparse
from pathlib import Path

from agent_security.evaluation_c import (
    layered_scenarios, run_layered_scenario, save_layered_results, summarize_layered,
)
from agent_security.redaction import PresidioRedactor, RegexDemoRedactor


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Configuration C layered-security evaluation & A/B/C comparison"
    )
    parser.add_argument("--redactor", choices=("presidio", "regex-demo"), default="regex-demo")
    parser.add_argument("--output", default="evaluation_results",
                        help="Directory for metadata-only CSV and JSON output")
    args = parser.parse_args()

    try:
        redactor = PresidioRedactor() if args.redactor == "presidio" else RegexDemoRedactor()
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 2

    print("=" * 86)
    print(f"AGENT LEAK GUARD: THREE-WAY SECURITY CONFIGURATION EVALUATION")
    print(f"Redactor engine: {args.redactor} | In-memory mocks only | Synthetic records")
    print("=" * 86)
    print(
        f"{'Scenario':36s} | {'Config A':14s} | {'Config B':14s} | {'Config C':20s}"
    )
    print("-" * 86)

    records = []
    for scenario in layered_scenarios():
        record = run_layered_scenario(scenario, redactor)
        records.append(record)

        # Labels for output
        a_lbl = record.config_a_status
        if record.config_a_unauthorised_field_disclosure or record.config_a_unauthorised_tool_exec:
            a_lbl += " [LEAK]"

        b_lbl = record.config_b_status
        if record.config_b_unauthorised_field_disclosure or record.config_b_unauthorised_tool_exec:
            b_lbl += " [LEAK]"

        c_lbl = record.outcome_status
        if not record.response_guard_passed:
            c_lbl += " [GUARDED]"

        print(f"{record.scenario:36s} | {a_lbl:14s} | {b_lbl:14s} | {c_lbl:20s}")

    csv_path, json_path = save_layered_results(
        records, Path(args.output), redactor=args.redactor
    )
    summary = summarize_layered(records)

    print("\n" + "=" * 86)
    print("THREE-WAY COMPARATIVE METRICS SUMMARY")
    print("=" * 86)
    print(f"{'Metric':42s} | {'Config A':10s} | {'Config B':10s} | {'Config C':10s}")
    print("-" * 86)
    print(
        f"{'Unauthorised tool executions':42s} | "
        f"{summary['config_a_unauthorised_tool_executions']:10d} | "
        f"{summary['config_b_unauthorised_tool_executions']:10d} | "
        f"{summary['config_c_unauthorised_tool_executions']:10d}"
    )
    print(
        f"{'Unauthorised field disclosures':42s} | "
        f"{summary['config_a_unauthorised_field_disclosures']:10d} | "
        f"{summary['config_b_unauthorised_field_disclosures']:10d} | "
        f"{summary['config_c_unauthorised_field_disclosures']:10d}"
    )
    print(
        f"{'Sensitive info in final responses':42s} | "
        f"{summary['config_a_response_leakages']:10d} | "
        f"{summary['config_b_response_leakages']:10d} | "
        f"{summary['config_c_response_leakages']:10d}"
    )
    print(
        f"{'Policy enforcement failures':42s} | "
        f"{(summary['config_a_unauthorised_tool_executions'] + summary['config_a_unauthorised_field_disclosures'] + summary['config_a_response_leakages']):10d} | "
        f"{(summary['config_b_unauthorised_tool_executions'] + summary['config_b_unauthorised_field_disclosures'] + summary['config_b_response_leakages']):10d} | "
        f"{summary['config_c_policy_enforcement_failures']:10d}"
    )
    print("-" * 86)
    total_scenarios = summary['total_scenarios']
    legit_total = summary['config_c_legitimate_scenarios_count']

    a_legit_pct = f"{summary['config_a_legitimate_tasks_completed']} ({summary['config_a_legitimate_tasks_completed'] / legit_total * 100:.0f}%)" if legit_total else "N/A"
    b_legit_pct = f"{summary['config_b_legitimate_tasks_completed']} ({summary['config_b_legitimate_tasks_completed'] / legit_total * 100:.0f}%)" if legit_total else "N/A"
    c_legit_pct = f"{summary['config_c_legitimate_tasks_completed']} ({summary['config_c_legitimate_tasks_completed'] / legit_total * 100:.0f}%)" if legit_total else "N/A"

    a_fp_rate = f"{summary['config_a_false_positive_blocked'] / total_scenarios * 100:.1f}%" if total_scenarios else "0.0%"
    b_fp_rate = f"{summary['config_b_false_positive_blocked'] / total_scenarios * 100:.1f}%" if total_scenarios else "0.0%"
    c_fp_rate = f"{summary['config_c_false_positive_blocked'] / total_scenarios * 100:.1f}%" if total_scenarios else "0.0%"

    a_avg_fields = f"{summary['config_a_avg_authorised_fields_delivered_pct'] * 100:.1f}%*"
    b_avg_fields = f"{summary['config_b_avg_authorised_fields_delivered_pct'] * 100:.1f}%*"
    c_avg_fields = f"{summary['config_c_avg_authorised_fields_delivered_pct'] * 100:.1f}%"

    print(
        f"{f'Legitimate tasks completed (out of {legit_total})':42s} | "
        f"{a_legit_pct:10s} | {b_legit_pct:10s} | {c_legit_pct:10s}"
    )
    print(
        f"{'False-positive blocking rate':42s} | "
        f"{a_fp_rate:10s} | {b_fp_rate:10s} | {c_fp_rate:10s}"
    )
    print(
        f"{'Avg authorised fields delivered':42s} | "
        f"{a_avg_fields:10s} | {b_avg_fields:10s} | {c_avg_fields:10s}"
    )
    print("  * Configurations A and B delivered 100% of fields only because they lack attribute controls,")
    print("    delivering unauthorized and confidential attributes alongside authorized ones.")
    print("-" * 86)
    print(f"CSV report:  {csv_path.resolve()}")
    print(f"JSON report: {json_path.resolve()}")
    print("=" * 86)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
