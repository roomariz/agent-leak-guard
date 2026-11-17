"""Five-scenario security evaluation with mock tools and optional live LLM calls.

Examples:
    python evaluate.py --provider fixed --redactor regex-demo
    python evaluate.py --provider google --model gemini-3.5-flash-lite --redactor presidio
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()

from agent_security.evaluation import run_scenario, save_results, scenarios, summarize
from agent_security.llm import GoogleGeminiProposer, OpenAICompatibleProposer
from agent_security.redaction import PresidioRedactor, RegexDemoRedactor


def main() -> int:
    parser = argparse.ArgumentParser(description="Controlled AI-agent tool-policy scenario evaluation")
    parser.add_argument("--provider", choices=("fixed", "google", "openai-compatible"), default="fixed")
    parser.add_argument("--model", default=os.getenv("LLM_MODEL"))
    parser.add_argument("--api-base", default=os.getenv("LLM_API_BASE", "https://api.openai.com/v1"))
    parser.add_argument("--redactor", choices=("presidio", "regex-demo"), default="presidio")
    parser.add_argument("--repeat", type=int, default=1, help="1–10 complete passes; each live pass makes 4 LLM calls")
    parser.add_argument("--output", default="evaluation_results", help="Directory for metadata-only JSON and CSV")
    args = parser.parse_args()
    if not 1 <= args.repeat <= 10:
        parser.error("--repeat must be between 1 and 10")
    if args.provider != "fixed" and not args.model:
        parser.error("--model is required for a live LLM provider")
    try:
        redactor = PresidioRedactor() if args.redactor == "presidio" else RegexDemoRedactor()
        proposer = None
        if args.provider == "google":
            proposer = GoogleGeminiProposer(model=args.model)
        elif args.provider == "openai-compatible":
            proposer = OpenAICompatibleProposer(model=args.model, api_base=args.api_base)
    except (RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 2

    results = []
    for rep in range(1, args.repeat + 1):
        for case in scenarios():
            record = run_scenario(case, redactor, repetition=rep, proposer=proposer)
            results.append(record)
            print(f"{case.name:25s} run={rep} source={record.proposal_source:14s} "
                  f"A={record.baseline_status:15s} B={record.protected_status:15s} "
                  f"policy_authorised={record.policy_authorised}")
    csv_path, json_path = save_results(results, Path(args.output), provider=args.provider,
                                       model=args.model, redactor=args.redactor)
    stats = summarize(results)
    print("\nSUMMARY (synthetic, in-memory mock only)")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print(f"\nCSV: {csv_path.resolve()}\nJSON: {json_path.resolve()}")
    print("IMPORTANT: fixed mode is not a live LLM experiment; errors are not counted as security blocks.")
    print("The injected-snippet case is a toy prompt with labelled untrusted text, not a real RAG/MCP exploit.")
    return 0 if stats["proposal_errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
