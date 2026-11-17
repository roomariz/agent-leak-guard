"""Run: python demo.py --redactor presidio|regex-demo --mode both"""
import argparse
from agent_security.models import ToolRequest
from agent_security.redaction import PresidioRedactor, RegexDemoRedactor
from agent_security.workflow import MockTool, TrustedDocumentStore, demo_documents, execute


def main() -> None:
    parser = argparse.ArgumentParser(description="Local PII redaction vs independent action authorisation")
    parser.add_argument("--redactor", choices=("presidio", "regex-demo"), default="presidio")
    parser.add_argument("--mode", choices=("both", "baseline", "protected"), default="both")
    args = parser.parse_args()
    try:
        redactor = PresidioRedactor() if args.redactor == "presidio" else RegexDemoRedactor()
    except RuntimeError as exc:
        parser.exit(2, f"ERROR: {exc}\n")
    print(f"Redactor: {args.redactor}" + (" (LIMITED OFFLINE DEMONSTRATION; NOT PRESIDIO)" if args.redactor == "regex-demo" else ""))
    store = TrustedDocumentStore(demo_documents())
    request = ToolRequest("external_report", "partner.example", ("private_forecast",))
    cases = []
    if args.mode in ("both", "baseline"):
        cases.append(("A: redaction only", False))
    if args.mode in ("both", "protected"):
        cases.append(("B: redaction + independent policy", True))
    for label, protected in cases:
        receiver = MockTool()
        result = execute(request, store, redactor, receiver, enforce_policy=protected)
        print(f"\n{label}\n  status: {result.status}\n  reason: {result.reason}")
        print(f"  simulated sends: {len(receiver.payloads)}")
        if receiver.payloads:
            print(f"  original email still present: {result.email_present_in_payload}")
            print(f"  confidential marker still present: {result.confidential_marker_present_in_payload}")
        else:
            print("  payload not generated or transmitted")
    # Control case proves policy isn't simply blocking everything.
    clean = ToolRequest("external_report", "partner.example", ("public_summary",))
    allowed = execute(clean, store, redactor, MockTool(), enforce_policy=True)
    print(f"\nControl: public summary to approved partner: {allowed.status}")
    print("\nAll tools are local mocks; nothing is sent over a network.")


if __name__ == "__main__":
    main()
