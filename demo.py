"""Run: python demo.py --redactor presidio|regex-demo --mode both|all|layered"""
import argparse
from agent_security.models import StructuredToolRequest, ToolRequest
from agent_security.redaction import PresidioRedactor, RegexDemoRedactor
from agent_security.workflow import (
    MockStructuredTool, MockTool, TrustedCustomerStore, TrustedDocumentStore,
    demo_customer_records, demo_documents, execute, execute_layered,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local PII redaction vs independent action authorisation vs layered security")
    parser.add_argument("--redactor", choices=("presidio", "regex-demo"), default="presidio")
    parser.add_argument("--mode", choices=("both", "baseline", "protected", "all", "layered"), default="both")
    args = parser.parse_args()
    try:
        redactor = PresidioRedactor() if args.redactor == "presidio" else RegexDemoRedactor()
    except RuntimeError as exc:
        parser.exit(2, f"ERROR: {exc}\n")
    print(f"Redactor: {args.redactor}" + (" (LIMITED OFFLINE DEMONSTRATION; NOT PRESIDIO)" if args.redactor == "regex-demo" else ""))
    store = TrustedDocumentStore(demo_documents())
    request = ToolRequest("external_report", "partner.example", ("private_forecast",))
    cases = []
    if args.mode in ("both", "baseline", "all"):
        cases.append(("A: redaction only", False))
    if args.mode in ("both", "protected", "all"):
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
    if args.mode in ("both", "protected", "all"):
        clean = ToolRequest("external_report", "partner.example", ("public_summary",))
        allowed = execute(clean, store, redactor, MockTool(), enforce_policy=True)
        print(f"\nControl: public summary to approved partner: {allowed.status}")

    # Configuration C demonstration
    if args.mode in ("all", "layered"):
        print("\nC: Layered Security (tool permission + attribute filtering + response guard)")
        c_store = TrustedCustomerStore(demo_customer_records())
        # Agent requests both permitted and confidential fields on approved internal endpoint
        c_req = StructuredToolRequest(
            tool_name="customer_lookup",
            action="lookup",
            recipient="intranet.example",
            record_ids=("cust_001",),
            requested_fields=("customer_id", "account_tier", "credit_limit", "credit_score"),
        )
        c_receiver = MockStructuredTool()
        c_result = execute_layered(
            c_req, c_store, redactor, c_receiver,
            response_text="Customer CUST-001 credit limit is 25000 and score is 740.",
        )
        print(f"  status: {c_result.status}\n  reason: {c_result.reason}")
        print(f"  simulated sends: {len(c_receiver.payloads)}")
        print(f"  delivered field names: {sorted(c_result.delivered_field_names)}")
        print(f"  confidential fields filtered out: {sorted(c_result.input_blocked_fields)}")
        print(f"  response guard passed: {c_result.response_guard_passed}")
        print(f"  response guard findings: {c_result.response_guard_findings}")
        print(f"  final sanitized response: {c_result.final_response}")

    print("\nAll tools are local mocks; nothing is sent over a network.")


if __name__ == "__main__":
    main()
