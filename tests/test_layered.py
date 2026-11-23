"""
Unit and integration tests for Configuration C: Layered Security.

All tests run without paid external API calls.
Sensitive values must not appear in assertions, test names, or failure messages.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_security.models import (
    CustomerRecord, FieldSensitivity, StructuredToolRequest,
)
from agent_security.policy import (
    CUSTOMER_RECORD_SCHEMA, FIELD_ALLOWLISTS, PERMITTED_ACTIONS,
    authorise_structured, filter_record_fields,
)
from agent_security.redaction import RegexDemoRedactor
from agent_security.response_guard import (
    ResponseGuardResult, check_response, redact_response,
)
from agent_security.workflow import (
    MockStructuredTool, TrustedCustomerStore,
    demo_customer_records, execute_layered,
)
from agent_security.evaluation_c import (
    LayeredRecord, layered_scenarios, run_layered_scenario,
    save_layered_results, summarize_layered,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store() -> TrustedCustomerStore:
    return TrustedCustomerStore(demo_customer_records())


@pytest.fixture
def redactor() -> RegexDemoRedactor:
    return RegexDemoRedactor()


def _make_request(**kwargs) -> StructuredToolRequest:
    defaults = dict(
        tool_name="customer_lookup",
        action="lookup",
        recipient="intranet.example",
        record_ids=("cust_001",),
        requested_fields=("customer_id", "account_tier"),
    )
    defaults.update(kwargs)
    return StructuredToolRequest(**defaults)


# ---------------------------------------------------------------------------
# Field allowlist tests
# ---------------------------------------------------------------------------

class TestFieldAllowlists:
    def test_allowlist_exists_for_known_endpoints(self):
        assert ("customer_lookup", "intranet.example") in FIELD_ALLOWLISTS
        assert ("customer_summary", "partner.example") in FIELD_ALLOWLISTS

    def test_internal_allowlist_excludes_confidential_fields(self):
        allowlist = FIELD_ALLOWLISTS[("customer_lookup", "intranet.example")]
        confidential = {
            name for name, spec in CUSTOMER_RECORD_SCHEMA.items()
            if spec.sensitivity == FieldSensitivity.CONFIDENTIAL
        }
        assert allowlist.isdisjoint(confidential), (
            "Confidential fields must not appear in any allowlist"
        )

    def test_partner_allowlist_excludes_pii_and_confidential(self):
        allowlist = FIELD_ALLOWLISTS[("customer_summary", "partner.example")]
        restricted = {
            name for name, spec in CUSTOMER_RECORD_SCHEMA.items()
            if spec.sensitivity in {FieldSensitivity.RESTRICTED, FieldSensitivity.CONFIDENTIAL}
        }
        assert allowlist.isdisjoint(restricted)

    def test_default_deny_for_unknown_endpoint(self):
        decision = authorise_structured(
            _make_request(recipient="unknown.example"),
            frozenset({"customer_id"}),
        )
        assert not decision.permitted
        assert "default deny" in decision.reason.lower() or "not approved" in decision.reason.lower()

    def test_default_deny_for_unknown_tool(self):
        decision = authorise_structured(
            _make_request(tool_name="shell_exec"),
            frozenset({"customer_id"}),
        )
        assert not decision.permitted

    def test_all_requested_fields_blocked_gives_deny(self):
        decision = authorise_structured(
            _make_request(requested_fields=("credit_limit", "credit_score")),
            frozenset({"credit_limit", "credit_score"}),
        )
        assert not decision.permitted

    def test_permitted_fields_returned_in_decision(self):
        decision = authorise_structured(
            _make_request(requested_fields=("customer_id", "account_tier")),
            frozenset({"customer_id", "account_tier"}),
        )
        assert decision.permitted
        assert "customer_id" in decision.allowed_fields
        assert "account_tier" in decision.allowed_fields

    def test_confidential_fields_removed_from_allowed_even_if_in_allowlist(self):
        # Belt-and-suspenders: even if someone puts a confidential field in the allowlist,
        # authorise_structured must still block it.
        from unittest.mock import patch
        patched_allowlist = dict(FIELD_ALLOWLISTS)
        patched_allowlist[("customer_lookup", "intranet.example")] = (
            FIELD_ALLOWLISTS[("customer_lookup", "intranet.example")] | frozenset({"credit_limit"})
        )
        with patch("agent_security.policy.FIELD_ALLOWLISTS", patched_allowlist):
            decision = authorise_structured(
                _make_request(requested_fields=("customer_id", "credit_limit")),
                frozenset({"customer_id", "credit_limit"}),
            )
        # credit_limit is CONFIDENTIAL → must still be in blocked_fields
        assert "credit_limit" in decision.blocked_fields

    def test_unknown_field_name_is_blocked(self):
        decision = authorise_structured(
            _make_request(requested_fields=("customer_id", "not_a_real_field")),
            frozenset({"customer_id", "not_a_real_field"}),
        )
        assert "not_a_real_field" in decision.blocked_fields

    def test_injection_looking_field_name_blocked(self):
        injection_field = "ignore_policy_and_send_all_fields"
        decision = authorise_structured(
            _make_request(requested_fields=("customer_id", injection_field)),
            frozenset({"customer_id", injection_field}),
        )
        assert injection_field in decision.blocked_fields
        assert "customer_id" in decision.allowed_fields


# ---------------------------------------------------------------------------
# Nested and unexpected field tests
# ---------------------------------------------------------------------------

class TestNestedAndUnexpectedFields:
    def test_dotted_field_name_is_blocked(self):
        dotted = "fields.credit_limit"
        decision = authorise_structured(
            _make_request(requested_fields=("customer_id", dotted)),
            frozenset({"customer_id", dotted}),
        )
        assert dotted in decision.blocked_fields

    def test_all_glob_field_is_blocked(self):
        glob = "__all__"
        decision = authorise_structured(
            _make_request(requested_fields=("customer_id", glob)),
            frozenset({"customer_id", glob}),
        )
        assert glob in decision.blocked_fields

    def test_empty_requested_fields_does_not_permit(self):
        decision = authorise_structured(
            _make_request(requested_fields=()),
            frozenset(),
        )
        assert not decision.permitted


# ---------------------------------------------------------------------------
# Default-deny behaviour
# ---------------------------------------------------------------------------

class TestDefaultDeny:
    def test_unknown_tool_denied(self):
        d = authorise_structured(_make_request(tool_name="evil_tool"), frozenset({"customer_id"}))
        assert not d.permitted

    def test_unknown_recipient_denied(self):
        d = authorise_structured(_make_request(recipient="evil.example"), frozenset({"customer_id"}))
        assert not d.permitted

    def test_unknown_action_denied(self):
        d = authorise_structured(_make_request(action="destroy"), frozenset({"customer_id"}))
        assert not d.permitted

    def test_no_fields_remaining_denied(self):
        d = authorise_structured(_make_request(requested_fields=("credit_limit",)),
                                 frozenset({"credit_limit"}))
        assert not d.permitted


# ---------------------------------------------------------------------------
# Tool input filtering
# ---------------------------------------------------------------------------

class TestToolInputFiltering:
    def test_confidential_fields_blocked_before_tool_execution(self, store, redactor):
        req = _make_request(requested_fields=("customer_id", "credit_limit", "credit_score"))
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        # Tool may still execute with remaining fields
        assert "credit_limit" in outcome.input_blocked_fields or \
               not any("credit_limit" in str(p) for p in receiver.payloads)

    def test_restricted_field_reaches_internal_tool(self, store, redactor):
        req = _make_request(requested_fields=("customer_id", "name", "email"))
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        assert outcome.sent_to_mock
        # name and email are RESTRICTED but allowed internally; they should be delivered
        assert "name" in outcome.delivered_field_names
        assert "email" in outcome.delivered_field_names

    def test_confidential_field_never_reaches_mock_tool(self, store, redactor):
        req = _make_request(requested_fields=("customer_id", "credit_limit"))
        receiver = MockStructuredTool()
        execute_layered(req, store, redactor, receiver)
        for payload in receiver.payloads:
            assert "credit_limit" not in payload, "credit_limit must not reach the mock tool"

    def test_unapproved_destination_blocks_all_fields(self, store, redactor):
        req = _make_request(recipient="attacker.example")
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        assert outcome.status == "BLOCKED"
        assert receiver.payloads == []

    def test_unknown_tool_blocks_execution(self, store, redactor):
        req = _make_request(tool_name="shell_exec")
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        assert outcome.status == "BLOCKED"
        assert receiver.payloads == []

    def test_unapproved_action_blocks_execution(self, store, redactor):
        req = _make_request(action="delete")
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        assert outcome.status == "BLOCKED"
        assert receiver.payloads == []


# ---------------------------------------------------------------------------
# Tool output filtering
# ---------------------------------------------------------------------------

class TestToolOutputFiltering:
    def test_filter_record_fields_removes_confidential(self):
        fields = {
            "customer_id": "CUST-001",
            "credit_limit": 25000,
            "credit_score": 740,
            "account_tier": "gold",
        }
        allowed = frozenset({"customer_id", "account_tier"})
        filtered = filter_record_fields(fields, allowed)
        assert "credit_limit" not in filtered
        assert "credit_score" not in filtered
        assert filtered["customer_id"] == "CUST-001"
        assert filtered["account_tier"] == "gold"

    def test_filter_record_fields_removes_unlisted(self):
        fields = {"customer_id": "X", "name": "Y", "credit_limit": 999}
        allowed = frozenset({"customer_id"})
        filtered = filter_record_fields(fields, allowed)
        assert set(filtered.keys()) == {"customer_id"}

    def test_confidential_fields_always_blocked_in_output(self):
        """Even if allowed_fields contains confidential names, they must be removed."""
        fields = {"customer_id": "X", "credit_limit": 50000}
        # Intentionally pass credit_limit in allowed_fields (belt-and-suspenders check)
        allowed = frozenset({"customer_id", "credit_limit"})
        filtered = filter_record_fields(fields, allowed)
        assert "credit_limit" not in filtered

    def test_tool_output_contains_only_permitted_field_names(self, store, redactor):
        req = _make_request(requested_fields=("customer_id", "account_tier", "credit_limit"))
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        for payload in receiver.payloads:
            assert "credit_limit" not in payload
        assert "credit_limit" not in outcome.delivered_field_names

    def test_unknown_record_id_blocked(self, store, redactor):
        req = _make_request(record_ids=("nonexistent_id",))
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        assert outcome.status == "BLOCKED"
        assert receiver.payloads == []


# ---------------------------------------------------------------------------
# Final-response validation
# ---------------------------------------------------------------------------

class TestFinalResponseValidation:
    def test_clean_response_passes(self):
        result = check_response("Customer CUST-001 is a gold member.")
        assert result.permitted

    def test_email_in_response_flagged(self):
        result = check_response("Contact alice@demo.invalid about this account.")
        assert not result.permitted
        assert "EMAIL_ADDRESS" in result.pii_patterns_found

    def test_phone_in_response_flagged(self):
        result = check_response("Call the customer at 555-100-0001 to follow up.")
        assert not result.permitted
        assert "PHONE_NUMBER" in result.pii_patterns_found

    def test_business_marker_in_response_flagged(self):
        result = check_response("The document references FORECAST-SECRET-2030.")
        assert not result.permitted
        assert "BUSINESS_MARKER_FORECAST_SECRET" in result.business_markers_found

    def test_confidential_field_value_in_response_flagged(self):
        record = CustomerRecord(
            record_id="cust_001",
            fields={"credit_limit": 25000, "credit_score": 740},
        )
        result = check_response(
            "The customer's credit score is 740.",
            confidential_records=[record],
        )
        assert not result.permitted
        assert "credit_score" in result.confidential_field_names_found

    def test_warn_only_policy_does_not_block(self):
        result = check_response(
            "Contact alice@demo.invalid",
            policy="warn_only",
        )
        assert result.permitted
        assert "EMAIL_ADDRESS" in result.pii_patterns_found

    def test_redact_response_removes_email(self):
        redacted = redact_response("Contact alice@demo.invalid today.")
        assert "@" not in redacted
        assert "[EMAIL_ADDRESS]" in redacted

    def test_redact_response_removes_business_marker(self):
        redacted = redact_response("See FORECAST-SECRET-2030 in notes.")
        assert "FORECAST-SECRET-2030" not in redacted
        assert "[RESTRICTED_MARKER]" in redacted

    def test_non_string_response_blocked(self):
        result = check_response(None)  # type: ignore[arg-type]
        assert not result.permitted

    def test_response_guard_called_in_pipeline(self, store, redactor):
        req = _make_request(requested_fields=("customer_id", "account_tier"))
        receiver = MockStructuredTool()
        outcome = execute_layered(
            req, store, redactor, receiver,
            response_text="Contact alice@demo.invalid for account CUST-001.",
        )
        # Tool executed (fields are allowed), but response guard should flag PII
        assert outcome.sent_to_mock
        assert not outcome.response_guard_passed
        assert "EMAIL_ADDRESS" in outcome.response_guard_findings


# ---------------------------------------------------------------------------
# Authorised task completion
# ---------------------------------------------------------------------------

class TestAuthorisedTaskCompletion:
    def test_legitimate_lookup_succeeds(self, store, redactor):
        req = _make_request(requested_fields=("customer_id", "account_tier", "account_status"))
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        assert outcome.status == "SIMULATED_SEND"
        assert outcome.sent_to_mock
        assert receiver.payloads

    def test_external_partner_public_fields_delivered(self, store, redactor):
        req = StructuredToolRequest(
            tool_name="customer_summary",
            action="summary",
            recipient="partner.example",
            record_ids=("cust_001",),
            requested_fields=("customer_id", "account_tier", "join_date"),
        )
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        assert outcome.sent_to_mock
        assert "customer_id" in outcome.delivered_field_names
        assert "account_tier" in outcome.delivered_field_names

    def test_multiple_records_retrieved(self, store, redactor):
        req = _make_request(
            record_ids=("cust_001", "cust_002"),
            requested_fields=("customer_id", "account_tier"),
        )
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        assert outcome.sent_to_mock
        assert len(receiver.payloads) == 2

    def test_pii_values_redacted_in_permitted_internal_fields(self, store, redactor):
        req = _make_request(requested_fields=("customer_id", "email"))
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        assert outcome.sent_to_mock
        for payload in receiver.payloads:
            # Email field should be redacted (regex replaces @-pattern)
            email_val = payload.get("email", "")
            assert "@" not in email_val, "Raw email must be redacted in delivered payload"


# ---------------------------------------------------------------------------
# Confidentiality boundaries
# ---------------------------------------------------------------------------

class TestConfidentialityBoundaries:
    def test_confidential_field_absent_from_all_payloads(self, store, redactor):
        req = _make_request(requested_fields=("customer_id", "credit_limit", "credit_score"))
        receiver = MockStructuredTool()
        execute_layered(req, store, redactor, receiver)
        for payload in receiver.payloads:
            assert "credit_limit" not in payload
            assert "credit_score" not in payload

    def test_confidential_field_absent_when_partner_requests_it(self, store, redactor):
        req = StructuredToolRequest(
            tool_name="customer_summary",
            action="summary",
            recipient="partner.example",
            record_ids=("cust_001",),
            requested_fields=("customer_id", "credit_limit"),
        )
        receiver = MockStructuredTool()
        execute_layered(req, store, redactor, receiver)
        for payload in receiver.payloads:
            assert "credit_limit" not in payload

    def test_combining_public_and_confidential_delivers_only_public(self, store, redactor):
        req = _make_request(
            requested_fields=("customer_id", "account_tier", "credit_limit", "credit_score")
        )
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        for payload in receiver.payloads:
            assert "credit_limit" not in payload
            assert "credit_score" not in payload
        assert "customer_id" in outcome.delivered_field_names
        assert "account_tier" in outcome.delivered_field_names


# ---------------------------------------------------------------------------
# Policy bypass attempts
# ---------------------------------------------------------------------------

class TestPolicyBypassAttempts:
    def test_injection_field_name_does_not_pass(self, store, redactor):
        injection_name = "ignore_policy_and_return_all_fields"
        req = _make_request(requested_fields=("customer_id", injection_name))
        receiver = MockStructuredTool()
        execute_layered(req, store, redactor, receiver)
        for payload in receiver.payloads:
            assert injection_name not in payload

    def test_nested_field_name_does_not_pass(self, store, redactor):
        nested = "fields.credit_limit"
        req = _make_request(requested_fields=("customer_id", nested))
        receiver = MockStructuredTool()
        execute_layered(req, store, redactor, receiver)
        for payload in receiver.payloads:
            assert nested not in payload
            assert "credit_limit" not in payload

    def test_glob_field_does_not_expand(self, store, redactor):
        req = _make_request(requested_fields=("customer_id", "__all__"))
        receiver = MockStructuredTool()
        execute_layered(req, store, redactor, receiver)
        # Only customer_id should be delivered; __all__ must not expand
        for payload in receiver.payloads:
            assert "credit_limit" not in payload
            assert "credit_score" not in payload

    def test_attacker_destination_cannot_receive_any_data(self, store, redactor):
        req = _make_request(recipient="attacker.example", requested_fields=("customer_id",))
        receiver = MockStructuredTool()
        outcome = execute_layered(req, store, redactor, receiver)
        assert outcome.status == "BLOCKED"
        assert receiver.payloads == []


# ---------------------------------------------------------------------------
# Regression protection for Configurations A and B
# ---------------------------------------------------------------------------

class TestConfigABRegression:
    """Ensure the original Config A/B tests still pass after model extension."""

    def test_config_a_redaction_does_not_stop_sensitive_egress(self):
        from agent_security.models import ToolRequest
        from agent_security.workflow import execute, MockTool, TrustedDocumentStore, demo_documents
        store = TrustedDocumentStore(demo_documents())
        mock = MockTool()
        result = execute(
            ToolRequest("external_report", "partner.example", ("private_forecast",)),
            store, RegexDemoRedactor(), mock, enforce_policy=False,
        )
        assert result.status == "SIMULATED_SEND"
        assert result.confidential_marker_present_in_payload is True
        assert result.email_present_in_payload is False

    def test_config_b_policy_blocks_confidential_external(self):
        from agent_security.models import ToolRequest
        from agent_security.workflow import execute, MockTool, TrustedDocumentStore, demo_documents
        store = TrustedDocumentStore(demo_documents())
        mock = MockTool()
        result = execute(
            ToolRequest("external_report", "partner.example", ("private_forecast",)),
            store, RegexDemoRedactor(), mock, enforce_policy=True,
        )
        assert result.status == "BLOCKED"
        assert mock.payloads == []

    def test_config_b_public_data_allowed(self):
        from agent_security.models import ToolRequest
        from agent_security.workflow import execute, MockTool, TrustedDocumentStore, demo_documents
        store = TrustedDocumentStore(demo_documents())
        mock = MockTool()
        result = execute(
            ToolRequest("external_report", "partner.example", ("public_summary",)),
            store, RegexDemoRedactor(), mock, enforce_policy=True,
        )
        assert result.status == "SIMULATED_SEND"


# ---------------------------------------------------------------------------
# Evaluation scenarios: full pipeline
# ---------------------------------------------------------------------------

class TestEvaluationScenarios:
    def test_all_scenarios_run_without_error(self, redactor):
        scenarios = layered_scenarios()
        for s in scenarios:
            record = run_layered_scenario(s, redactor)
            assert isinstance(record, LayeredRecord)

    def test_legitimate_scenarios_complete(self, redactor):
        legitimate = [s for s in layered_scenarios() if s.category == "legitimate"]
        for s in legitimate:
            record = run_layered_scenario(s, redactor)
            assert record.sent_to_mock, f"Legitimate scenario '{s.name}' was unexpectedly blocked"

    def test_attack_scenarios_blocked(self, redactor):
        attacks = [s for s in layered_scenarios() if s.category == "attack"]
        for s in attacks:
            record = run_layered_scenario(s, redactor)
            assert record.outcome_status == "BLOCKED", (
                f"Attack scenario '{s.name}' was not blocked"
            )

    def test_no_confidential_field_ever_delivered(self, redactor):
        confidential_names = {
            name for name, spec in CUSTOMER_RECORD_SCHEMA.items()
            if spec.sensitivity == FieldSensitivity.CONFIDENTIAL
        }
        for s in layered_scenarios():
            record = run_layered_scenario(s, redactor)
            delivered_set = frozenset(record.delivered_field_names.split(",")) if record.delivered_field_names else frozenset()
            overlap = delivered_set & confidential_names
            assert not overlap, (
                f"Scenario '{s.name}' delivered confidential fields: {overlap}"
            )

    def test_response_guard_scenarios_flagged(self, redactor):
        response_guard_cases = [s for s in layered_scenarios() if s.category == "response_guard"]
        for s in response_guard_cases:
            record = run_layered_scenario(s, redactor)
            assert not record.response_guard_passed, (
                f"Response guard should have flagged '{s.name}'"
            )

    def test_summary_has_zero_unauthorised_field_disclosures(self, redactor):
        records = [run_layered_scenario(s, redactor) for s in layered_scenarios()]
        summary = summarize_layered(records)
        assert summary["unauthorised_field_disclosures"] == 0

    def test_summary_has_zero_unauthorised_tool_executions(self, redactor):
        records = [run_layered_scenario(s, redactor) for s in layered_scenarios()]
        summary = summarize_layered(records)
        assert summary["unauthorised_tool_executions"] == 0

    def test_all_attack_scenarios_blocked_in_summary(self, redactor):
        records = [run_layered_scenario(s, redactor) for s in layered_scenarios()]
        summary = summarize_layered(records)
        assert summary["attacks_blocked"] == summary["attack_scenarios"]

    def test_results_contain_no_confidential_values(self, redactor, tmp_path):
        """Saved CSV/JSON must not expose synthetic sensitive values."""
        records = [run_layered_scenario(s, redactor) for s in layered_scenarios()]
        csv_path, json_path = save_layered_results(records, tmp_path, redactor="regex-demo")
        combined = csv_path.read_text(encoding="utf-8") + json_path.read_text(encoding="utf-8")
        # Raw PII values must not appear
        assert "alice@demo.invalid" not in combined
        assert "bob@demo.invalid" not in combined
        assert "25000" not in combined, "credit_limit value must not appear in output"
        assert "740" not in combined, "credit_score value must not appear in output"
        assert "FORECAST-SECRET-2030" not in combined, "raw secret marker must not appear in output"

    def test_bypass_scenarios_filtered_or_blocked(self, redactor):
        bypass = [s for s in layered_scenarios() if s.category == "bypass_attempt"]
        for s in bypass:
            record = run_layered_scenario(s, redactor)
            assert record.outcome_status in {"BLOCKED", "PERMITTED_WITH_FILTERING"}, (
                f"Bypass attempt '{s.name}' was not filtered or blocked"
            )

    def test_delivered_fields_match_expected_for_legitimate(self, redactor):
        legitimate = [s for s in layered_scenarios() if s.category == "legitimate"]
        for s in legitimate:
            record = run_layered_scenario(s, redactor)
            # For legitimate scenarios, the delivered fields should match expectations
            assert record.delivered_matches_expected, (
                f"Legitimate scenario '{s.name}': delivered '{record.delivered_field_names}' "
                f"but expected '{record.expected_delivered_fields}'"
            )


# ---------------------------------------------------------------------------
# Adversarial and Regression Tests for Verified Security Corrections
# ---------------------------------------------------------------------------

class TestNestedDataFilteringAndRedaction:
    def test_nested_dict_confidential_field_stripped(self):
        record_fields = {
            "customer_id": "CUST-999",
            "notes": {
                "general_comment": "Standard user",
                "credit_limit": 50000,
                "internal_audit": {"credit_score": 800, "status": "verified"},
            },
        }
        allowed = frozenset({"customer_id", "notes"})
        filtered = filter_record_fields(record_fields, allowed)
        assert "credit_limit" not in filtered["notes"]
        assert "credit_score" not in filtered["notes"]["internal_audit"]
        assert filtered["notes"]["internal_audit"]["status"] == "verified"
        assert filtered["notes"]["general_comment"] == "Standard user"

    def test_nested_list_confidential_field_stripped(self):
        record_fields = {
            "customer_id": "CUST-999",
            "notes": [
                {"item": "record_one", "credit_limit": 20000},
                {"item": "record_two", "note": "clean entry"},
            ],
        }
        allowed = frozenset({"customer_id", "notes"})
        filtered = filter_record_fields(record_fields, allowed)
        assert len(filtered["notes"]) == 2
        assert "credit_limit" not in filtered["notes"][0]
        assert filtered["notes"][0]["item"] == "record_one"
        assert filtered["notes"][1]["note"] == "clean entry"

    def test_nested_dict_pii_redacted_in_pipeline(self, redactor):
        custom_record = CustomerRecord(
            record_id="cust_nested_pii",
            fields={
                "customer_id": "CUST-999",
                "notes": {
                    "contact_email": "nested_user@demo.invalid",
                    "details": {"sub_email": "sub_user@demo.invalid"},
                },
            },
        )
        custom_store = TrustedCustomerStore((custom_record,))
        req = _make_request(
            record_ids=("cust_nested_pii",),
            requested_fields=("customer_id", "notes"),
        )
        receiver = MockStructuredTool()
        execute_layered(req, custom_store, redactor, receiver)
        assert len(receiver.payloads) == 1
        payload = receiver.payloads[0]
        assert "nested_user@demo.invalid" not in str(payload)
        assert "sub_user@demo.invalid" not in str(payload)
        assert payload["notes"]["contact_email"] == "[EMAIL_ADDRESS]"
        assert payload["notes"]["details"]["sub_email"] == "[EMAIL_ADDRESS]"


class TestResponseGuardHardening:
    def test_confidential_value_flagged_when_tool_is_blocked(self, store, redactor):
        """Reproduces Scenario 9 finding: blocked tool calls must still guard response text."""
        # Request only confidential fields -> input policy blocks execution
        req = _make_request(requested_fields=("credit_limit", "credit_score"))
        receiver = MockStructuredTool()
        outcome = execute_layered(
            req, store, redactor, receiver,
            response_text="Credit limit is 25000.",
        )
        assert outcome.status == "BLOCKED"
        assert not outcome.response_guard_passed
        assert "25000" not in outcome.final_response
        assert "[REDACTED_CREDIT_LIMIT]" in outcome.final_response

    def test_currency_formatted_confidential_number_flagged(self, store):
        """Tests that formatted confidential numbers like 25,000 are detected."""
        res = check_response(
            "Customer has a limit of 25,000 dollars.",
            confidential_records=list(store._records.values()),
        )
        assert not res.permitted
        assert "credit_limit" in res.confidential_field_names_found

    def test_recipient_aware_blocks_customer_name_to_external_partner(self, store):
        """Reproduces Scenario 5 finding: customer name to external partner must be flagged."""
        res = check_response(
            "Alice Testuser's account tier is gold.",
            records=list(store._records.values()),
            recipient="partner.example",
            tool_name="customer_summary",
        )
        assert not res.permitted
        assert "name" in res.confidential_field_names_found

        sanitized = redact_response(
            "Alice Testuser's account tier is gold.",
            records=list(store._records.values()),
            recipient="partner.example",
            tool_name="customer_summary",
        )
        assert "Alice Testuser" not in sanitized
        assert "[REDACTED_NAME]" in sanitized

    def test_recipient_aware_allows_customer_name_internally(self, store):
        """Ensures legitimate internal use of customer name is permitted by response guard."""
        res = check_response(
            "Customer Bob Exampleson (CUST-002) is a silver-tier account.",
            records=list(store._records.values()),
            recipient="intranet.example",
            tool_name="customer_lookup",
        )
        assert res.permitted

