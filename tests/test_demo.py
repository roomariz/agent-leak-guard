import pytest
from agent_security.models import Document, Sensitivity, ToolRequest
from agent_security.policy import authorise
from agent_security.redaction import RegexDemoRedactor
from agent_security.workflow import MockTool, TrustedDocumentStore, demo_documents, execute


@pytest.fixture
def store():
    return TrustedDocumentStore(demo_documents())


def test_redaction_only_does_not_stop_sensitive_egress(store):
    mock = MockTool()
    result = execute(ToolRequest("external_report", "partner.example", ("private_forecast",)),
                     store, RegexDemoRedactor(), mock, enforce_policy=False)
    assert result.status == "SIMULATED_SEND"
    assert result.confidential_marker_present_in_payload is True
    assert result.email_present_in_payload is False
    assert len(mock.payloads) == 1


def test_policy_blocks_confidential_external_egress(store):
    mock = MockTool()
    result = execute(ToolRequest("external_report", "partner.example", ("private_forecast",)),
                     store, RegexDemoRedactor(), mock, enforce_policy=True)
    assert result.status == "BLOCKED"
    assert mock.payloads == []


def test_public_data_is_allowed(store):
    mock = MockTool()
    result = execute(ToolRequest("external_report", "partner.example", ("public_summary",)),
                     store, RegexDemoRedactor(), mock, enforce_policy=True)
    assert result.status == "SIMULATED_SEND"
    assert mock.payloads and "[EMAIL_ADDRESS]" in mock.payloads[0]


def test_combining_public_and_confidential_is_blocked(store):
    result = execute(ToolRequest("external_report", "partner.example", ("public_summary", "private_forecast")),
                     store, RegexDemoRedactor(), MockTool(), enforce_policy=True)
    assert result.status == "BLOCKED"


@pytest.mark.parametrize("tool,recipient", [("shell", "partner.example"), ("external_report", "evil.example"), ("internal_report", "partner.example")])
def test_unknown_tool_or_destination_blocked(tool, recipient):
    assert not authorise(ToolRequest(tool, recipient, ("public_summary",)), Sensitivity.PUBLIC).permitted


def test_internal_reporting_for_confidential_is_allowed(store):
    result = execute(ToolRequest("internal_report", "intranet.example", ("private_forecast",)),
                     store, RegexDemoRedactor(), MockTool(), enforce_policy=True)
    assert result.status == "SIMULATED_SEND"


def test_missing_ids_denied_without_sending(store):
    mock = MockTool()
    result = execute(ToolRequest("external_report", "partner.example", ("not_found",)),
                     store, RegexDemoRedactor(), mock, enforce_policy=False)
    assert result.status == "BLOCKED" and mock.payloads == []


def test_empty_selection_denied(store):
    result = execute(ToolRequest("external_report", "partner.example", ()), store,
                     RegexDemoRedactor(), MockTool(), enforce_policy=True)
    assert result.status == "BLOCKED"


def test_presidio_integration_when_installed():
    pytest.importorskip("presidio_analyzer")
    pytest.importorskip("presidio_anonymizer")
    from agent_security.redaction import PresidioRedactor
    try:
        redactor = PresidioRedactor()
    except RuntimeError as exc:
        pytest.skip(str(exc))
    masked = redactor.redact("Contact customer@example.com about the FORECAST-SECRET-2030 forecast")
    assert "customer@example.com" not in masked
    assert "FORECAST-SECRET-2030" in masked
