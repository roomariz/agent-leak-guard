"""No actual LLM calls in the automated test suite."""
import json
from unittest.mock import patch
from io import BytesIO

import pytest

from agent_security.llm import (FixedTestProposer, OpenAICompatibleProposer,
                                ProposalError, validate_proposal)
from agent_security.models import ToolRequest
from agent_security.redaction import RegexDemoRedactor
from agent_security.workflow import MockTool, TrustedDocumentStore, demo_documents, execute


REQUEST = {"tool_name": "external_report", "recipient": "partner.example", "document_ids": ["private_forecast"]}


def test_valid_json_proposal():
    assert validate_proposal(REQUEST) == ToolRequest("external_report", "partner.example", ("private_forecast",))


@pytest.mark.parametrize("proposal", [
    {},
    {**REQUEST, "extra": "anything"},
    {**REQUEST, "document_ids": []},
    {**REQUEST, "document_ids": ["private_forecast", "private_forecast"]},
    {**REQUEST, "document_ids": ["no_such_doc"]},
    {**REQUEST, "tool_name": "shell"},
    {**REQUEST, "recipient": "attacker.example"},
    {**REQUEST, "document_ids": "private_forecast"},
])
def test_invalid_model_proposals_fail_closed(proposal):
    with pytest.raises(ProposalError):
        validate_proposal(proposal)


def test_reject_insecure_remote_endpoint():
    with pytest.raises(ValueError):
        OpenAICompatibleProposer(api_base="http://example.com/v1", model="demo")


def test_llm_proposal_is_reused_across_both_configs():
    proposer = FixedTestProposer(validate_proposal(REQUEST))
    request = proposer.propose("make a report")
    store = TrustedDocumentStore(demo_documents())
    unsafe_tool, safe_tool = MockTool(), MockTool()
    unsafe = execute(request, store, RegexDemoRedactor(), unsafe_tool, enforce_policy=False)
    safe = execute(request, store, RegexDemoRedactor(), safe_tool, enforce_policy=True)
    assert unsafe.status == "SIMULATED_SEND"
    assert unsafe.confidential_marker_present_in_payload
    assert not unsafe.email_present_in_payload
    assert safe.status == "BLOCKED"
    assert safe_tool.payloads == []


class FakeResponse:
    def __init__(self, value):
        self.stream = BytesIO(json.dumps(value).encode())
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, size): return self.stream.read(size)


def test_api_response_parsed_without_network():
    response = {"choices": [{"message": {"content": json.dumps(REQUEST)}}]}
    with patch("agent_security.llm.urlopen", return_value=FakeResponse(response)) as fake:
        llm = OpenAICompatibleProposer(api_base="https://api.example.com/v1", model="sample", api_key="test")
        proposed = llm.propose("Prepare an external partner report using the private_forecast document")
    assert proposed == validate_proposal(REQUEST)
    sent = fake.call_args.args[0]
    body = json.loads(sent.data)
    assert "FORECAST-SECRET-2030" not in json.dumps(body)
    assert "customer@example.com" not in json.dumps(body)
    assert sent.get_header("Authorization") == "Bearer test"


def test_malformed_api_result_rejected():
    response = {"choices": [{"message": {"content": "not JSON"}}]}
    with patch("agent_security.llm.urlopen", return_value=FakeResponse(response)):
        with pytest.raises(ProposalError):
            OpenAICompatibleProposer(api_base="https://api.example.com/v1", model="sample").propose("report")
