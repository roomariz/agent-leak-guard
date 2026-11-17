"""Mocked Gemini REST tests. No real Google credentials or network calls."""
import json
from io import BytesIO
from unittest.mock import patch

import pytest

from agent_security.llm import GoogleGeminiProposer, ProposalError, validate_proposal
from agent_security.redaction import RegexDemoRedactor
from agent_security.workflow import TrustedDocumentStore, MockTool, demo_documents, execute


REQUEST = {"tool_name": "external_report", "recipient": "partner.example", "document_ids": ["private_forecast"]}


class FakeResponse:
    def __init__(self, body):
        self.stream = BytesIO(json.dumps(body).encode("utf-8"))
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, size): return self.stream.read(size)


def gemini_response(obj):
    return {"candidates": [{"content": {"parts": [{"text": json.dumps(obj)}]}}]}


def test_google_parse_and_send_only_synthetic_metadata():
    with patch("agent_security.llm.urlopen", return_value=FakeResponse(gemini_response(REQUEST))) as mocked:
        proposer = GoogleGeminiProposer(model="gemini-2.5-flash", api_key="test-key")
        request = proposer.propose("Prepare an external partner report using the private_forecast document")
    assert request == validate_proposal(REQUEST)
    sent = mocked.call_args.args[0]
    assert sent.full_url == "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    assert sent.get_header("X-goog-api-key") == "test-key"
    body = json.loads(sent.data)
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert "FORECAST-SECRET-2030" not in json.dumps(body)
    assert "customer@example.com" not in json.dumps(body)
    assert body["contents"][0]["role"] == "user"
    assert body["systemInstruction"]["parts"][0]["text"]


def test_google_same_proposal_can_be_blocked_by_policy():
    with patch("agent_security.llm.urlopen", return_value=FakeResponse(gemini_response(REQUEST))):
        proposed = GoogleGeminiProposer(model="gemini-2.5-flash", api_key="dummy").propose("external report")
    store = TrustedDocumentStore(demo_documents())
    baseline_tool, safe_tool = MockTool(), MockTool()
    unsafe = execute(proposed, store, RegexDemoRedactor(), baseline_tool, enforce_policy=False)
    safe = execute(proposed, store, RegexDemoRedactor(), safe_tool, enforce_policy=True)
    assert unsafe.status == "SIMULATED_SEND"
    assert unsafe.confidential_marker_present_in_payload
    assert not unsafe.email_present_in_payload
    assert safe.status == "BLOCKED"
    assert safe_tool.payloads == []


@pytest.mark.parametrize("bad", [
    {"candidates": []},
    {"candidates": [{"content": {"parts": []}}]},
    {"candidates": [{"content": {"parts": [{"text": "not-json"}]}}]},
    gemini_response({**REQUEST, "recipient": "attacker.example"}),
    gemini_response({**REQUEST, "tool_name": "shell"}),
])
def test_google_rejects_invalid_outputs(bad):
    with patch("agent_security.llm.urlopen", return_value=FakeResponse(bad)):
        with pytest.raises(ProposalError):
            GoogleGeminiProposer(model="gemini-2.5-flash", api_key="dummy").propose("report")


def test_google_api_key_required(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(ValueError):
        GoogleGeminiProposer(model="gemini-2.5-flash")


def test_google_model_path_validation():
    with pytest.raises(ValueError):
        GoogleGeminiProposer(model="../../evil", api_key="dummy")
