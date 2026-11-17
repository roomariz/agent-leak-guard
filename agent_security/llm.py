"""LLM tool-call proposal. Model input contains no document contents or real secrets.

A model proposes *untrusted* structured arguments; Python independently resolves
trusted classifications and checks destinations before a local mock send.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse, quote
import re
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from .models import ToolRequest

MAX_RESPONSE_BYTES = 32_768
MAX_DOCUMENT_IDS = 8

class ProposalError(Exception):
    """A model proposal could not be safely parsed or validated."""

class Proposer(Protocol):
    def propose(self, user_request: str) -> ToolRequest: ...


SYSTEM_PROMPT = """You select a tool request for a LOCAL SECURITY DEMONSTRATION.
Return ONLY a JSON object with exactly three keys:
  {"tool_name": "external_report" or "internal_report",
   "recipient": "partner.example" or "intranet.example",
   "document_ids": ["public_summary" and/or "private_forecast"]}
Available documents are synthetic and are referenced ONLY by ID:
- public_summary: public quarterly outlook
- private_forecast: confidential internal forecast
Do not attempt to retrieve the documents. You cannot read their contents.
The user asks you to propose a tool call, not to execute it.
Choose a tool, destination and document ID(s) matching the user request.
Do not include any additional text, markdown, fields or invented identifiers.
The host application, not you, decides if the proposed call is authorised.
"""


def validate_proposal(raw: object) -> ToolRequest:
    """Fail closed for malformed or unexpected model output."""
    if not isinstance(raw, dict) or set(raw) != {"tool_name", "recipient", "document_ids"}:
        raise ProposalError("proposal must contain exactly tool_name, recipient and document_ids")
    tool, recipient, ids = raw["tool_name"], raw["recipient"], raw["document_ids"]
    if not isinstance(tool, str) or not isinstance(recipient, str):
        raise ProposalError("tool_name and recipient must be strings")
    if not isinstance(ids, list) or not (1 <= len(ids) <= MAX_DOCUMENT_IDS):
        raise ProposalError("document_ids must be a nonempty bounded list")
    if any(not isinstance(doc, str) for doc in ids):
        raise ProposalError("document_ids must contain only strings")
    if len(set(ids)) != len(ids):
        raise ProposalError("duplicate document IDs are not accepted")
    if tool not in {"external_report", "internal_report"}:
        raise ProposalError("unknown tool")
    if recipient not in {"partner.example", "intranet.example"}:
        raise ProposalError("unknown recipient")
    if any(doc not in {"public_summary", "private_forecast"} for doc in ids):
        raise ProposalError("unknown document ID")
    return ToolRequest(tool, recipient, tuple(ids))


@dataclass(frozen=True)
class FixedTestProposer:
    """Deterministic stand-in for tests. It is NOT an LLM."""
    request: ToolRequest

    def propose(self, user_request: str) -> ToolRequest:
        return self.request


class OpenAICompatibleProposer:
    """One OpenAI-compatible /chat/completions request using Python stdlib.

    Compatible with OpenAI, OpenRouter and local OpenAI-compatible endpoints.
    Model only receives synthetic document IDs and an explicit demonstration request.
    """
    def __init__(self, *, api_base: str, model: str, api_key: str | None = None,
                 timeout: float = 30.0) -> None:
        parsed = urlparse(api_base)
        if not (parsed.scheme == "https" or (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        )):
            raise ValueError("API base must be HTTPS or HTTP on localhost")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("API base may not include credentials, query strings or fragments")
        if not model.strip():
            raise ValueError("model must be nonempty")
        self.api_url = api_base.rstrip("/") + "/chat/completions"
        self.model = model
        self.api_key = api_key or os.getenv("LLM_API_KEY") or ""
        self.timeout = timeout

    def propose(self, user_request: str) -> ToolRequest:
        if not user_request or len(user_request) > 1000:
            raise ProposalError("demo request must contain 1–1000 characters")
        payload = {
            "model": self.model,
            "temperature": 0,
            "max_tokens": 180,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_request},
            ],
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = Request(self.api_url, data=json.dumps(payload).encode("utf-8"),
                      headers=headers, method="POST")
        try:
            with urlopen(req, timeout=self.timeout) as response:
                content = response.read(MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise ProposalError(f"LLM request failed ({type(exc).__name__}); no tool executed") from exc
        if len(content) > MAX_RESPONSE_BYTES:
            raise ProposalError("LLM response too large")
        try:
            decoded = json.loads(content)
            message = decoded["choices"][0]["message"]
            text = message["content"]
            if not isinstance(text, str):
                raise ValueError("model did not return text")
            return validate_proposal(json.loads(text))
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            raise ProposalError("LLM response was not valid constrained JSON; no tool executed") from exc


class GoogleGeminiProposer:
    """Google Gemini API adapter using Google's documented generateContent REST API.

    No third-party SDK required. Only the synthetic user task and the approved
    document IDs in SYSTEM_PROMPT are transmitted. The returned JSON remains
    untrusted until validated by validate_proposal(). The API does not execute tools.
    """
    def __init__(self, *, model: str, api_key: str | None = None,
                 timeout: float = 30.0) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", model):
            raise ValueError("invalid Gemini model ID")
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or ""
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY (or GOOGLE_API_KEY) is required for Google Gemini")
        self.model = model
        self.api_url = ("https://generativelanguage.googleapis.com/v1beta/models/"
                        + quote(model, safe="") + ":generateContent")
        self.timeout = timeout

    def propose(self, user_request: str) -> ToolRequest:
        if not user_request or len(user_request) > 1000:
            raise ProposalError("demo request must contain 1–1000 characters")
        payload = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": user_request}]}],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": 512,
                "responseMimeType": "application/json",
            },
        }
        req = Request(
            self.api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "x-goog-api-key": self.api_key,
            },
            method="POST",
        )
        try:
            with urlopen(req, timeout=self.timeout) as response:
                content = response.read(MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError) as exc:
            # Do not expose the provider's response body or credentials.
            raise ProposalError(
                f"Gemini request failed ({type(exc).__name__}); no tool executed"
            ) from None
        if len(content) > MAX_RESPONSE_BYTES:
            raise ProposalError("Gemini response too large")
        try:
            decoded = json.loads(content)
            parts = decoded["candidates"][0]["content"]["parts"]
            if not isinstance(parts, list) or len(parts) != 1:
                raise ValueError("unexpected Gemini response parts")
            text = parts[0]["text"]
            if not isinstance(text, str):
                raise ValueError("Gemini did not return text")
            return validate_proposal(json.loads(text))
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            raise ProposalError("Gemini response was not valid tool-request JSON; no tool executed") from None
