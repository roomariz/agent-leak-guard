"""Workflow with synthetic data and simulated tools; never sends HTTP/email."""
from dataclasses import dataclass
from .models import Document, Sensitivity, ToolRequest
from .policy import authorise
from .redaction import Redactor


@dataclass(frozen=True)
class Outcome:
    status: str
    reason: str
    email_present_in_payload: bool
    confidential_marker_present_in_payload: bool
    sent_to_mock: bool


class MockTool:
    """In-process receiver. Its contents never leave the Python process."""

    def __init__(self):
        self.payloads: list[str] = []

    def send(self, payload: str) -> None:
        self.payloads.append(payload)


class TrustedDocumentStore:
    def __init__(self, documents: tuple[Document, ...]):
        self._documents = {d.document_id: d for d in documents}

    def retrieve(self, ids: tuple[str, ...]) -> tuple[Document, ...]:
        return tuple(self._documents[doc_id] for doc_id in ids)


def execute(request: ToolRequest, store: TrustedDocumentStore, redactor: Redactor,
            receiver: MockTool, *, enforce_policy: bool) -> Outcome:
    """Tool request is untrusted; document labels come from trusted store."""
    try:
        records = store.retrieve(request.document_ids)
    except KeyError:
        return Outcome("BLOCKED", "unknown document ID (default deny)", False, False, False)
    if not records:
        return Outcome("BLOCKED", "empty document selection (default deny)", False, False, False)
    classification = max(doc.sensitivity for doc in records)
    if enforce_policy:
        decision = authorise(request, classification)
        if not decision.permitted:
            return Outcome("BLOCKED", decision.reason, False, False, False)
    # Redaction is always applied, even in the intentionally unsafe baseline.
    sanitized = redactor.redact("\n".join(doc.content for doc in records))
    receiver.send(sanitized)  # Simulated tool only; no real external transmission.
    return Outcome(
        status="SIMULATED_SEND",
        reason="tool call was not subject to destination policy" if not enforce_policy
               else "tool call permitted by policy",
        email_present_in_payload="customer@example.com" in sanitized,
        confidential_marker_present_in_payload="FORECAST-SECRET-2030" in sanitized,
        sent_to_mock=True,
    )


def demo_documents() -> tuple[Document, ...]:
    return (
        Document("public_summary", "Public quarterly outlook. Contact customer@example.com.", Sensitivity.PUBLIC),
        Document("private_forecast", "Internal forecast: FORECAST-SECRET-2030. Contact customer@example.com.", Sensitivity.CONFIDENTIAL),
    )
