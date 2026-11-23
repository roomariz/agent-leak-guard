"""Trusted, server-owned labels and immutable records."""
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Sensitivity(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2


@dataclass(frozen=True)
class Document:
    document_id: str
    content: str
    sensitivity: Sensitivity  # Set by trusted data store, not by LLM or source text.


@dataclass(frozen=True)
class ToolRequest:
    tool_name: str
    recipient: str
    document_ids: tuple[str, ...]


# ---------------------------------------------------------------------------
# Configuration C: structured customer/business records with field labels
# ---------------------------------------------------------------------------

class FieldSensitivity(IntEnum):
    """Per-field sensitivity, independent of the record's document classification."""
    PUBLIC = 0
    INTERNAL = 1
    RESTRICTED = 2   # Must not be disclosed outside approved internal recipients.
    CONFIDENTIAL = 3  # Must never leave the system under any configured policy.


@dataclass(frozen=True)
class FieldSpec:
    """Trusted field descriptor: name, sensitivity label, and optional PII flag."""
    name: str
    sensitivity: FieldSensitivity
    is_pii: bool = False


@dataclass(frozen=True)
class CustomerRecord:
    """
    Synthetic customer record returned by a mock database tool.
    Fields are classified by trusted application configuration; the LLM cannot
    alter these labels or request fields by sensitivity level.
    """
    record_id: str
    # All field values stored together; controlled access is enforced by policy,
    # not by hiding them from Python.  Real values never leave the process.
    fields: dict[str, Any]

    def __hash__(self) -> int:  # required because fields is a dict
        return hash(self.record_id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CustomerRecord):
            return NotImplemented
        return self.record_id == other.record_id and self.fields == other.fields


@dataclass(frozen=True)
class StructuredToolRequest:
    """
    Configuration C tool proposal: also carries the requested action and
    the set of fields the agent wants to retrieve or share.

    All three are UNTRUSTED model output validated before use.
    """
    tool_name: str
    action: str
    recipient: str
    record_ids: tuple[str, ...]
    requested_fields: tuple[str, ...]  # LLM-proposed; enforced against allowlist.
