"""Trusted, server-owned labels and immutable records."""
from dataclasses import dataclass
from enum import IntEnum


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
