"""
Final-response guard for Configuration C.

Checks an agent-generated text response for:
  - Recognised PII patterns (email, phone, SSN, credit-card-like sequences).
  - Restricted business information (synthetic confidential markers).
  - Explicit field values known to be CONFIDENTIAL from the trusted schema.

This is a DETERMINISTIC complement to tool-boundary enforcement. It is not a
complete information-flow-control system and cannot guarantee that all sensitive
information is detected. PII detection based on patterns will miss novel formats.

Policy decisions are made without logging raw sensitive values.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .models import FieldSensitivity, CustomerRecord
from .policy import CUSTOMER_RECORD_SCHEMA


# ---------------------------------------------------------------------------
# Pattern-based PII detectors (deterministic; supplements Presidio or regex-demo)
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(
    r"""(?x)
    (?:\+?1[\s\-.]?)?          # optional country code
    (?:\(\d{3}\)|\d{3})        # area code
    [\s\-.]?\d{3}[\s\-.]?\d{4} # rest of number
    """
)
_SSN_RE = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")
# Card-like: 13–16 consecutive digits (not perfect, avoids false positives via context)
_CARD_RE = re.compile(r"\b(?:\d[\s\-]?){13,16}\b")

# Synthetic confidential business markers used in the demonstration mapped to safe labels.
# In a real application this would be a configurable external list.
_BUSINESS_MARKERS: dict[str, str] = {
    "FORECAST-SECRET-2030": "BUSINESS_MARKER_FORECAST_SECRET",
    "CREDIT-LIMIT-INTERNAL": "BUSINESS_MARKER_CREDIT_LIMIT",
    "SCORE-INTERNAL": "BUSINESS_MARKER_SCORE",
}


@dataclass(frozen=True)
class ResponseGuardResult:
    permitted: bool
    reason: str                      # Safe decision label; never contains raw values.
    pii_patterns_found: list[str]    # Pattern type names, not matched text.
    business_markers_found: list[str]  # Marker type names, not raw values.
    confidential_field_names_found: list[str]  # Field names only, not values.


def _detect_pii_patterns(text: str) -> list[str]:
    """Return a list of PII pattern type names found in text, without logging values."""
    found = []
    if _EMAIL_RE.search(text):
        found.append("EMAIL_ADDRESS")
    if _PHONE_RE.search(text):
        found.append("PHONE_NUMBER")
    if _SSN_RE.search(text):
        found.append("SSN")
    if _CARD_RE.search(text):
        found.append("CARD_NUMBER_PATTERN")
    return found


def _detect_business_markers(text: str) -> list[str]:
    """Return marker type labels, never raw secret marker tokens."""
    found = []
    for marker, label in _BUSINESS_MARKERS.items():
        if marker in text:
            found.append(label)
    return found


def _get_nested_values(val: Any) -> list[Any]:
    vals = [val]
    if isinstance(val, dict):
        for v in val.values():
            vals.extend(_get_nested_values(v))
    elif isinstance(val, (list, tuple)):
        for item in val:
            vals.extend(_get_nested_values(item))
    return vals


def _extract_field_values_from_record(fields: dict[str, Any], target_field: str) -> list[Any]:
    found = []
    if target_field in fields:
        found.extend(_get_nested_values(fields[target_field]))
    for v in fields.values():
        if isinstance(v, dict):
            found.extend(_extract_field_values_from_record(v, target_field))
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, dict):
                    found.extend(_extract_field_values_from_record(item, target_field))
    return found


def _candidate_representations(value: Any) -> list[str]:
    reps = []
    if value is None:
        return reps
    str_val = str(value)
    if len(str_val) >= 3:
        reps.append(str_val)
    if isinstance(value, (int, float)):
        try:
            formatted = f"{int(value):,}"
            if formatted != str_val and len(formatted) >= 3:
                reps.append(formatted)
        except (ValueError, OverflowError):
            pass
    return reps


def _detect_confidential_field_values(
    text: str,
    confidential_records: list[CustomerRecord],
    *,
    recipient: str | None = None,
    tool_name: str | None = None,
) -> list[str]:
    """
    Check whether any CONFIDENTIAL or recipient-disallowed field value from
    the records appears in the response. Return field names, not values.
    """
    from .policy import FIELD_ALLOWLISTS
    confidential_field_names = {
        name for name, spec in CUSTOMER_RECORD_SCHEMA.items()
        if spec.sensitivity == FieldSensitivity.CONFIDENTIAL
    }
    allowed_for_recipient = None
    if recipient:
        key = (tool_name, recipient) if tool_name else None
        allowed_for_recipient = FIELD_ALLOWLISTS.get(key) if key else None
        if allowed_for_recipient is None:
            relevant = [fields for (t, r), fields in FIELD_ALLOWLISTS.items() if r == recipient]
            if relevant:
                allowed_for_recipient = frozenset.union(*relevant)

    found_field_names: list[str] = []
    for record in confidential_records:
        for fname, spec in CUSTOMER_RECORD_SCHEMA.items():
            is_confidential = fname in confidential_field_names
            is_unauthorized_for_recipient = (
                allowed_for_recipient is not None and fname not in allowed_for_recipient
            )
            if is_confidential or is_unauthorized_for_recipient:
                values = _extract_field_values_from_record(record.fields, fname)
                for val in values:
                    for rep in _candidate_representations(val):
                        if rep in text:
                            if fname not in found_field_names:
                                found_field_names.append(fname)
                            break
    return found_field_names


def check_response(
    response_text: str,
    *,
    confidential_records: list[CustomerRecord] | None = None,
    records: list[CustomerRecord] | None = None,
    recipient: str | None = None,
    tool_name: str | None = None,
    policy: str = "redact_or_block",
) -> ResponseGuardResult:
    """
    Validate an agent-generated text response before displaying it.

    policy values:
      "redact_or_block"  – block if any restricted content is detected.
      "warn_only"        – report findings without blocking (for testing).

    Returns a ResponseGuardResult. The caller decides how to handle blocking.
    Raw values are never stored in the result or logged here.
    """
    if not isinstance(response_text, str):
        return ResponseGuardResult(
            False, "response is not a string", [], [], []
        )
    all_records = list(confidential_records or [])
    if records:
        for r in records:
            if r not in all_records:
                all_records.append(r)

    pii_found = _detect_pii_patterns(response_text)
    markers_found = _detect_business_markers(response_text)
    conf_fields = _detect_confidential_field_values(
        response_text,
        all_records,
        recipient=recipient,
        tool_name=tool_name,
    )

    any_problem = bool(pii_found or markers_found or conf_fields)

    if policy == "warn_only":
        return ResponseGuardResult(
            True,
            "warn_only mode: findings recorded but not blocked",
            pii_found, markers_found, conf_fields,
        )

    if any_problem:
        return ResponseGuardResult(
            False,
            "response blocked: contains PII patterns, restricted business markers "
            "or confidential field values",
            pii_found, markers_found, conf_fields,
        )

    return ResponseGuardResult(True, "response passed all checks", [], [], [])


def redact_response(
    response_text: str,
    *,
    confidential_records: list[CustomerRecord] | None = None,
    records: list[CustomerRecord] | None = None,
    recipient: str | None = None,
    tool_name: str | None = None,
) -> str:
    """
    Apply pattern-based redaction to a response string.
    If records are provided, also masks confidential and recipient-disallowed field values.
    Returns a sanitised copy; original is not modified.
    """
    from .policy import FIELD_ALLOWLISTS
    text = _EMAIL_RE.sub("[EMAIL_ADDRESS]", response_text)
    text = _PHONE_RE.sub("[PHONE_NUMBER]", text)
    text = _SSN_RE.sub("[SSN]", text)
    for marker in _BUSINESS_MARKERS:
        text = text.replace(marker, "[RESTRICTED_MARKER]")

    all_records = list(confidential_records or [])
    if records:
        for r in records:
            if r not in all_records:
                all_records.append(r)

    if all_records:
        confidential_field_names = {
            name for name, spec in CUSTOMER_RECORD_SCHEMA.items()
            if spec.sensitivity == FieldSensitivity.CONFIDENTIAL
        }
        allowed_for_recipient = None
        if recipient:
            key = (tool_name, recipient) if tool_name else None
            allowed_for_recipient = FIELD_ALLOWLISTS.get(key) if key else None
            if allowed_for_recipient is None:
                relevant = [fields for (t, r), fields in FIELD_ALLOWLISTS.items() if r == recipient]
                if relevant:
                    allowed_for_recipient = frozenset.union(*relevant)

        for record in all_records:
            for fname, spec in CUSTOMER_RECORD_SCHEMA.items():
                is_confidential = fname in confidential_field_names
                is_unauthorized_for_recipient = (
                    allowed_for_recipient is not None and fname not in allowed_for_recipient
                )
                if is_confidential or is_unauthorized_for_recipient:
                    values = _extract_field_values_from_record(record.fields, fname)
                    for val in values:
                        for rep in _candidate_representations(val):
                            if rep in text:
                                text = text.replace(rep, f"[REDACTED_{fname.upper()}]")
    return text
