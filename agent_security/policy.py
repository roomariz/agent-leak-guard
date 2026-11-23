"""Deterministic, fail-closed destination check. This is NOT complete IFC."""
from dataclasses import dataclass
from typing import Any
from .models import (
    FieldSensitivity, FieldSpec, Sensitivity, StructuredToolRequest, ToolRequest,
)


@dataclass(frozen=True)
class Decision:
    permitted: bool
    reason: str


# Demonstration policy is trusted application configuration.
# Public data may go to an approved external summary endpoint.
# Any classified data may go to an approved internal report tool only.
APPROVED_DESTINATIONS = {
    "external_report": frozenset({"partner.example"}),
    "internal_report": frozenset({"intranet.example"}),
}


def authorise(request: ToolRequest, sensitivity: Sensitivity) -> Decision:
    allowed = APPROVED_DESTINATIONS.get(request.tool_name)
    if allowed is None:
        return Decision(False, "unknown tool (default deny)")
    if request.recipient not in allowed:
        return Decision(False, "recipient is not on this tool's trusted allowlist")
    if request.tool_name == "external_report" and sensitivity > Sensitivity.PUBLIC:
        return Decision(False, "classified source information cannot use external_report")
    return Decision(True, "trusted tool, recipient and information classification")


# ---------------------------------------------------------------------------
# Configuration C: attribute-level policies
# ---------------------------------------------------------------------------

# Schema for the synthetic customer records returned by the mock database tool.
# Assigned by trusted application configuration, not the LLM.
CUSTOMER_RECORD_SCHEMA: dict[str, FieldSpec] = {
    "customer_id":    FieldSpec("customer_id",    FieldSensitivity.INTERNAL,     is_pii=False),
    "name":           FieldSpec("name",           FieldSensitivity.RESTRICTED,   is_pii=True),
    "email":          FieldSpec("email",          FieldSensitivity.RESTRICTED,   is_pii=True),
    "phone":          FieldSpec("phone",          FieldSensitivity.RESTRICTED,   is_pii=True),
    "account_tier":   FieldSpec("account_tier",   FieldSensitivity.PUBLIC,       is_pii=False),
    "account_status": FieldSpec("account_status", FieldSensitivity.INTERNAL,     is_pii=False),
    "credit_limit":   FieldSpec("credit_limit",   FieldSensitivity.CONFIDENTIAL, is_pii=False),
    "credit_score":   FieldSpec("credit_score",   FieldSensitivity.CONFIDENTIAL, is_pii=False),
    "notes":          FieldSpec("notes",          FieldSensitivity.INTERNAL,     is_pii=False),
    "join_date":      FieldSpec("join_date",      FieldSensitivity.PUBLIC,       is_pii=False),
}

# Per-tool, per-recipient field allowlists.
# Maps (tool_name, recipient) -> frozenset of allowed field names.
# Default deny: any field not listed here is blocked regardless of its sensitivity label.
FIELD_ALLOWLISTS: dict[tuple[str, str], frozenset[str]] = {
    ("customer_lookup", "intranet.example"): frozenset({
        "customer_id", "name", "email", "phone", "account_tier", "account_status",
        "notes", "join_date",
    }),
    ("customer_summary", "partner.example"): frozenset({
        "customer_id", "account_tier", "join_date",
    }),
}

# Per-tool, per-recipient permitted actions.
PERMITTED_ACTIONS: dict[tuple[str, str], frozenset[str]] = {
    ("customer_lookup", "intranet.example"): frozenset({"lookup", "list"}),
    ("customer_summary", "partner.example"): frozenset({"summary"}),
}


@dataclass(frozen=True)
class AttributeDecision:
    permitted: bool
    reason: str
    allowed_fields: frozenset[str]  # Empty when not permitted.
    blocked_fields: frozenset[str]  # Fields that were requested but not permitted.


def authorise_structured(
    request: StructuredToolRequest,
    requested_fields: frozenset[str],
) -> AttributeDecision:
    """
    Deterministic attribute-level authorisation for Configuration C.

    Checks in order:
      1. Tool is known and destination is approved.
      2. Action is permitted for this tool+destination pair.
      3. Each requested field is in the allowlist for this tool+destination.
      4. No CONFIDENTIAL fields are requested (absolute block).

    Returns an AttributeDecision with the intersection of requested and allowed
    fields, or a deny decision with an explanation.
    """
    key = (request.tool_name, request.recipient)

    # 1. Tool and destination check
    if request.tool_name not in {t for t, _ in FIELD_ALLOWLISTS}:
        return AttributeDecision(False, "unknown tool (default deny)", frozenset(), requested_fields)
    allowlist = FIELD_ALLOWLISTS.get(key)
    if allowlist is None:
        return AttributeDecision(False, "recipient not approved for this tool (default deny)",
                                 frozenset(), requested_fields)

    # 2. Action check
    permitted_actions = PERMITTED_ACTIONS.get(key, frozenset())
    if request.action not in permitted_actions:
        return AttributeDecision(False,
                                 f"action '{request.action}' not permitted for this tool+destination",
                                 frozenset(), requested_fields)

    # 3. Field-level check: start from the allowlist, then remove CONFIDENTIAL
    #    and unrecognised fields regardless of what the LLM proposed.
    known_fields = frozenset(CUSTOMER_RECORD_SCHEMA)
    confidential_fields = frozenset(
        name for name, spec in CUSTOMER_RECORD_SCHEMA.items()
        if spec.sensitivity == FieldSensitivity.CONFIDENTIAL
    )

    # Unknown fields are always blocked (default deny for unlisted schema fields)
    unknown_requested = requested_fields - known_fields
    # Fields that are known but not in the allowlist for this endpoint
    not_in_allowlist = (requested_fields & known_fields) - allowlist
    # Confidential fields (absolute block even if somehow in allowlist)
    confidential_requested = requested_fields & confidential_fields

    blocked = unknown_requested | not_in_allowlist | confidential_requested
    effective_allowed = requested_fields - blocked

    if not effective_allowed:
        return AttributeDecision(
            False,
            "no permitted fields remain after applying allowlist and confidentiality rules",
            frozenset(), blocked,
        )

    return AttributeDecision(True, "tool, destination, action and fields authorised",
                             effective_allowed, blocked)


def _filter_value(val: Any, confidential: frozenset[str]) -> Any:
    """Recursively filter nested dictionaries and lists to strip confidential fields."""
    if isinstance(val, dict):
        return {
            k: _filter_value(v, confidential)
            for k, v in val.items()
            if k not in confidential
        }
    elif isinstance(val, (list, tuple)):
        filtered_items = [_filter_value(item, confidential) for item in val]
        return type(val)(filtered_items)
    return val


def filter_record_fields(
    record_fields: dict[str, Any],
    allowed_fields: frozenset[str],
) -> dict[str, Any]:
    """
    Tool output filter: return only fields in the agent's authorised scope.
    Fields not in allowed_fields are silently removed (default deny).
    Fields not present in the record are ignored.
    CONFIDENTIAL fields are always blocked regardless of allowed_fields,
    even when nested inside allowed dictionary or list structures.
    """
    confidential = frozenset(
        name for name, spec in CUSTOMER_RECORD_SCHEMA.items()
        if spec.sensitivity == FieldSensitivity.CONFIDENTIAL
    )
    # Intersect with allowed_fields and exclude confidential as a belt-and-suspenders guard.
    safe_allowed = allowed_fields - confidential
    return {
        k: _filter_value(v, confidential)
        for k, v in record_fields.items()
        if k in safe_allowed
    }
