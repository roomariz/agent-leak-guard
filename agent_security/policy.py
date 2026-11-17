"""Deterministic, fail-closed destination check. This is NOT complete IFC."""
from dataclasses import dataclass
from .models import Sensitivity, ToolRequest


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
