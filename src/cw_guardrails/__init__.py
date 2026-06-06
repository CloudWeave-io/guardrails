"""CloudWeave Guardrails — architecture invariants verified against the live graph.

Public API:
    evaluate_guardrails(policy_bytes, account_ids, regions, neo4j_driver) -> GuardrailReport
    load_policy(text|bytes) -> Policy
"""

from cw_guardrails.entry import evaluate_guardrails
from cw_guardrails.models import GuardrailReport, InvariantResult, Severity, Violation
from cw_guardrails.policy import Policy, load_policy

__all__ = [
    "evaluate_guardrails",
    "load_policy",
    "Policy",
    "GuardrailReport",
    "InvariantResult",
    "Violation",
    "Severity",
]
