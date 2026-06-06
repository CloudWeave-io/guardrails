"""evaluate_policy — run every invariant, apply waivers, build the report."""

from __future__ import annotations

from datetime import date

from cw_guardrails.graph import Graph
from cw_guardrails.models import GuardrailReport, InvariantResult, Status, Violation
from cw_guardrails.policy import Policy, Waiver
from cw_guardrails.predicates import EVALUATORS, EvalContext
from cw_guardrails.selectors import resolve


def evaluate_policy(
    policy: Policy, graph: Graph, *, driver: object | None = None, account_id: str = ""
) -> GuardrailReport:
    ctx = EvalContext(groups=policy.groups, driver=driver, account_id=account_id)
    results: list[InvariantResult] = []

    for inv in policy.invariants:
        kind = inv.predicate_kind
        try:
            violations = EVALUATORS[kind](inv, graph, ctx)
        except Exception as exc:  # a bad predicate must not crash the whole run
            results.append(
                InvariantResult(
                    id=inv.id,
                    description=inv.description,
                    severity=inv.severity,
                    predicate=kind,
                    status=Status.ERROR,
                    violations=[Violation(message=f"evaluation error: {exc}")],
                )
            )
            continue

        active, waived = _apply_waivers(inv.id, violations, policy.waivers, graph, policy.groups)
        if active:
            status = Status.FAIL
        elif waived:
            status = Status.WAIVED
        else:
            status = Status.PASS
        results.append(
            InvariantResult(
                id=inv.id,
                description=inv.description,
                severity=inv.severity,
                predicate=kind,
                status=status,
                violations=active,
                waived=waived,
            )
        )

    return GuardrailReport(
        account_ids=policy.scope.accounts,
        regions=policy.scope.regions,
        graph_nodes=len(graph.nodes),
        graph_edges=len(graph.edges),
        results=results,
    )


def _apply_waivers(
    inv_id: str, violations: list[Violation], waivers: list[Waiver], graph: Graph, groups: dict
) -> tuple[list[Violation], list[Violation]]:
    relevant = [w for w in waivers if w.invariant == inv_id and _active(w)]
    if not relevant:
        return violations, []
    active: list[Violation] = []
    waived: list[Violation] = []
    for v in violations:
        match = next((w for w in relevant if _covers(w, v, graph, groups)), None)
        if match is not None:
            v.waiver_reason = match.reason or "waived"
            waived.append(v)
        else:
            active.append(v)
    return active, waived


def _active(waiver: Waiver) -> bool:
    if not waiver.expires:
        return True
    try:
        return date.today() <= date.fromisoformat(waiver.expires)
    except ValueError:
        return True  # malformed date -> don't silently drop the waiver


def _covers(waiver: Waiver, v: Violation, graph: Graph, groups: dict) -> bool:
    if waiver.target is None:
        return True  # whole-invariant waiver
    return v.resource in resolve(waiver.target, graph, groups)
