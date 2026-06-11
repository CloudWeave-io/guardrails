"""Library entrypoint: fetch the graph and evaluate a policy against it."""

from __future__ import annotations

from cw_guardrails.diff import annotate_new
from cw_guardrails.engine import evaluate_policy
from cw_guardrails.graph import Graph, build_indexes, fetch_graph
from cw_guardrails.models import GuardrailReport
from cw_guardrails.overlay import OverlayResult, overlay_plan
from cw_guardrails.policy import Policy, load_policy


def evaluate_guardrails(
    policy_source: str | bytes | Policy,
    *,
    neo4j_driver: object,
    account_ids: list[str] | None = None,
    regions: list[str] | None = None,
) -> GuardrailReport:
    """Load a policy, fetch the (multi-account) graph, and evaluate.

    `account_ids` / `regions` override the policy's `scope` when provided.
    """
    policy = policy_source if isinstance(policy_source, Policy) else load_policy(policy_source)
    # Accounts to FETCH = an explicit override or the policy scope, ALWAYS unioned with
    # every rule's own accounts. So per-rule scoping drives the fetch on its own, and a
    # rule's accounts are always loaded even if the (optional) policy scope omits them.
    # Which accounts each rule actually *evaluates* against is handled per-rule in
    # evaluate_policy (isolated subgraphs); this only decides what to pull from Neo4j.
    rule_accounts = {a for inv in policy.invariants for a in inv.accounts}
    base = set(account_ids or policy.scope.accounts)
    accounts = sorted(base | rule_accounts)
    regions = regions if regions is not None else policy.scope.regions
    if not accounts:
        raise ValueError("no accounts to evaluate: set policy.scope.accounts or pass account_ids")

    graph = _fetch_merged(neo4j_driver, accounts, regions)
    return evaluate_policy(policy, graph, driver=neo4j_driver, account_id=accounts[0])


def evaluate_guardrails_with_plan(
    policy_source: str | bytes | Policy,
    *,
    neo4j_driver: object,
    plan: dict,
    account_ids: list[str] | None = None,
    regions: list[str] | None = None,
) -> tuple[GuardrailReport, OverlayResult]:
    """The PR gate: evaluate the live graph (baseline), overlay the Terraform
    plan, evaluate the would-be world, and annotate which violations are NEW.

    Returns the annotated AFTER report + the overlay result (mapped counts,
    unmapped types, planned uids) for surfacing in CI output.
    """
    policy = policy_source if isinstance(policy_source, Policy) else load_policy(policy_source)
    rule_accounts = {a for inv in policy.invariants for a in inv.accounts}
    base = set(account_ids or policy.scope.accounts)
    accounts = sorted(base | rule_accounts)
    regions = regions if regions is not None else policy.scope.regions
    if not accounts:
        raise ValueError("no accounts to evaluate: set policy.scope.accounts or pass account_ids")

    graph = _fetch_merged(neo4j_driver, accounts, regions)
    baseline = evaluate_policy(policy, graph, driver=neo4j_driver, account_id=accounts[0])
    overlaid = overlay_plan(graph, plan, account=accounts[0])
    after = evaluate_policy(policy, overlaid.graph, driver=neo4j_driver, account_id=accounts[0])
    return annotate_new(baseline, after), overlaid


def _fetch_merged(driver, accounts: list[str], regions: list[str]) -> Graph:
    if len(accounts) == 1:
        return fetch_graph(driver, accounts[0], regions)
    merged = Graph()
    for acct in accounts:
        sub = fetch_graph(driver, acct, regions)
        merged.nodes.update(sub.nodes)
        merged.edges.extend(sub.edges)
    # de-dup edges and rebuild indexes over the union
    merged.edges = list({(s, d, r) for (s, d, r) in merged.edges})
    build_indexes(merged)
    return merged
