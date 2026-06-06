"""Library entrypoint: fetch the graph and evaluate a policy against it."""

from __future__ import annotations

from cw_guardrails.engine import evaluate_policy
from cw_guardrails.graph import Graph, build_indexes, fetch_graph
from cw_guardrails.models import GuardrailReport
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
    accounts = account_ids or policy.scope.accounts
    regions = regions if regions is not None else policy.scope.regions
    if not accounts:
        raise ValueError("no accounts to evaluate: set policy.scope.accounts or pass account_ids")

    graph = _fetch_merged(neo4j_driver, accounts, regions)
    return evaluate_policy(policy, graph, driver=neo4j_driver, account_id=accounts[0])


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
