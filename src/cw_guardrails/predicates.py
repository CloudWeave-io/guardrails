"""One evaluator per predicate kind -> list[Violation].

Each takes the invariant, the graph, and an EvalContext (groups + optional Neo4j
driver for cross-account questions). Pure over the graph wherever possible so the
same code runs over a Terraform-overlaid graph later.
"""

from __future__ import annotations

from dataclasses import dataclass

from cw_guardrails.graph import Graph
from cw_guardrails.models import Violation
from cw_guardrails.policy import Invariant, SelectorSpec
from cw_guardrails.reachability import (
    INTERNET,
    any_reach,
    egress_bypass,
    internet_facing,
)
from cw_guardrails.selectors import resolve

_WORLD = {"0.0.0.0/0", "::/0"}


@dataclass
class EvalContext:
    groups: dict[str, SelectorSpec]
    driver: object | None = None
    account_id: str = ""


def _name(graph: Graph, uid: str) -> str:
    return graph.nodes[uid].name if uid in graph.nodes else uid


def _resolve_nodes(selector: object, graph: Graph, groups: dict) -> set[str]:
    """Resolve a `select` to real graph-node uids, dropping the INTERNET sentinel and
    any phantom id. Posture predicates index graph.nodes directly, so a misconfigured
    rule (e.g. not_ingress with select: internet) must not KeyError — it just selects
    nothing."""
    return {u for u in resolve(selector, graph, groups) if u in graph.nodes}


def _ingress_desc(rule: dict) -> tuple[str, bool]:
    """Human description of an inbound rule + whether it is an all-traffic rule.
    The scanner encodes protocol -1 (all traffic) as port 0-0."""
    proto = str(rule.get("protocol", "") or "")
    fp, tp = int(rule.get("from_port", 0)), int(rule.get("to_port", 0))
    if proto in ("-1", "") or (fp, tp) == (0, 0):
        return "ALL traffic (every port and protocol)", True
    span = f"port {fp}" if fp == tp else f"ports {fp}-{tp}"
    return f"{proto} {span}", False


# ── posture ───────────────────────────────────────────────────────────────
def eval_not_ingress(inv: Invariant, graph: Graph, ctx: EvalContext) -> list[Violation]:
    spec = inv.not_ingress
    assert spec is not None
    ports = set(spec.ports)
    viols: list[Violation] = []
    for uid in _resolve_nodes(spec.select, graph, ctx.groups):
        for rule in graph.nodes[uid].inbound:
            if spec.from_ not in (rule.get("cidrs") or []):
                continue
            fp, tp = int(rule.get("from_port", 0)), int(rule.get("to_port", 0))
            hit = sorted(p for p in ports if fp <= p <= tp) if ports else [-1]
            if hit:
                desc, all_traffic = _ingress_desc(rule)
                matched = (
                    f" (matched port{'s' if len(hit) > 1 else ''} {', '.join(str(p) for p in hit)})"
                    if ports and not all_traffic
                    else ""
                )
                viols.append(
                    Violation(
                        resource=uid,
                        name=_name(graph, uid),
                        message=f"{_name(graph, uid)} allows {desc} from {spec.from_}{matched}",
                    )
                )
    return viols


def eval_property(inv: Invariant, graph: Graph, ctx: EvalContext) -> list[Violation]:
    spec = inv.property_
    assert spec is not None
    viols: list[Violation] = []
    for uid in _resolve_nodes(spec.select, graph, ctx.groups):
        val = graph.nodes[uid].props.get(spec.field)
        ok = True
        if spec.equals is not None:
            ok = str(val) == str(spec.equals)
        elif spec.in_ is not None:
            ok = str(val) in {str(x) for x in spec.in_}
        elif spec.matches is not None:
            import re

            ok = val is not None and re.search(spec.matches, str(val)) is not None
        if not ok:
            viols.append(
                Violation(
                    resource=uid,
                    name=_name(graph, uid),
                    message=f"{_name(graph, uid)}.{spec.field} = {val!r} violates the constraint",
                )
            )
    return viols


# ── reachability ────────────────────────────────────────────────────────────
def eval_not_public(inv: Invariant, graph: Graph, ctx: EvalContext) -> list[Violation]:
    spec = inv.not_public
    assert spec is not None
    facing = internet_facing(graph)
    return [
        Violation(
            resource=uid,
            name=_name(graph, uid),
            path=facing[uid],
            message=f"{graph.nodes[uid].type} '{_name(graph, uid)}' is reachable from the internet",
        )
        for uid in _resolve_nodes(spec.select, graph, ctx.groups)
        if uid in facing
    ]


def eval_not_in_public_subnet(inv: Invariant, graph: Graph, ctx: EvalContext) -> list[Violation]:
    spec = inv.not_in_public_subnet
    assert spec is not None
    viols: list[Violation] = []
    for uid in _resolve_nodes(spec.select, graph, ctx.groups):
        sub = graph.subnet_of.get(uid)
        if sub and sub in graph.public_subnets:
            viols.append(
                Violation(
                    resource=uid,
                    name=_name(graph, uid),
                    path=[sub, uid],
                    message=f"{graph.nodes[uid].type} '{_name(graph, uid)}' sits in public subnet "
                    f"{_name(graph, sub)} (routes to an Internet Gateway)",
                )
            )
    return viols


def eval_not_path(inv: Invariant, graph: Graph, ctx: EvalContext) -> list[Violation]:
    spec = inv.not_path
    assert spec is not None
    src_set = resolve(spec.from_, graph, ctx.groups)
    dst_set = resolve(spec.to, graph, ctx.groups)
    viols: list[Violation] = []
    for dst in dst_set - {INTERNET}:
        hit = any_reach(graph, src_set, {dst})
        if hit is not None:
            src, _d, path = hit
            # Name the concrete source that reached — that IS the evidence.
            src_desc = (
                "the internet"
                if src == INTERNET
                else f"{graph.nodes[src].type} '{_name(graph, src)}'"
                if src in graph.nodes
                else src
            )
            viols.append(
                Violation(
                    resource=dst,
                    name=_name(graph, dst),
                    path=path,
                    message=f"{graph.nodes[dst].type} '{_name(graph, dst)}' is reachable from {src_desc}",
                )
            )
    return viols


def eval_only_via(inv: Invariant, graph: Graph, ctx: EvalContext) -> list[Violation]:
    spec = inv.only_via
    assert spec is not None
    src_set = resolve(spec.from_, graph, ctx.groups)
    to_set = resolve(spec.to, graph, ctx.groups)
    through = resolve(spec.through, graph, ctx.groups)
    viols: list[Violation] = []
    if INTERNET in to_set:  # egress-to-internet-through-NAT pattern
        for uid, path in egress_bypass(graph, src_set, through):
            viols.append(
                Violation(
                    resource=uid,
                    name=_name(graph, uid),
                    path=path,
                    message=f"{_name(graph, uid)} egresses to the internet without passing the required gateway",
                )
            )
        return viols
    # generic chokepoint: a path that survives removing `through` is a bypass
    blocked = frozenset(through)
    for dst in to_set:
        hit = any_reach(graph, src_set, {dst}, blocked=blocked)
        if hit is not None:
            _s, _d, path = hit
            viols.append(
                Violation(
                    resource=dst,
                    name=_name(graph, dst),
                    path=path,
                    message=f"{_name(graph, dst)} is reachable without passing the required chokepoint",
                )
            )
    return viols


def eval_must_have(inv: Invariant, graph: Graph, ctx: EvalContext) -> list[Violation]:
    spec = inv.must_have
    assert spec is not None
    neighbors: dict[str, set[str]] = {}
    for s, d, _rel in graph.edges:
        neighbors.setdefault(s, set()).add(d)
        neighbors.setdefault(d, set()).add(s)
    viols: list[Violation] = []
    for uid in _resolve_nodes(spec.select, graph, ctx.groups):
        has = any(
            graph.nodes.get(n) and graph.nodes[n].type == spec.has
            for n in neighbors.get(uid, set())
        )
        if not has:
            viols.append(
                Violation(
                    resource=uid,
                    name=_name(graph, uid),
                    message=f"{graph.nodes[uid].type} '{_name(graph, uid)}' has no related {spec.has}",
                )
            )
    return viols


def eval_no_shared_tgw(inv: Invariant, graph: Graph, ctx: EvalContext) -> list[Violation]:
    spec = inv.no_shared_tgw
    assert spec is not None
    if ctx.driver is None:
        return []  # cross-account question needs Neo4j; skip in graph-only mode
    import re

    attach = {
        n.props.get("vpc_id"): n.props.get("tgw_id") for n in graph.by_type("TgwVpcAttachment")
    }
    viols: list[Violation] = []
    with ctx.driver.session() as s:  # type: ignore[attr-defined]
        for vpc in _resolve_nodes(spec.select, graph, ctx.groups):
            m = re.search(r"vpc-[0-9a-f]+", vpc)
            tgw = attach.get(graph.nodes[vpc].props.get("vpc_id")) or attach.get(
                m.group(0) if m else None
            )
            if not tgw:
                continue
            # "Shared with others" means accounts other than the VPC's OWN account —
            # not the run's first account, which is arbitrary in multi-account policies.
            own = graph.nodes[vpc].account or ctx.account_id
            others = sorted(
                {
                    r["a"]
                    for r in s.run(
                        "MATCH (x:TgwVpcAttachment {tgw_id:$t}) WHERE x.owner_account_id IS NOT NULL "
                        "RETURN DISTINCT x.owner_account_id AS a",
                        t=tgw,
                    )
                }
                - {own}
            )
            if others:
                viols.append(
                    Violation(
                        resource=vpc,
                        name=_name(graph, vpc),
                        message=f"VPC '{_name(graph, vpc)}' attaches to {tgw}, shared with {', '.join(others)}",
                    )
                )
    return viols


EVALUATORS = {
    "not_ingress": eval_not_ingress,
    "not_public": eval_not_public,
    "not_in_public_subnet": eval_not_in_public_subnet,
    "not_path": eval_not_path,
    "only_via": eval_only_via,
    "property": eval_property,
    "must_have": eval_must_have,
    "no_shared_tgw": eval_no_shared_tgw,
}
