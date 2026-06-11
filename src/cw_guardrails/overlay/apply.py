"""Apply a parsed Terraform plan onto a (deep-copied) graph.

Order matters:
  1. deletes (and the delete half of replaces) — binds via change.before
  2. reindex literal-id lookups over the mutated copy
  3. build all create/fold deltas (references resolve via the created-address map)
  4. add nodes, then folds + edges (an edge applies only when both ends exist)
  5. in-place updates (node identity preserved → stable baseline-diff keys)
  6. rebuild the derived indexes — public subnets, containment, SG folding and
     the VPC union-find all recompute over the merged world for free.
"""

from __future__ import annotations

import copy
from collections import Counter
from dataclasses import dataclass, field

from cw_guardrails.graph import Graph, build_indexes
from cw_guardrails.overlay.mapping import (
    BUILDERS,
    FOLD_TYPES,
    UPDATE_SCALAR_PROPS,
    BuildContext,
    Delta,
    sg_rule,
)
from cw_guardrails.overlay.plan import ResourceChange, parse_plan
from cw_guardrails.overlay.resolve import Resolver


@dataclass
class OverlayResult:
    graph: Graph
    mapped: int = 0
    unmapped_types: list[str] = field(default_factory=list)
    planned_uids: set[str] = field(default_factory=set)


def _dominant(graph: Graph, attr: str) -> str | None:
    counts = Counter(getattr(n, attr) for n in graph.nodes.values() if getattr(n, attr) is not None)
    return counts.most_common(1)[0][0] if counts else None


def overlay_plan(
    base: Graph, plan: dict, *, account: str | None = None, region: str | None = None
) -> OverlayResult:
    parsed = parse_plan(plan)
    g = copy.deepcopy(base)
    ctx = BuildContext(
        account=account or _dominant(base, "account"),
        region=region or _dominant(base, "region"),
    )
    resolver = Resolver(g, parsed)
    result = OverlayResult(graph=g)
    unmapped: set[str] = set()

    supported = [c for c in parsed.changes if c.type in BUILDERS]
    for c in parsed.changes:
        if c.type not in BUILDERS:
            unmapped.add(c.type)
    result.mapped = len(supported)

    # 1. deletes (incl. the delete half of replace, and fold-type updates which
    #    are remove-before + add-after)
    for c in supported:
        if c.deletes or (c.updates and c.type in FOLD_TYPES):
            _apply_delete(g, c, resolver)
    resolver.reindex(g)

    # 2. build deltas: creates, plus fold-type updates re-added from `after`
    deltas: list[Delta] = []
    for c in supported:
        if c.creates or (c.updates and c.type in FOLD_TYPES):
            deltas.append(BUILDERS[c.type](c, resolver, ctx))

    # 3. nodes first, then folds/edges
    for d in deltas:
        for node in d.nodes:
            g.nodes[node.uid] = node
            result.planned_uids.add(node.uid)
    for d in deltas:
        for uid, key, value in d.props:
            if uid in g.nodes:
                g.nodes[uid].props[key] = value
        for sg_uid, rule in d.inbound:
            if sg_uid in g.nodes:
                g.nodes[sg_uid].props.setdefault("inbound", []).append(rule)
        for s, dst, rel in d.edges:
            if s in g.nodes and dst in g.nodes and (s, dst, rel) not in g.edges:
                g.edges.append((s, dst, rel))

    # 4. in-place updates for node types
    for c in supported:
        if c.updates and c.type not in FOLD_TYPES:
            _apply_update(g, c, resolver)

    build_indexes(g)
    result.unmapped_types = sorted(unmapped)
    return result


def _apply_delete(g: Graph, c: ResourceChange, r: Resolver) -> None:
    if c.type in FOLD_TYPES:
        _delete_fold(g, c, r)
        return
    uid = r.bind_existing(c)
    if uid is None:
        return
    g.nodes.pop(uid, None)
    g.edges = [(s, d, rel) for (s, d, rel) in g.edges if s != uid and d != uid]


def _delete_fold(g: Graph, c: ResourceChange, r: Resolver) -> None:
    before = c.before or {}
    if c.type == "aws_route":
        rt = r.by_id(before.get("route_table_id"))
        target = next(
            (
                r.by_id(before.get(f))
                for f in (
                    "gateway_id",
                    "nat_gateway_id",
                    "transit_gateway_id",
                    "vpc_peering_connection_id",
                )
                if r.by_id(before.get(f))
            ),
            None,
        )
        if rt and target:
            g.edges = [e for e in g.edges if e != (rt, target, "ROUTES_TO")]
    elif c.type == "aws_route_table_association":
        sub = r.by_id(before.get("subnet_id"))
        rt = r.by_id(before.get("route_table_id"))
        if sub and rt:
            g.edges = [e for e in g.edges if e != (sub, rt, "USES_ROUTE_TABLE")]
    elif c.type in ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule"):
        owner = r.by_id(before.get("security_group_id"))
        if owner and owner in g.nodes:
            gone = sg_rule(before)
            g.nodes[owner].props["inbound"] = [
                rule
                for rule in g.nodes[owner].props.get("inbound", [])
                if not (
                    rule.get("protocol") == gone["protocol"]
                    and int(rule.get("from_port", 0)) == gone["from_port"]
                    and int(rule.get("to_port", 0)) == gone["to_port"]
                    and set(rule.get("cidrs") or []) == set(gone["cidrs"])
                )
            ]
    elif c.type == "aws_internet_gateway_attachment":
        igw = r.by_id(before.get("internet_gateway_id"))
        if igw and igw in g.nodes:
            g.nodes[igw].props.pop("vpc_id", None)
    # aws_vpc_peering_connection_accepter delete: no graph effect in v1.


def _apply_update(g: Graph, c: ResourceChange, r: Resolver) -> None:
    uid = r.bind_existing(c)
    if uid is None or uid not in g.nodes:
        return
    node = g.nodes[uid]
    after = c.after or {}
    for key in UPDATE_SCALAR_PROPS:
        if after.get(key) is not None:
            node.props[key] = after[key]
    if c.type == "aws_security_group" and "ingress" in after:
        node.props["inbound"] = [sg_rule(x) for x in after.get("ingress") or []]
    if c.type == "aws_instance" and after.get("vpc_security_group_ids") is not None:
        g.edges = [
            (s, d, rel) for (s, d, rel) in g.edges if not (s == uid and rel == "PROTECTED_BY")
        ]
        for sg in r.nodes_for(c, "vpc_security_group_ids"):
            g.edges.append((uid, sg, "PROTECTED_BY"))
