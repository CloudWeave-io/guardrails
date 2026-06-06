"""Network reachability over the in-memory graph.

Semantics ported from the AI-Agent reachability checkers, reduced to what the
starter-pack predicates need and kept deterministic so it can later run over a
Terraform-overlaid graph in CI:

- internet exposure  — a resource in an IGW-routed (public) subnet; an Instance
  additionally needs a world-open security-group ingress to be *inbound*-reachable.
- lateral reach      — resource→resource within network-connected VPCs (same VPC,
  peered, or sharing a transit gateway), gated by the destination's SGs.
- chokepoint (only_via) — egress to the internet that does not traverse a required
  gateway (e.g. instances in a public subnet bypass the NAT).

Documented non-goals for now (tracked as follow-ups, matching AI-Agent's fuller
checkers): NACL rule ordering, per-route TGW blackholes, exact host-IP CIDR math.
"""

from __future__ import annotations

from cw_guardrails.graph import Graph, sg_admits
from cw_guardrails.selectors import INTERNET

_WORLD = {"0.0.0.0/0", "::/0"}
_REACH_TYPES = {"Instance", "LambdaFunction", "RdsInstance"}
# Types that can actually be *reached inbound* from the internet by sitting in a
# public subnet. A Lambda in a VPC subnet is not inbound-reachable that way, so
# it's excluded here (its placement risk is caught by `not_in_public_subnet`).
_INBOUND_TYPES = {"Instance", "RdsInstance", "LoadBalancer"}


def _world_open_inbound(graph: Graph, uid: str) -> bool:
    for sg_uid in graph.protected_by.get(uid, []):
        for rule in graph.nodes[sg_uid].inbound:
            if any(c in _WORLD for c in (rule.get("cidrs") or [])):
                return True
    return False


def internet_facing(graph: Graph) -> dict[str, list[str]]:
    """uid -> evidence path for every resource reachable from the internet."""
    out: dict[str, list[str]] = {}
    for uid, node in graph.nodes.items():
        if node.type not in _INBOUND_TYPES:
            continue
        sub = graph.subnet_of.get(uid)
        if not sub or sub not in graph.public_subnets:
            continue
        if node.type == "Instance" and not _world_open_inbound(graph, uid):
            continue  # in a public subnet but no inbound opening
        out[uid] = [INTERNET, sub, uid]
    return out


def _resources(graph: Graph) -> list[str]:
    return [u for u, n in graph.nodes.items() if n.type in _REACH_TYPES]


def reaches(
    graph: Graph, src: str, dst: str, blocked: frozenset[str] = frozenset()
) -> list[str] | None:
    """BFS for a lateral path src→dst; returns the uid path or None."""
    if src == dst:
        return [src]
    src_vpc = graph.vpc_of(src)
    if src_vpc is None:
        return None
    pool = [u for u in _resources(graph) if u not in blocked]
    visited = {src}
    queue: list[tuple[str, list[str]]] = [(src, [src])]
    while queue:
        cur, path = queue.pop(0)
        cur_vpc = graph.vpc_of(cur)
        for cand in pool:
            if cand in visited:
                continue
            if not graph.vpcs_connected(cur_vpc, graph.vpc_of(cand)):
                continue
            if not sg_admits(graph, cand, cur):
                continue
            npath = [*path, cand]
            if cand == dst:
                return npath
            visited.add(cand)
            queue.append((cand, npath))
    return None


def any_reach(
    graph: Graph, src_set: set[str], dst_set: set[str], blocked: frozenset[str] = frozenset()
) -> tuple[str, str, list[str]] | None:
    """First (src, dst, path) where some src reaches some dst. Handles INTERNET source."""
    dsts = dst_set - {INTERNET}
    if INTERNET in src_set:
        facing = internet_facing(graph)
        for d in dsts:
            if d in facing:
                return INTERNET, d, facing[d]
    for s in src_set - {INTERNET}:
        if s in blocked:
            continue
        for d in dsts:
            path = reaches(graph, s, d, blocked)
            if path is not None:
                return s, d, path
    return None


def egress_bypass(
    graph: Graph, src_set: set[str], through_uids: set[str]
) -> list[tuple[str, list[str]]]:
    """Resources that egress to the internet without traversing `through` (the NAT case).

    A resource in a public (IGW-routed) subnet egresses straight through the IGW —
    bypassing any required NAT. We report each such resource with its path.
    """
    out: list[tuple[str, list[str]]] = []
    has_nat = bool(through_uids)
    for uid in src_set:
        sub = graph.subnet_of.get(uid)
        if sub and sub in graph.public_subnets:
            note = "" if has_nat else " (no NAT gateway present)"
            out.append((uid, [uid, sub, "igw", INTERNET]))
            _ = note  # evidence string is composed by the predicate layer
    return out
