"""Bind plan fields to graph nodes.

Literal ids ("vpc-22b…") bind to LIVE nodes via identity-prop / uid-tail
indexes; *known after apply* fields resolve through configuration references
to the synthetic uid of the planned resource (`tf:<address>`).
"""

from __future__ import annotations

from cw_guardrails.graph import Graph
from cw_guardrails.overlay.plan import ParsedPlan, ResourceChange

SYNTH_PREFIX = "tf:"

# Identity props the scanner stores that we can bind literal ids against.
_ID_PROPS = ("vpc_id", "subnet_id", "group_id", "tgw_id")


def synthetic_uid(address: str) -> str:
    return f"{SYNTH_PREFIX}{address}"


def is_planned_uid(uid: str) -> bool:
    return uid.startswith(SYNTH_PREFIX)


class Resolver:
    def __init__(self, graph: Graph, plan: ParsedPlan):
        self.plan = plan
        # Every created resource gets its synthetic uid up front, so references
        # resolve regardless of processing order.
        self.created = {c.address: synthetic_uid(c.address) for c in plan.changes if c.creates}
        self._by_tail: dict[str, str] = {}
        self._by_prop: dict[tuple[str, str], str] = {}
        self.reindex(graph)

    def reindex(self, graph: Graph) -> None:
        """(Re)build the literal-id indexes — call after deletes mutate the graph."""
        self._uids = set(graph.nodes)
        self._by_tail = {}
        self._by_prop = {}
        for uid, n in graph.nodes.items():
            self._by_tail.setdefault(uid.split("/")[-1], uid)
            for key in _ID_PROPS:
                v = n.props.get(key)
                if v is not None:
                    self._by_prop.setdefault((key, str(v)), uid)

    def by_id(self, literal: object) -> str | None:
        """A bare AWS id ('vpc-…', 'sg-…', 'igw-…') -> live node uid, if fetched."""
        if not literal:
            return None
        s = str(literal)
        for key in _ID_PROPS:
            uid = self._by_prop.get((key, s))
            if uid:
                return uid
        return self._by_tail.get(s)

    # ── field access (dotted paths walk nested blocks; list indices collapse) ──
    def _walk(self, root: object, field: str) -> object:
        node = root
        for part in field.split("."):
            if isinstance(node, list):
                node = node[0] if node else None
            if not isinstance(node, dict):
                return None
            node = node.get(part)
        return node

    def _refs(self, change: ResourceChange, field: str) -> list[str]:
        return (self.plan.refs.get(change.address) or {}).get(field) or []

    def node_for(self, change: ResourceChange, field: str) -> str | None:
        """Resolve a single id-valued field to a node uid — live or planned."""
        lit = self._walk(change.after, field)
        if isinstance(lit, list):
            lit = lit[0] if lit else None
        if lit not in (None, ""):
            uid = self.by_id(lit)
            if uid:
                return uid
        for addr in self._refs(change, field):
            uid = self.created.get(addr)
            if uid:
                return uid
        return None

    def nodes_for(self, change: ResourceChange, field: str) -> list[str]:
        """Resolve a list-valued field (SG ids, subnet_ids) to node uids."""
        out: list[str] = []
        lit = self._walk(change.after, field)
        values = lit if isinstance(lit, list) else [lit] if lit else []
        for v in values:
            uid = self.by_id(v)
            if uid and uid not in out:
                out.append(uid)
        for addr in self._refs(change, field):
            uid = self.created.get(addr)
            if uid and uid not in out:
                out.append(uid)
        return out

    def value_for(self, change: ResourceChange, field: str) -> str | None:
        """A cross-reference kept as a PROP VALUE (e.g. TgwVpcAttachment.tgw_id).
        Literal stays literal; unknown becomes the referenced synthetic uid — an
        opaque id the engine's prop-matching helpers group on consistently."""
        lit = self._walk(change.after, field)
        if lit not in (None, "", []):
            return str(lit)
        for addr in self._refs(change, field):
            uid = self.created.get(addr)
            if uid:
                return uid
        return None

    def bind_existing(self, change: ResourceChange) -> str | None:
        """Bind an update/delete to the LIVE node it targets, via change.before."""
        before = change.before or {}
        arn = before.get("arn")
        if arn and arn in self._uids:
            return arn
        for cand in (arn, before.get("id")):
            if not cand:
                continue
            uid = self.by_id(str(cand).split("/")[-1])
            if uid:
                return uid
        return None
