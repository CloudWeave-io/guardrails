"""In-memory cloud graph + Neo4j fetch.

The engine always evaluates against an in-memory `Graph` (never Neo4j directly),
so the exact same code path works on the live graph and, later, on a graph with
a Terraform-plan delta overlaid for the pre-merge check.

Fetch semantics are ported from the document-ingestion reconciliation engine:
account/region-scoped traversal, pick the *specific* Neo4j label (skip the generic
:CloudResource), and fold SG rules onto their group. Derived indexes
(public subnets, containment, VPC connectivity) power the reachability engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_META_LABELS = {"CloudResource", "Resource"}
_PRIVATE_CIDRS = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.2",
    "172.30.",
    "172.31.",
    "192.168.",
)
_WORLD = {"0.0.0.0/0", "::/0"}


@dataclass
class Node:
    uid: str
    type: str
    name: str
    account: str | None
    region: str | None
    props: dict[str, Any] = field(default_factory=dict)

    @property
    def inbound(self) -> list[dict[str, Any]]:
        return self.props.get("inbound", [])


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[tuple[str, str, str]] = field(default_factory=list)  # (src, dst, rel)

    # derived indexes
    public_subnets: set[str] = field(default_factory=set)
    subnet_of: dict[str, str] = field(default_factory=dict)  # resource uid -> subnet uid
    vpc_of_subnet: dict[str, str] = field(default_factory=dict)  # subnet uid -> vpc uid
    protected_by: dict[str, list[str]] = field(default_factory=dict)  # resource -> [sg uid]
    _vpc_parent: dict[str, str] = field(default_factory=dict)  # union-find over connected VPCs

    # ── lookups ──
    def by_type(self, *types: str) -> list[Node]:
        t = set(types)
        return [n for n in self.nodes.values() if n.type in t]

    def vpc_of(self, uid: str) -> str | None:
        sub = self.subnet_of.get(uid)
        return self.vpc_of_subnet.get(sub) if sub else None

    def vpc_group(self, vpc: str) -> str:
        """Union-find root — two VPCs in the same group are network-connected."""
        root = vpc
        while self._vpc_parent.get(root, root) != root:
            root = self._vpc_parent[root]
        return root

    def vpcs_connected(self, a: str | None, b: str | None) -> bool:
        if not a or not b:
            return False
        return self.vpc_group(a) == self.vpc_group(b)


def node_type(labels: list[str]) -> str:
    specific = sorted(label for label in labels if label not in _META_LABELS)
    return specific[0] if specific else sorted(labels)[0]


def fetch_graph(driver, account_id: str, regions: list[str]) -> Graph:
    """Fetch the account/region-scoped subgraph into a Graph."""
    acct_uid = f"arn:aws:iam::{account_id}:root"
    region_active = bool(regions)
    g = Graph()
    with driver.session() as s:
        nodes_q = (
            "MATCH (acct:AwsAccount {uid:$acct})-[*0..5]->(n) "
            "WHERE (coalesce(n.accountID,n.account_id)=$aid OR coalesce(n.accountID,n.account_id) IS NULL) "
            "  AND (NOT $ra OR n.region IS NULL OR n.region IN $regions) "
            "RETURN DISTINCT n"
        )
        for rec in s.run(nodes_q, acct=acct_uid, aid=account_id, regions=regions, ra=region_active):
            nd = rec["n"]
            uid = nd.get("uid")
            if not uid:
                continue
            props = dict(nd.items())
            g.nodes[uid] = Node(
                uid=uid,
                type=node_type(list(nd.labels)),
                name=str(props.get("name", "")) or uid.split("/")[-1],
                account=props.get("accountID") or props.get("account_id"),
                region=props.get("region"),
                props=props,
            )
        edges_q = (
            "MATCH (acct:AwsAccount {uid:$acct})-[*0..5]->(a)-[r]->(b) "
            "RETURN DISTINCT a.uid AS s, b.uid AS d, type(r) AS rel"
        )
        for rec in s.run(edges_q, acct=acct_uid):
            if rec["s"] in g.nodes and rec["d"] in g.nodes:
                g.edges.append((rec["s"], rec["d"], rec["rel"]))

        rules_q = (
            "MATCH (sg:SecurityGroup)-[:HAS_INBOUND_RULE]->(x:SGRule) "
            "WHERE sg.uid CONTAINS $aid RETURN sg.uid AS sg, properties(x) AS p"
        )
        for rec in s.run(rules_q, aid=account_id):
            sg = g.nodes.get(rec["sg"])
            if sg is not None:
                sg.props.setdefault("inbound", []).append(rec["p"])

    build_indexes(g)
    return g


def build_indexes(g: Graph) -> None:
    """Compute derived indexes (idempotent; also used by tests on hand-built graphs)."""
    rt_to_igw = {
        src
        for (src, dst, rel) in g.edges
        if rel == "ROUTES_TO" and g.nodes.get(dst) and g.nodes[dst].type == "InternetGateway"
    }
    subnet_rt = {src: dst for (src, dst, rel) in g.edges if rel == "USES_ROUTE_TABLE"}
    g.public_subnets = {sub for sub, rt in subnet_rt.items() if rt in rt_to_igw}

    g.subnet_of, g.vpc_of_subnet, g.protected_by = {}, {}, {}
    for src, dst, rel in g.edges:
        if rel in ("CONTAINS_INSTANCE", "CONTAINS_LAMBDA"):
            g.subnet_of[dst] = src
        elif rel == "HAS_SUBNET":
            g.vpc_of_subnet[dst] = src
        elif rel == "PROTECTED_BY":
            g.protected_by.setdefault(src, []).append(dst)

    # Union-find over network-connected VPCs (peering + shared transit gateway).
    g._vpc_parent = {n.uid: n.uid for n in g.by_type("Vpc")}
    for src, dst, rel in g.edges:
        if rel == "PEERS_WITH" and src in g._vpc_parent and dst in g._vpc_parent:
            _union(g, src, dst)
    # In the live schema peering is mediated by a VpcPeeringConnection node
    # (Vpc-[:HAS_PEERING]->pcx-[:PEERS_WITH]->Vpc), so union via its props too.
    for pcx in g.by_type("VpcPeeringConnection"):
        if str(pcx.props.get("status", "active")) != "active":
            continue
        a = _vpc_uid_for(g, pcx.props.get("requester_vpc_id"))
        b = _vpc_uid_for(g, pcx.props.get("accepter_vpc_id"))
        if a and b:
            _union(g, a, b)
    by_tgw: dict[str, list[str]] = {}
    for att in g.by_type("TgwVpcAttachment"):
        tgw, vid = att.props.get("tgw_id"), att.props.get("vpc_id")
        vpc = _vpc_uid_for(g, vid)
        if tgw and vpc:
            by_tgw.setdefault(tgw, []).append(vpc)
    for vpcs in by_tgw.values():
        for other in vpcs[1:]:
            _union(g, vpcs[0], other)


def _union(g: Graph, a: str, b: str) -> None:
    ra, rb = g.vpc_group(a), g.vpc_group(b)
    if ra != rb:
        g._vpc_parent[ra] = rb


def _vpc_uid_for(g: Graph, vpc_id: str | None) -> str | None:
    if not vpc_id:
        return None
    for n in g.by_type("Vpc"):
        if n.props.get("vpc_id") == vpc_id or vpc_id in n.uid:
            return n.uid
    return None


def subgraph_for_accounts(g: Graph, accounts: set[str]) -> Graph:
    """A new Graph with only nodes owned by `accounts` (and edges among them),
    indexes rebuilt. Used for per-rule account scope: a rule evaluates in true
    isolation against its own accounts — reachability included — rather than against
    the merged multi-account graph with a post-hoc filter.
    """
    sub = Graph()
    sub.nodes = {uid: n for uid, n in g.nodes.items() if n.account in accounts}
    keep = set(sub.nodes)
    sub.edges = [(s, d, r) for (s, d, r) in g.edges if s in keep and d in keep]
    build_indexes(sub)
    return sub


def sg_admits(graph: Graph, dst_uid: str, src_uid: str | None) -> bool:
    """Does any security group on `dst` admit inbound traffic from `src`?

    Approximation (documented): a dst inbound rule admits the source when it is
    world-open, references the source's SG, or is an RFC1918 CIDR (any in-cloud
    private source). A dst with NO inbound rules is closed (default-deny).
    Resources with no SG at all (e.g. some managed services) are treated as open.
    """
    sgs = graph.protected_by.get(dst_uid, [])
    if not sgs:
        return True  # no SG layer to stop it
    src_sgs = set(graph.protected_by.get(src_uid, [])) if src_uid else set()
    src_sg_ids = {graph.nodes[s].props.get("group_id") or s.split("/")[-1] for s in src_sgs}
    saw_rule = False
    for sg_uid in sgs:
        for rule in graph.nodes[sg_uid].inbound:
            saw_rule = True
            for cidr in rule.get("cidrs") or []:
                if cidr in _WORLD or str(cidr).startswith(_PRIVATE_CIDRS):
                    return True
            sid = str(rule.get("source_sg_id") or "")
            if sid and sid in src_sg_ids:
                return True
    return not saw_rule  # SGs exist but with no inbound rules at all -> open egress-only group
