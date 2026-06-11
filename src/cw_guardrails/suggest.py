"""Generate candidate invariants from the live graph (authoring path #2).

Each generator inspects the graph, computes current state, and emits a candidate
rule tagged 'ratchet' (already passing — lock it in) or 'fix-first' (would flag N
existing resources). Accepting a candidate appends `rule_yaml` to the policy.
"""

from __future__ import annotations

from pydantic import BaseModel

from cw_guardrails.graph import Graph
from cw_guardrails.reachability import internet_facing
from cw_guardrails.selectors import glob_re

_ADMIN = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "Postgres"}
_WORLD = {"0.0.0.0/0", "::/0"}
_SENSITIVE = "*exfil*|*data*|*secret*|*vuln*"


class Candidate(BaseModel):
    id: str
    severity: str
    rule_yaml: str
    rationale: str
    violations: list[str]

    @property
    def kind(self) -> str:
        return "ratchet" if not self.violations else "fix-first"


def suggest_rules(
    graph: Graph, *, driver: object | None = None, account_id: str = ""
) -> list[Candidate]:
    return [
        c
        for gen in (
            _admin_ports,
            _world_open_ingress,
            _public_db,
            _instance_internet,
            _sensitive_public,
            _egress_nat,
            _instances_have_sg,
            _public_subnet_nacl,
            _shared_tgw,
        )
        for c in [gen(graph, driver, account_id)]
        if c is not None
    ]


def _admin_ports(g: Graph, driver, acct) -> Candidate:
    bad = []
    for sg in g.by_type("SecurityGroup"):
        for r in sg.inbound:
            if set(r.get("cidrs") or []) & _WORLD:
                fp, tp = int(r.get("from_port", 0)), int(r.get("to_port", 0))
                hit = [n for p, n in _ADMIN.items() if fp <= p <= tp]
                if hit:
                    bad.append(f"{sg.name}: {'/'.join(hit)} open to internet")
    return Candidate(
        id="no-world-open-admin-ports",
        severity="critical",
        rule_yaml="not_ingress: { select: {type: SecurityGroup}, ports: [22,3389,3306,5432], from: 0.0.0.0/0 }",
        rationale="No security group exposes SSH/RDP/DB ports to the internet today.",
        violations=bad,
    )


def _world_open_ingress(g: Graph, driver, acct) -> Candidate:
    bad = []
    for sg in g.by_type("SecurityGroup"):
        for r in sg.inbound:
            if set(r.get("cidrs") or []) & _WORLD:
                fp, tp = int(r.get("from_port", 0)), int(r.get("to_port", 0))
                bad.append(f"{sg.name}: {r.get('protocol', 'tcp')}/{fp}-{tp} open to 0.0.0.0/0")
                break
    return Candidate(
        id="no-world-open-ingress",
        severity="high",
        rule_yaml="not_ingress: { select: {type: SecurityGroup}, from: 0.0.0.0/0 }",
        rationale="No security group should expose any port to the entire internet.",
        violations=bad,
    )


def _instance_internet(g: Graph, driver, acct) -> Candidate | None:
    insts = g.by_type("Instance")
    if not insts:
        return None
    facing = internet_facing(g)
    bad = [n.name for n in insts if n.uid in facing]
    return Candidate(
        id="instance-not-internet-reachable",
        severity="high",
        rule_yaml="not_path: { from: internet, to: {type: Instance} }",
        rationale=f"{len(insts)} instance(s) exist; lock down which may be reached from the internet.",
        violations=bad,
    )


def _instances_have_sg(g: Graph, driver, acct) -> Candidate | None:
    insts = g.by_type("Instance")
    if not insts:
        return None
    bad = [i.name for i in insts if not g.protected_by.get(i.uid)]
    return Candidate(
        id="instances-have-security-group",
        severity="medium",
        rule_yaml="must_have: { select: {type: Instance}, has: SecurityGroup }",
        rationale="Every instance should be protected by at least one security group.",
        violations=bad,
    )


def _public_subnet_nacl(g: Graph, driver, acct) -> Candidate | None:
    if not g.public_subnets:
        return None
    neighbors: dict[str, set[str]] = {}
    for s, d, _rel in g.edges:
        neighbors.setdefault(s, set()).add(d)
        neighbors.setdefault(d, set()).add(s)
    bad = []
    for sub in g.public_subnets:
        has_nacl = any(
            g.nodes.get(n) and g.nodes[n].type == "NetworkACL" for n in neighbors.get(sub, set())
        )
        if not has_nacl:
            bad.append(g.nodes[sub].name if sub in g.nodes else sub)
    return Candidate(
        id="public-subnet-has-nacl",
        severity="medium",
        rule_yaml="must_have: { select: {type: Subnet}, has: NetworkACL }",
        rationale="Internet-routed (public) subnets should have an explicit network ACL.",
        violations=bad,
    )


def _public_db(g: Graph, driver, acct) -> Candidate:
    facing = internet_facing(g)
    rds = g.by_type("RdsInstance")
    bad = [n.name for n in rds if n.uid in facing]
    return Candidate(
        id="database-not-internet-reachable",
        severity="critical",
        rule_yaml="not_path: { from: internet, to: {type: RdsInstance} }",
        rationale=f"{len(rds)} database(s) exist; none are internet-reachable today.",
        violations=bad,
    )


def _sensitive_public(g: Graph, driver, acct) -> Candidate:
    rx = glob_re(_SENSITIVE)
    bad = [
        f"{n.type} '{n.name}'"
        for n in g.nodes.values()
        if rx.search(n.name) and g.subnet_of.get(n.uid) in g.public_subnets
    ]
    return Candidate(
        id="sensitive-not-in-public-subnet",
        severity="critical",
        # Inline selector — a bare group name here would dangle unless the user's
        # policy happens to define it, turning the accepted rule into an ERROR.
        rule_yaml=f'not_in_public_subnet: {{ select: {{ name_matches: "{_SENSITIVE}" }} }}',
        rationale="Sensitive workloads must not sit in an internet-routed subnet.",
        violations=bad,
    )


def _egress_nat(g: Graph, driver, acct) -> Candidate | None:
    insts = g.by_type("Instance")
    if not insts:
        return None
    bad = [
        f"{i.name} egresses via an Internet Gateway"
        for i in insts
        if g.subnet_of.get(i.uid) in g.public_subnets
    ]
    return Candidate(
        id="instance-egress-only-via-nat",
        severity="high",
        rule_yaml="only_via: { from: {type: Instance}, to: internet, through: {type: NatGateway} }",
        rationale="Private instance egress should traverse a NAT.",
        violations=bad,
    )


def _shared_tgw(g: Graph, driver, acct) -> Candidate | None:
    if driver is None:
        return None
    import re

    attach = {n.props.get("vpc_id"): n.props.get("tgw_id") for n in g.by_type("TgwVpcAttachment")}
    bad = []
    with driver.session() as s:  # type: ignore[attr-defined]
        for vpc in g.by_type("Vpc"):
            m = re.search(r"vpc-[0-9a-f]+", vpc.uid)
            tgw = attach.get(vpc.props.get("vpc_id")) or attach.get(m.group(0) if m else None)
            if not tgw:
                continue
            others = sorted(
                {
                    r["a"]
                    for r in s.run(
                        "MATCH (x:TgwVpcAttachment {tgw_id:$t}) WHERE x.owner_account_id IS NOT NULL "
                        "RETURN DISTINCT x.owner_account_id AS a",
                        t=tgw,
                    )
                }
                - {vpc.account or acct}
            )
            if others:
                bad.append(f"{vpc.name} shares {tgw} with {', '.join(others)}")
    return Candidate(
        id="no-cross-account-shared-tgw",
        severity="high",
        rule_yaml="no_shared_tgw: { select: {type: Vpc} }",
        rationale="A VPC must not attach to a transit gateway shared with other accounts.",
        violations=bad,
    )
