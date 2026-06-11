"""Terraform resource type -> graph deltas.

Each builder turns one planned resource into exactly the node/edge/prop shapes
the engine's indexes consume (see docs/pr-gate-plan.md §3.2) — that contract is
what makes not_path / not_public / only_via light up on planned changes with
zero engine changes:

- VPC connectivity: VpcPeeringConnection / TgwVpcAttachment nodes with the
  requester/accepter/tgw/vpc id PROPS (union-find groups on values).
- Public subnets: Subnet -USES_ROUTE_TABLE-> RouteTable -ROUTES_TO-> IGW edges.
- Placement: CONTAINS_INSTANCE / CONTAINS_LAMBDA edges (subnet -> workload).
- SG gating: PROTECTED_BY edges + rules folded onto SecurityGroup.props.inbound.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cw_guardrails.graph import Node
from cw_guardrails.overlay.plan import ResourceChange
from cw_guardrails.overlay.resolve import Resolver, synthetic_uid


@dataclass
class BuildContext:
    account: str | None
    region: str | None


@dataclass
class Delta:
    nodes: list[Node] = field(default_factory=list)
    edges: list[tuple[str, str, str]] = field(default_factory=list)
    inbound: list[tuple[str, dict]] = field(default_factory=list)  # fold rule onto SG uid
    props: list[tuple[str, str, object]] = field(default_factory=list)  # fold prop onto uid


def _name_of(change: ResourceChange) -> str:
    after = change.after or {}
    tags = after.get("tags") or {}
    return str(tags.get("Name") or after.get("name") or after.get("identifier") or change.address)


def _node(change: ResourceChange, ntype: str, ctx: BuildContext, **props: object) -> Node:
    clean = {k: v for k, v in props.items() if v not in (None, "", [])}
    clean.update({"planned": True, "tf_address": change.address})
    return Node(
        uid=synthetic_uid(change.address),
        type=ntype,
        name=_name_of(change),
        account=ctx.account,
        region=ctx.region,
        props=clean,
    )


def sg_rule(d: dict) -> dict:
    """Normalize a TF ingress block / rule resource to the scanner's rule shape."""
    cidrs = (
        list(d.get("cidr_blocks") or [])
        + list(d.get("ipv6_cidr_blocks") or [])
        + ([d["cidr_ipv4"]] if d.get("cidr_ipv4") else [])
        + ([d["cidr_ipv6"]] if d.get("cidr_ipv6") else [])
    )
    proto = d.get("protocol") or d.get("ip_protocol") or "tcp"
    src_sgs = d.get("security_groups") or []
    return {
        "protocol": str(proto),
        "from_port": int(d.get("from_port") or 0),
        "to_port": int(d.get("to_port") or 0),
        "cidrs": cidrs,
        "source_sg_id": (src_sgs[0] if src_sgs else None)
        or d.get("source_security_group_id")
        or d.get("referenced_security_group_id"),
    }


# ── builders ────────────────────────────────────────────────────────────────
def _vpc(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    a = c.after
    return Delta(nodes=[_node(c, "Vpc", ctx, vpc_id=a.get("id"), cidr_block=a.get("cidr_block"))])


def _subnet(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    a = c.after
    d = Delta(
        nodes=[
            _node(
                c,
                "Subnet",
                ctx,
                subnet_id=a.get("id"),
                vpc_id=r.value_for(c, "vpc_id"),
                cidr_block=a.get("cidr_block"),
                availability_zone=a.get("availability_zone"),
            )
        ]
    )
    vpc = r.node_for(c, "vpc_id")
    if vpc:
        d.edges.append((vpc, synthetic_uid(c.address), "HAS_SUBNET"))
    return d


def _instance(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    a = c.after
    uid = synthetic_uid(c.address)
    d = Delta(nodes=[_node(c, "Instance", ctx, private_ip=a.get("private_ip"))])
    sub = r.node_for(c, "subnet_id")
    if sub:
        d.edges.append((sub, uid, "CONTAINS_INSTANCE"))
    for sg in r.nodes_for(c, "vpc_security_group_ids"):
        d.edges.append((uid, sg, "PROTECTED_BY"))
    return d


def _lambda(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    uid = synthetic_uid(c.address)
    d = Delta(nodes=[_node(c, "LambdaFunction", ctx)])
    for sub in r.nodes_for(c, "vpc_config.subnet_ids"):
        d.edges.append((sub, uid, "CONTAINS_LAMBDA"))
    return d


def _rds(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    # Placement via db_subnet_group is a documented v1 limit (plan §10).
    return Delta(nodes=[_node(c, "RdsInstance", ctx, engine=c.after.get("engine"))])


def _lb(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    scheme = "internal" if c.after.get("internal") else "internet-facing"
    return Delta(nodes=[_node(c, "LoadBalancer", ctx, scheme=scheme)])


def _security_group(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    a = c.after
    node = _node(c, "SecurityGroup", ctx, group_id=a.get("id"), vpc_id=r.value_for(c, "vpc_id"))
    node.props["inbound"] = [sg_rule(x) for x in a.get("ingress") or []]
    return Delta(nodes=[node])


def _sg_rule_resource(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    # aws_security_group_rule has type ingress|egress; the dedicated
    # aws_vpc_security_group_ingress_rule is always ingress.
    if c.type == "aws_security_group_rule" and c.after.get("type") != "ingress":
        return Delta()  # engine only evaluates inbound
    target = r.node_for(c, "security_group_id")
    if not target:
        return Delta()
    return Delta(inbound=[(target, sg_rule(c.after))])


def _route_table(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    uid = synthetic_uid(c.address)
    d = Delta(nodes=[_node(c, "RouteTable", ctx, vpc_id=r.value_for(c, "vpc_id"))])
    for route in c.after.get("route") or []:
        target = _route_target(route, r)
        if target:
            d.edges.append((uid, target, "ROUTES_TO"))
    # Routes whose gateway is itself planned reference it symbolically.
    for fld in _ROUTE_TARGET_FIELDS:
        for gw in r.nodes_for(c, f"route.{fld}"):
            if (uid, gw, "ROUTES_TO") not in d.edges:
                d.edges.append((uid, gw, "ROUTES_TO"))
    return d


_ROUTE_TARGET_FIELDS = (
    "gateway_id",
    "nat_gateway_id",
    "transit_gateway_id",
    "vpc_peering_connection_id",
)


def _route_target(route: dict, r: Resolver) -> str | None:
    for fld in _ROUTE_TARGET_FIELDS:
        uid = r.by_id(route.get(fld))
        if uid:
            return uid
    return None


def _route(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    rt = r.node_for(c, "route_table_id")
    if not rt:
        return Delta()
    for fld in _ROUTE_TARGET_FIELDS:
        gw = r.node_for(c, fld)
        if gw:
            return Delta(edges=[(rt, gw, "ROUTES_TO")])
    return Delta()


def _rt_association(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    sub = r.node_for(c, "subnet_id")
    rt = r.node_for(c, "route_table_id")
    if sub and rt:
        return Delta(edges=[(sub, rt, "USES_ROUTE_TABLE")])
    return Delta()


def _igw(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    return Delta(nodes=[_node(c, "InternetGateway", ctx, vpc_id=r.value_for(c, "vpc_id"))])


def _igw_attachment(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    igw = r.node_for(c, "internet_gateway_id")
    vpc = r.value_for(c, "vpc_id")
    if igw and vpc:
        return Delta(props=[(igw, "vpc_id", vpc)])
    return Delta()


def _nat(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    return Delta(nodes=[_node(c, "NatGateway", ctx, subnet_id=r.value_for(c, "subnet_id"))])


def _tgw(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    return Delta(nodes=[_node(c, "TransitGateway", ctx, tgw_id=c.after.get("id"))])


def _tgw_attachment(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    return Delta(
        nodes=[
            _node(
                c,
                "TgwVpcAttachment",
                ctx,
                tgw_id=r.value_for(c, "transit_gateway_id"),
                vpc_id=r.value_for(c, "vpc_id"),
                owner_account_id=ctx.account,
            )
        ]
    )


def _peering(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    uid = synthetic_uid(c.address)
    # Assumed active (locked decision D6) — the security-conservative reading.
    d = Delta(
        nodes=[
            _node(
                c,
                "VpcPeeringConnection",
                ctx,
                requester_vpc_id=r.value_for(c, "vpc_id"),
                accepter_vpc_id=r.value_for(c, "peer_vpc_id"),
                status="active",
            )
        ]
    )
    requester = r.node_for(c, "vpc_id")
    accepter = r.node_for(c, "peer_vpc_id")
    if requester:
        d.edges.append((requester, uid, "HAS_PEERING"))
    if accepter:
        d.edges.append((uid, accepter, "PEERS_WITH"))
    return d


def _peering_accepter(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    pcx = r.node_for(c, "vpc_peering_connection_id")
    if pcx:
        return Delta(props=[(pcx, "status", "active")])
    return Delta()


def _iam_role(c: ResourceChange, r: Resolver, ctx: BuildContext) -> Delta:
    return Delta(
        nodes=[_node(c, "IamRole", ctx, assume_role_policy=c.after.get("assume_role_policy"))]
    )


BUILDERS = {
    "aws_vpc": _vpc,
    "aws_subnet": _subnet,
    "aws_instance": _instance,
    "aws_lambda_function": _lambda,
    "aws_db_instance": _rds,
    "aws_lb": _lb,
    "aws_security_group": _security_group,
    "aws_security_group_rule": _sg_rule_resource,
    "aws_vpc_security_group_ingress_rule": _sg_rule_resource,
    "aws_route_table": _route_table,
    "aws_route": _route,
    "aws_route_table_association": _rt_association,
    "aws_internet_gateway": _igw,
    "aws_internet_gateway_attachment": _igw_attachment,
    "aws_nat_gateway": _nat,
    "aws_ec2_transit_gateway": _tgw,
    "aws_ec2_transit_gateway_vpc_attachment": _tgw_attachment,
    "aws_vpc_peering_connection": _peering,
    "aws_vpc_peering_connection_accepter": _peering_accepter,
    "aws_iam_role": _iam_role,
}

# Types whose effect is an edge/rule fold rather than a node — deletes remove
# the folded effect instead of a node.
FOLD_TYPES = {
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule",
    "aws_route",
    "aws_route_table_association",
    "aws_internet_gateway_attachment",
    "aws_vpc_peering_connection_accepter",
}

# Props merged in place on UPDATE actions (node identity is preserved so the
# baseline diff doesn't mistake a prop change for a new resource).
UPDATE_SCALAR_PROPS = (
    "cidr_block",
    "availability_zone",
    "engine",
    "scheme",
    "private_ip",
    "assume_role_policy",
)
