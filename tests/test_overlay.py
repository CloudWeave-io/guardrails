"""Overlay tests — Terraform plan deltas applied to a two-VPC, two-account graph."""

from __future__ import annotations

from cw_guardrails.engine import evaluate_policy
from cw_guardrails.graph import Graph, Node, build_indexes, subgraph_for_accounts
from cw_guardrails.overlay import overlay_plan
from cw_guardrails.overlay.plan import parse_plan
from cw_guardrails.policy import load_policy

ARN = "arn:aws:ec2:us-east-1"


def _add(g: Graph, uid: str, type_: str, name: str, account: str, **props: object) -> None:
    g.nodes[uid] = Node(
        uid=uid, type=type_, name=name, account=account, region="us-east-1", props=props
    )


def two_vpc_graph() -> Graph:
    """dev (acct 111): public subnet + dev-web (world SSH). prod (acct 222):
    private subnet + prod-db (internal SG). The VPCs are NOT connected."""
    g = Graph()
    _add(
        g,
        f"{ARN}:111:vpc/vpc-aaa",
        "Vpc",
        "dev-vpc",
        "111",
        vpc_id="vpc-aaa",
        cidr_block="10.1.0.0/16",
    )
    _add(
        g,
        f"{ARN}:111:subnet/subnet-pub",
        "Subnet",
        "dev-public",
        "111",
        subnet_id="subnet-pub",
        vpc_id="vpc-aaa",
    )
    _add(g, f"{ARN}:111:route-table/rtb-pub", "RouteTable", "rtb-pub", "111")
    _add(g, f"{ARN}:111:internet-gateway/igw-111", "InternetGateway", "igw-111", "111")
    _add(g, f"{ARN}:111:instance/i-web", "Instance", "dev-web", "111")
    _add(
        g,
        f"{ARN}:111:security-group/sg-open",
        "SecurityGroup",
        "sg-open",
        "111",
        group_id="sg-open",
        inbound=[{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"]}],
    )
    _add(
        g,
        f"{ARN}:222:vpc/vpc-bbb",
        "Vpc",
        "prod-vpc",
        "222",
        vpc_id="vpc-bbb",
        cidr_block="10.2.0.0/16",
    )
    _add(
        g,
        f"{ARN}:222:subnet/subnet-priv",
        "Subnet",
        "prod-private",
        "222",
        subnet_id="subnet-priv",
        vpc_id="vpc-bbb",
    )
    _add(g, f"{ARN}:222:instance/i-db", "Instance", "prod-db", "222")
    _add(
        g,
        f"{ARN}:222:security-group/sg-int",
        "SecurityGroup",
        "sg-int",
        "222",
        group_id="sg-int",
        inbound=[{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidrs": ["10.0.0.0/8"]}],
    )
    g.edges = [
        (f"{ARN}:111:vpc/vpc-aaa", f"{ARN}:111:subnet/subnet-pub", "HAS_SUBNET"),
        (f"{ARN}:111:subnet/subnet-pub", f"{ARN}:111:route-table/rtb-pub", "USES_ROUTE_TABLE"),
        (f"{ARN}:111:route-table/rtb-pub", f"{ARN}:111:internet-gateway/igw-111", "ROUTES_TO"),
        (f"{ARN}:111:subnet/subnet-pub", f"{ARN}:111:instance/i-web", "CONTAINS_INSTANCE"),
        (f"{ARN}:111:instance/i-web", f"{ARN}:111:security-group/sg-open", "PROTECTED_BY"),
        (f"{ARN}:222:vpc/vpc-bbb", f"{ARN}:222:subnet/subnet-priv", "HAS_SUBNET"),
        (f"{ARN}:222:subnet/subnet-priv", f"{ARN}:222:instance/i-db", "CONTAINS_INSTANCE"),
        (f"{ARN}:222:instance/i-db", f"{ARN}:222:security-group/sg-int", "PROTECTED_BY"),
    ]
    build_indexes(g)
    return g


def change(address: str, type_: str, actions: list[str], before=None, after=None, unknown=None):
    return {
        "address": address,
        "type": type_,
        "mode": "managed",
        "change": {
            "actions": actions,
            "before": before,
            "after": after,
            "after_unknown": unknown or {},
        },
    }


def tfplan(*changes, config=None) -> dict:
    plan: dict = {"resource_changes": list(changes)}
    if config:
        plan["configuration"] = {"root_module": {"resources": config}}
    return plan


ISOLATION = load_policy(
    """
version: 1
invariants:
  - id: dev-prod-isolation
    severity: critical
    not_path: { from: { name_matches: "dev-*" }, to: { name_matches: "prod-*" } }
"""
)


def test_parse_skips_noop_and_data_resources():
    plan = tfplan(
        change("aws_vpc.x", "aws_vpc", ["no-op"], after={}),
        {
            "address": "data.aws_ami.x",
            "type": "aws_ami",
            "mode": "data",
            "change": {"actions": ["read"], "before": None, "after": {}, "after_unknown": {}},
        },
        change("aws_vpc.y", "aws_vpc", ["create"], after={"cidr_block": "10.0.0.0/16"}),
    )
    parsed = parse_plan(plan)
    assert [c.address for c in parsed.changes] == ["aws_vpc.y"]


def test_planned_peering_connects_the_vpcs_and_fires_not_path():
    base = two_vpc_graph()
    assert not evaluate_policy(ISOLATION, base).results[0].violations  # baseline clean

    plan = tfplan(
        change(
            "aws_vpc_peering_connection.bridge",
            "aws_vpc_peering_connection",
            ["create"],
            after={"vpc_id": "vpc-aaa", "peer_vpc_id": "vpc-bbb"},
        )
    )
    result = overlay_plan(base, plan)
    assert result.mapped == 1 and not result.unmapped_types
    g = result.graph
    assert g.vpcs_connected(f"{ARN}:111:vpc/vpc-aaa", f"{ARN}:222:vpc/vpc-bbb")

    after = evaluate_policy(ISOLATION, g)
    v = after.results[0].violations
    assert len(v) == 1
    assert v[0].resource == f"{ARN}:222:instance/i-db"
    assert "dev-web" in v[0].message  # the concrete source is named


def test_world_open_rule_folds_onto_live_sg():
    base = two_vpc_graph()
    plan = tfplan(
        change(
            "aws_security_group_rule.open",
            "aws_security_group_rule",
            ["create"],
            after={
                "type": "ingress",
                "security_group_id": "sg-int",
                "protocol": "tcp",
                "from_port": 443,
                "to_port": 443,
                "cidr_blocks": ["0.0.0.0/0"],
            },
        )
    )
    g = overlay_plan(base, plan).graph
    rules = g.nodes[f"{ARN}:222:security-group/sg-int"].props["inbound"]
    assert {
        "protocol": "tcp",
        "from_port": 443,
        "to_port": 443,
        "cidrs": ["0.0.0.0/0"],
        "source_sg_id": None,
    } in rules
    # and the base graph was not mutated
    assert len(base.nodes[f"{ARN}:222:security-group/sg-int"].props["inbound"]) == 1


def test_route_association_flips_private_subnet_public():
    base = two_vpc_graph()
    # bring prod-private under the dev public route table (contrived but legal TF)
    plan = tfplan(
        change(
            "aws_route_table_association.flip",
            "aws_route_table_association",
            ["create"],
            after={"subnet_id": "subnet-priv", "route_table_id": "rtb-pub"},
        )
    )
    g = overlay_plan(base, plan).graph
    assert f"{ARN}:222:subnet/subnet-priv" in g.public_subnets
    assert f"{ARN}:222:subnet/subnet-priv" not in base.public_subnets


def test_route_delete_removes_the_internet_path():
    base = two_vpc_graph()
    plan = tfplan(
        change(
            "aws_route.default",
            "aws_route",
            ["delete"],
            before={"route_table_id": "rtb-pub", "gateway_id": "igw-111"},
        )
    )
    g = overlay_plan(base, plan).graph
    assert g.public_subnets == set()


def test_replace_swaps_uid_but_keeps_placement():
    base = two_vpc_graph()
    plan = tfplan(
        change(
            "aws_instance.web",
            "aws_instance",
            ["delete", "create"],
            before={"arn": f"{ARN}:111:instance/i-web", "id": "i-web"},
            after={"subnet_id": "subnet-pub", "tags": {"Name": "dev-web-v2"}},
        )
    )
    result = overlay_plan(base, plan)
    g = result.graph
    assert f"{ARN}:111:instance/i-web" not in g.nodes
    assert "tf:aws_instance.web" in g.nodes
    assert g.subnet_of["tf:aws_instance.web"] == f"{ARN}:111:subnet/subnet-pub"
    assert "tf:aws_instance.web" in result.planned_uids


def test_unknown_references_resolve_through_configuration():
    base = two_vpc_graph()
    plan = tfplan(
        change(
            "aws_vpc.new",
            "aws_vpc",
            ["create"],
            after={"cidr_block": "10.9.0.0/16"},
            unknown={"id": True},
        ),
        change(
            "aws_subnet.new",
            "aws_subnet",
            ["create"],
            after={"cidr_block": "10.9.1.0/24"},
            unknown={"id": True, "vpc_id": True},
        ),
        change(
            "aws_instance.new",
            "aws_instance",
            ["create"],
            after={"tags": {"Name": "dev-new"}},
            unknown={"id": True, "subnet_id": True},
        ),
        config=[
            {
                "address": "aws_subnet.new",
                "expressions": {"vpc_id": {"references": ["aws_vpc.new.id", "aws_vpc.new"]}},
            },
            {
                "address": "aws_instance.new",
                "expressions": {"subnet_id": {"references": ["aws_subnet.new.id"]}},
            },
        ],
    )
    g = overlay_plan(base, plan).graph
    assert ("tf:aws_vpc.new", "tf:aws_subnet.new", "HAS_SUBNET") in g.edges
    assert g.subnet_of["tf:aws_instance.new"] == "tf:aws_subnet.new"
    assert g.vpc_of_subnet["tf:aws_subnet.new"] == "tf:aws_vpc.new"


def test_unmapped_types_are_surfaced_not_silently_dropped():
    base = two_vpc_graph()
    plan = tfplan(change("aws_s3_bucket.b", "aws_s3_bucket", ["create"], after={"bucket": "b"}))
    result = overlay_plan(base, plan)
    assert result.unmapped_types == ["aws_s3_bucket"]
    assert result.mapped == 0


def test_planned_nodes_survive_per_rule_account_subgraphs():
    base = two_vpc_graph()
    plan = tfplan(
        change(
            "aws_vpc_peering_connection.bridge",
            "aws_vpc_peering_connection",
            ["create"],
            after={"vpc_id": "vpc-aaa", "peer_vpc_id": "vpc-bbb"},
        )
    )
    g = overlay_plan(base, plan).graph
    sub = subgraph_for_accounts(g, {"111", "222"})
    assert "tf:aws_vpc_peering_connection.bridge" in sub.nodes
    assert sub.vpcs_connected(f"{ARN}:111:vpc/vpc-aaa", f"{ARN}:222:vpc/vpc-bbb")


def test_noop_plan_changes_nothing():
    base = two_vpc_graph()
    result = overlay_plan(base, tfplan())
    assert result.mapped == 0
    assert set(result.graph.nodes) == set(base.nodes)
    assert sorted(result.graph.edges) == sorted(base.edges)
