from cw_guardrails.policy import Invariant, SelectorSpec
from cw_guardrails.predicates import EvalContext, EVALUATORS

CTX = EvalContext(groups={})


def _run(kind, graph, **kw):
    inv = Invariant(id="t", **{kind: kw})
    return EVALUATORS[kind](inv, graph, CTX)


def test_not_ingress_flags_world_open_ssh(graph):
    v = _run(
        "not_ingress",
        graph,
        select=SelectorSpec(type="SecurityGroup"),
        ports=[22],
        **{"from": "0.0.0.0/0"},
    )
    assert {x.resource for x in v} == {"sgOpen"}


def test_not_ingress_ignores_private_source(graph):
    v = _run(
        "not_ingress",
        graph,
        select=SelectorSpec(type="SecurityGroup"),
        ports=[443],
        **{"from": "0.0.0.0/0"},
    )
    assert v == []  # the 443 rule is 10/8, not world


def test_not_public(graph):
    v = _run("not_public", graph, select=SelectorSpec(type="Instance"))
    assert {x.resource for x in v} == {"web"}


def test_not_in_public_subnet(graph):
    v = _run("not_in_public_subnet", graph, select=SelectorSpec(type="Instance"))
    assert {x.resource for x in v} == {"web"}


def test_not_path_lateral(graph):
    v = _run(
        "not_path",
        graph,
        **{
            "from": SelectorSpec(type="Instance", name_matches="web*"),
            "to": SelectorSpec(name_matches="*prod"),
        },
    )
    assert {x.resource for x in v} == {"db"}


def test_not_path_message_names_the_concrete_source(graph):
    v = _run(
        "not_path",
        graph,
        **{
            "from": SelectorSpec(type="Instance", name_matches="web*"),
            "to": SelectorSpec(name_matches="*prod"),
        },
    )
    assert "Instance 'web-server'" in v[0].message  # not "the source set"
    assert v[0].path  # evidence path present


def test_not_ingress_message_is_humanized(graph):
    v = _run(
        "not_ingress",
        graph,
        select=SelectorSpec(type="SecurityGroup"),
        ports=[22],
        **{"from": "0.0.0.0/0"},
    )
    assert v[0].message == "sg-open allows tcp port 22 from 0.0.0.0/0 (matched port 22)"


def test_not_ingress_all_traffic_rule_reads_as_all_traffic(graph):
    # The scanner encodes a protocol -1 (allow everything) rule as port 0-0.
    graph.nodes["sgOpen"].props["inbound"] = [
        {"protocol": "-1", "from_port": 0, "to_port": 0, "cidrs": ["0.0.0.0/0"]}
    ]
    v = _run(
        "not_ingress",
        graph,
        select=SelectorSpec(type="SecurityGroup"),
        ports=[0],
        **{"from": "0.0.0.0/0"},
    )
    assert v[0].message == "sg-open allows ALL traffic (every port and protocol) from 0.0.0.0/0"


def test_only_via_egress(graph):
    v = _run(
        "only_via",
        graph,
        **{
            "from": SelectorSpec(type="Instance"),
            "to": "internet",
            "through": SelectorSpec(type="NatGateway"),
        },
    )
    assert {x.resource for x in v} == {"web"}  # only the public-subnet instance bypasses
