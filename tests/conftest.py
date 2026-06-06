"""Shared fixtures: a small hand-built graph (no Neo4j needed)."""

from __future__ import annotations

import pytest

from cw_guardrails.graph import Graph, Node, build_indexes


def _add(g: Graph, uid: str, type_: str, name: str = "", **props) -> None:
    g.nodes[uid] = Node(
        uid=uid,
        type=type_,
        name=name or uid,
        account="111111111111",
        region="us-east-1",
        props=props,
    )


def _edge(g: Graph, s: str, d: str, rel: str) -> None:
    g.edges.append((s, d, rel))


@pytest.fixture
def graph() -> Graph:
    """vpc1 { public subnet [web: world-open SG] , private subnet [db: 10/8 SG] }."""
    g = Graph()
    _add(g, "vpc1", "Vpc", "vpc-main", vpc_id="vpc-1")
    _add(g, "subPub", "Subnet", "public-subnet")
    _add(g, "subPriv", "Subnet", "private-subnet")
    _add(g, "rtPub", "RouteTable", "rt-public")
    _add(g, "igw", "InternetGateway", "igw-1")
    _add(
        g,
        "sgOpen",
        "SecurityGroup",
        "sg-open",
        inbound=[{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"]}],
    )
    _add(
        g,
        "sgClosed",
        "SecurityGroup",
        "sg-closed",
        inbound=[{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidrs": ["10.0.0.0/8"]}],
    )
    _add(g, "web", "Instance", "web-server")
    _add(g, "db", "Instance", "db-prod")

    _edge(g, "vpc1", "subPub", "HAS_SUBNET")
    _edge(g, "vpc1", "subPriv", "HAS_SUBNET")
    _edge(g, "subPub", "rtPub", "USES_ROUTE_TABLE")
    _edge(g, "rtPub", "igw", "ROUTES_TO")
    _edge(g, "subPub", "web", "CONTAINS_INSTANCE")
    _edge(g, "subPriv", "db", "CONTAINS_INSTANCE")
    _edge(g, "web", "sgOpen", "PROTECTED_BY")
    _edge(g, "db", "sgClosed", "PROTECTED_BY")

    build_indexes(g)
    return g
