from cw_guardrails.reachability import (
    INTERNET,
    any_reach,
    egress_bypass,
    internet_facing,
    reaches,
)


def test_internet_facing_only_public_open(graph):
    facing = internet_facing(graph)
    assert "web" in facing  # public subnet + world-open SG
    assert "db" not in facing  # private subnet
    assert facing["web"][0] == INTERNET


def test_lateral_reach_same_vpc(graph):
    # db's SG admits 10/8 (private) -> web can reach db
    path = reaches(graph, "web", "db")
    assert path == ["web", "db"]


def test_any_reach_from_internet(graph):
    hit = any_reach(graph, {INTERNET}, {"web"})
    assert hit is not None and hit[1] == "web"
    # db is not internet-facing
    assert any_reach(graph, {INTERNET}, {"db"}) is None


def test_egress_bypass_public_only(graph):
    bypass = dict(egress_bypass(graph, {"web", "db"}, set()))
    assert "web" in bypass  # public subnet -> egresses via IGW
    assert "db" not in bypass  # private subnet
