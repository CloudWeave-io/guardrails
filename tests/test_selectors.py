import pytest

from cw_guardrails.policy import SelectorSpec
from cw_guardrails.selectors import INTERNET, resolve


def test_by_type(graph):
    assert resolve(SelectorSpec(type="Instance"), graph, {}) == {"web", "db"}
    assert resolve(SelectorSpec(type=["Subnet"]), graph, {}) == {"subPub", "subPriv"}


def test_name_matches(graph):
    assert resolve(SelectorSpec(name_matches="*prod*"), graph, {}) == {"db"}
    assert resolve(SelectorSpec(name_matches="web*|*prod"), graph, {}) == {"web", "db"}


def test_group_reference(graph):
    groups = {"servers": SelectorSpec(type="Instance")}
    assert resolve("servers", graph, groups) == {"web", "db"}


def test_internet_pseudo(graph):
    assert resolve("internet", graph, {}) == {INTERNET}
    assert resolve(SelectorSpec(pseudo="internet"), graph, {}) == {INTERNET}


def test_unknown_group_raises(graph):
    with pytest.raises(KeyError):
        resolve("nope", graph, {})
