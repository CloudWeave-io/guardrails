"""Resolve a selector (inline spec, group name, or pseudo) to a set of node uids."""

from __future__ import annotations

import ipaddress
import re

from cw_guardrails.graph import Graph
from cw_guardrails.policy import SelectorSpec

INTERNET = "__internet__"


def glob_re(pattern: str) -> re.Pattern[str]:
    """Translate a 'a*|b*' glob/alternation into a compiled regex."""
    alts = [re.escape(a.strip()).replace(r"\*", ".*") for a in pattern.split("|")]
    return re.compile("|".join(f"(?:{a})" for a in alts), re.I)


def resolve(selector, graph: Graph, groups: dict[str, SelectorSpec]) -> set[str]:
    """Return the set of node uids a selector matches.

    `selector` is a SelectorSpec, or a string naming a group, or a string
    "internet" pseudo-selector.
    """
    if isinstance(selector, str):
        if selector == "internet":
            return {INTERNET}
        if selector in groups:
            selector = groups[selector]
        else:
            raise KeyError(f"unknown group or pseudo-selector: {selector!r}")
    spec: SelectorSpec = selector

    if spec.pseudo == "internet":
        return {INTERNET}

    out = set(graph.nodes)
    if spec.type is not None:
        types = {spec.type} if isinstance(spec.type, str) else set(spec.type)
        out &= {u for u, n in graph.nodes.items() if n.type in types}
    if spec.name_matches is not None:
        rx = glob_re(spec.name_matches)
        out &= {u for u, n in graph.nodes.items() if rx.search(n.name)}
    if spec.account is not None:
        out &= {u for u, n in graph.nodes.items() if n.account == spec.account}
    if spec.region is not None:
        out &= {u for u, n in graph.nodes.items() if n.region == spec.region}
    if spec.id is not None:
        out &= {spec.id} if spec.id in graph.nodes else set()
    if spec.tag is not None:
        out &= {u for u, n in graph.nodes.items() if _has_tag(n.props, spec.tag)}
    if spec.cidr is not None:
        out &= {u for u, n in graph.nodes.items() if _in_cidr(n.props, spec.cidr)}
    return out


def _has_tag(props: dict, tag: str) -> bool:
    key, _, value = tag.partition("=")
    tags = props.get("tags") or props.get("Tags") or {}
    if isinstance(tags, list):  # [{"Key":..,"Value":..}]
        tags = {t.get("Key"): t.get("Value") for t in tags if isinstance(t, dict)}
    if not isinstance(tags, dict):
        return False
    if key not in tags and key not in props:
        return False
    if not value:
        return True
    return str(tags.get(key, props.get(key))) == value


def _in_cidr(props: dict, cidr: str) -> bool:
    block = props.get("cidrBlock") or props.get("CidrBlock") or props.get("cidr_block")
    if not block:
        return False
    try:
        net = ipaddress.ip_network(str(block))
        parent = ipaddress.ip_network(cidr)
        return net.version == parent.version and net.subnet_of(parent)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return False
