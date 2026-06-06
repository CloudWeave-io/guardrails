import pytest
from pydantic import ValidationError

from cw_guardrails.policy import load_policy

_VALID = """
version: 1
scope: { accounts: ["111111111111"], regions: ["us-east-1"] }
groups:
  internet: { pseudo: internet }
  db: { type: [RdsInstance], tag: "env=prod" }
invariants:
  - id: db-not-public
    severity: critical
    not_path: { from: internet, to: db }
"""


def test_load_valid():
    p = load_policy(_VALID)
    assert p.scope.accounts == ["111111111111"]
    inv = p.invariants[0]
    assert inv.predicate_kind == "not_path"
    # 'from' alias parsed into from_
    assert inv.not_path.from_ == "internet"
    assert inv.not_path.to == "db"


def test_exactly_one_predicate_two():
    bad = """
version: 1
invariants:
  - id: x
    not_public: { select: { type: Instance } }
    not_in_public_subnet: { select: { type: Instance } }
"""
    with pytest.raises(ValidationError):
        load_policy(bad)


def test_exactly_one_predicate_none():
    bad = """
version: 1
invariants:
  - id: x
    severity: high
"""
    with pytest.raises(ValidationError):
        load_policy(bad)


def test_unknown_predicate_key_rejected():
    bad = """
version: 1
invariants:
  - id: x
    not_a_real_predicate: { select: {} }
"""
    with pytest.raises(ValidationError):
        load_policy(bad)
