"""PR-gate pieces: baseline diff, gate modes, hybrid merge, NEW-aware rendering."""

from __future__ import annotations

import json

import pytest
from test_overlay import ARN, change, tfplan, two_vpc_graph

from cw_guardrails.diff import annotate_new
from cw_guardrails.engine import evaluate_policy
from cw_guardrails.merge import PolicyMergeError, merge_policies
from cw_guardrails.overlay import overlay_plan
from cw_guardrails.policy import load_policy
from cw_guardrails.report import render_sarif, render_text

POLICY = load_policy(
    """
version: 1
invariants:
  - id: dev-prod-isolation
    severity: critical
    not_path: { from: { name_matches: "dev-*" }, to: { name_matches: "prod-*" } }
  - id: no-world-ssh
    severity: high
    not_ingress: { select: { type: SecurityGroup }, ports: [22], from: "0.0.0.0/0" }
"""
)

PEERING_PLAN = tfplan(
    change(
        "aws_vpc_peering_connection.bridge",
        "aws_vpc_peering_connection",
        ["create"],
        after={"vpc_id": "vpc-aaa", "peer_vpc_id": "vpc-bbb"},
    )
)


def _diffed_report():
    base = two_vpc_graph()
    baseline = evaluate_policy(POLICY, base)
    after = evaluate_policy(POLICY, overlay_plan(base, PEERING_PLAN).graph)
    return annotate_new(baseline, after)


def test_annotate_marks_only_what_the_plan_introduced():
    report = _diffed_report()
    by_id = {r.id: r for r in report.results}
    assert all(v.new is True for v in by_id["dev-prod-isolation"].violations)
    assert all(v.new is False for v in by_id["no-world-ssh"].violations)  # pre-existing debt
    assert report.summary()["new_violations"] == 1


def test_gate_modes():
    report = _diffed_report()
    assert report.gate_failed("new-high") is True  # critical NEW violation
    assert report.gate_failed("new-any") is True
    assert report.gate_failed("all-high") is True  # strict counts the old debt too


def test_gate_ignores_preexisting_and_low_severity_news():
    low_policy = load_policy(
        """
version: 1
invariants:
  - id: low-isolation
    severity: low
    not_path: { from: { name_matches: "dev-*" }, to: { name_matches: "prod-*" } }
"""
    )
    base = two_vpc_graph()
    baseline = evaluate_policy(low_policy, base)
    after = evaluate_policy(low_policy, overlay_plan(base, PEERING_PLAN).graph)
    report = annotate_new(baseline, after)
    assert report.gate_failed("new-high") is False  # new, but only low severity
    assert report.gate_failed("new-any") is True


def test_text_and_sarif_mark_new_and_downgrade_preexisting():
    report = _diffed_report()
    text = render_text(report)
    assert "NEW " in text and "1 NEW violation" in text

    sarif = json.loads(render_sarif(report))
    results = sarif["runs"][0]["results"]
    new = [x for x in results if x["properties"]["new"]]
    old = [x for x in results if not x["properties"]["new"]]
    assert new and all(x["level"] == "error" for x in new)
    assert all(x["message"]["text"].startswith("NEW: ") for x in new)
    assert old and all(x["level"] == "note" for x in old)


# ── hybrid merge ─────────────────────────────────────────────────────────────
STORED = load_policy(
    """
version: 1
groups:
  internet: { pseudo: internet }
invariants:
  - id: floor-rule
    severity: critical
    not_path: { from: internet, to: { type: Instance } }
waivers:
  - invariant: floor-rule
    reason: "stored waiver"
"""
)


def test_merge_none_returns_stored_unchanged():
    merged, warnings = merge_policies(STORED, None)
    assert merged is STORED and warnings == []


def test_merge_adds_namespaced_repo_rules_and_keeps_floor():
    repo = """
version: 1
groups:
  team_db: { type: RdsInstance }
invariants:
  - id: extra-strict
    severity: high
    not_public: { select: team_db }
"""
    merged, warnings = merge_policies(STORED, repo)
    assert [i.id for i in merged.invariants] == ["floor-rule", "repo/extra-strict"]
    assert set(merged.groups) == {"internet", "team_db"}
    assert merged.waivers == STORED.waivers
    assert warnings == []


def test_merge_rejects_repo_waivers():
    repo = """
version: 1
invariants:
  - id: x
    not_public: { select: { type: Instance } }
waivers:
  - invariant: floor-rule
    reason: "sneaky"
"""
    with pytest.raises(PolicyMergeError, match="waivers"):
        merge_policies(STORED, repo)


def test_merge_rejects_group_redefinition():
    repo = """
version: 1
groups:
  internet: { type: Instance }
invariants:
  - id: x
    not_public: { select: { type: Instance } }
"""
    with pytest.raises(PolicyMergeError, match="internet"):
        merge_policies(STORED, repo)


def test_merge_rejects_duplicate_repo_ids_and_warns_on_scope():
    dup = """
version: 1
invariants:
  - id: x
    not_public: { select: { type: Instance } }
  - id: x
    not_public: { select: { type: RdsInstance } }
"""
    with pytest.raises(PolicyMergeError, match="duplicate"):
        merge_policies(STORED, dup)

    scoped = """
version: 1
scope:
  accounts: ["999"]
invariants:
  - id: x
    not_public: { select: { type: Instance } }
"""
    merged, warnings = merge_policies(STORED, scoped)
    assert merged.scope == STORED.scope
    assert any("scope" in w for w in warnings)


def test_repo_rule_may_reference_stored_groups():
    repo = """
version: 1
invariants:
  - id: uses-floor-group
    severity: medium
    not_path: { from: internet, to: { name_matches: "prod-*" } }
"""
    base = two_vpc_graph()
    merged, _ = merge_policies(STORED, repo)
    report = evaluate_policy(merged, base)
    assert {r.id for r in report.results} == {"floor-rule", "repo/uses-floor-group"}
    assert all(r.status != "error" for r in report.results)


def test_violation_path_survives_overlay_with_planned_uid():
    report = _diffed_report()
    iso = next(r for r in report.results if r.id == "dev-prod-isolation")
    assert iso.violations[0].path  # evidence path present
    assert iso.violations[0].path[0] == f"{ARN}:111:instance/i-web"
