from cw_guardrails.engine import evaluate_policy
from cw_guardrails.models import Status
from cw_guardrails.policy import load_policy
from cw_guardrails.report import render_json, render_sarif, render_text

_POLICY = """
version: 1
scope: { accounts: ["111111111111"] }
groups:
  internet: { pseudo: internet }
invariants:
  - id: no-public-instance
    severity: critical
    not_public: { select: { type: Instance } }
  - id: ssh-locked
    severity: critical
    not_ingress: { select: { type: SecurityGroup }, ports: [443], from: "0.0.0.0/0" }
"""


def test_evaluate_pass_and_fail(graph):
    report = evaluate_policy(load_policy(_POLICY), graph)
    by_id = {r.id: r for r in report.results}
    assert by_id["no-public-instance"].status == Status.FAIL  # web is public
    assert by_id["ssh-locked"].status == Status.PASS  # 443 rule is 10/8
    assert report.exit_code() == 1


def test_waiver_downgrades(graph):
    waived = (
        _POLICY
        + """
waivers:
  - invariant: no-public-instance
    target: { id: web }
    reason: approved edge node
    expires: 2099-01-01
"""
    )
    report = evaluate_policy(load_policy(waived), graph)
    r = next(x for x in report.results if x.id == "no-public-instance")
    assert r.status == Status.WAIVED
    assert report.exit_code() == 0  # nothing active left


def test_expired_waiver_rearms(graph):
    expired = (
        _POLICY
        + """
waivers:
  - invariant: no-public-instance
    target: { id: web }
    reason: stale
    expires: 2000-01-01
"""
    )
    report = evaluate_policy(load_policy(expired), graph)
    r = next(x for x in report.results if x.id == "no-public-instance")
    assert r.status == Status.FAIL  # expired waiver does not suppress


def test_renderers(graph):
    import json

    report = evaluate_policy(load_policy(_POLICY), graph)
    assert "FAIL" in render_text(report)
    assert json.loads(render_json(report))["results"]
    sarif = json.loads(render_sarif(report))
    assert sarif["runs"][0]["results"]
