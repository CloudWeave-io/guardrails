from cw_guardrails.suggest import suggest_rules


def test_suggest_classifies_ratchet_and_fixfirst(graph):
    cands = {c.id: c for c in suggest_rules(graph)}  # no driver -> shared-tgw skipped

    assert "no-cross-account-shared-tgw" not in cands  # needs a driver

    # sgOpen exposes SSH to the world -> fix-first
    assert cands["no-world-open-admin-ports"].kind == "fix-first"
    assert cands["no-world-open-admin-ports"].violations

    # no RDS at all -> vacuously passing forward-guard
    assert cands["database-not-internet-reachable"].kind == "ratchet"

    # web is in a public subnet -> egress bypasses NAT -> fix-first
    assert cands["instance-egress-only-via-nat"].kind == "fix-first"
    assert any("web" in v for v in cands["instance-egress-only-via-nat"].violations)

    # every candidate carries an appendable YAML rule body
    assert all(":" in c.rule_yaml for c in cands.values())


def test_suggest_new_generators(graph):
    cands = {c.id: c for c in suggest_rules(graph)}

    # sgOpen exposes a world-open port → fix-first
    assert cands["no-world-open-ingress"].kind == "fix-first"
    assert cands["no-world-open-ingress"].violations

    # web sits in a public subnet with a world-open SG → internet-reachable → fix-first
    assert cands["instance-not-internet-reachable"].kind == "fix-first"
    assert any("web" in v for v in cands["instance-not-internet-reachable"].violations)

    # both instances are protected by a security group → ratchet
    assert cands["instances-have-security-group"].kind == "ratchet"

    # the public subnet has no NetworkACL neighbor → fix-first
    assert cands["public-subnet-has-nacl"].kind == "fix-first"
