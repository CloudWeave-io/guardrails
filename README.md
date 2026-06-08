# CloudWeave Guardrails

Architecture **invariants as code**, verified against the live CloudWeave graph.

You declare the rules your architecture must always satisfy — *"the internet must
never reach the database", "dev must never reach prod", "no world-open SSH"* — and
Guardrails checks them against the real, scanned cloud (and, later, against a
Terraform plan in CI before it merges).

> 📖 **Full documentation:** [`docs/guardrails.md`](docs/guardrails.md) — concepts,
> CLI, library, platform integration (backend + 🚦 frontend tab), the reachability
> model, and engine internals. Policy language reference:
> [`docs/policy-reference.md`](docs/policy-reference.md).

## How it works

```
weave.guardrails.yaml ─▶ engine ─▶ GuardrailReport
                          ▲
   live graph (Neo4j) ────┘   selectors → predicates → reachability
```

A policy is `scope` + named `groups` (selectors) + `invariants` (rules). Each rule
picks a set of resources and states a constraint on it.

```yaml
version: 1
scope: { accounts: ["1234..."], regions: ["us-east-1"] }
groups:
  internet:  { pseudo: internet }
  sensitive: { type: [LambdaFunction, Instance], name_matches: "*data*|*secret*" }
invariants:
  - id: sensitive-not-internet-reachable
    severity: critical
    not_path: { from: internet, to: sensitive }
```

### Predicate catalog
`not_ingress` · `not_public` · `not_in_public_subnet` · `not_path(from,to)` ·
`only_via(through)` · `property` · `must_have` · `no_shared_tgw`.

### Selectors
`type` · `tag` · `name_matches` (glob + `|`) · `account` · `region` · `cidr` ·
`id` · `pseudo: internet`. Name a selector under `groups:` to reuse it.

### Waivers
Explicit, expiring exceptions. An expired waiver re-arms the finding.

## CLI

```bash
# check a policy against the live graph (exit 1 on high/critical failure)
cw-guardrails check --policy weave.guardrails.yaml -f text|json|sarif

# generate candidate rules from your live cloud (ratchet / fix-first)
cw-guardrails suggest --account 1234... --region us-east-1
```

`policies/starter-pack.yaml` is a library of common rules to copy from.

## Library

```python
from neo4j import GraphDatabase
from cw_guardrails import evaluate_guardrails

driver = GraphDatabase.driver(...)
report = evaluate_guardrails(open("weave.guardrails.yaml","rb").read(), neo4j_driver=driver)
report.exit_code()   # 0 clean, 1 blocking failure
```

## Layout

```
src/cw_guardrails/
  policy.py        pydantic policy models + YAML loader
  graph.py         in-memory graph + account-scoped Neo4j fetch
  selectors.py     selector → set of nodes
  reachability.py  internet exposure, lateral reach, chokepoint (ported semantics)
  predicates.py    one evaluator per predicate kind
  engine.py        evaluate_policy + waivers
  suggest.py       generate candidate rules from the live graph
  report.py        text / json / sarif renderers
  cli.py / entry.py
policies/          starter pack + demo policy
tests/             fixture-based unit tests (no Neo4j needed)
```

## Reachability — scope & non-goals

Ported from the AI-Agent reachability checkers, reduced to what the predicates
need and kept **deterministic** so it can run over a Terraform-overlaid graph in
CI. Models: internet exposure (public subnet + world-open SG), lateral reach
(network-connected VPCs gated by SGs), and egress chokepoints. **Not yet** modeled
(follow-ups, matching AI-Agent's fuller checkers): NACL rule ordering, per-route
TGW blackholes, exact host-IP CIDR math.

## Dev

```bash
pip install -e ".[dev]"
pytest && ruff check src tests && mypy src
```
