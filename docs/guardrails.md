# CloudWeave Guardrails — Full Documentation

> Architecture **invariants as code**, verified against the live CloudWeave graph.

This is the complete guide to the Guardrails feature: what it is, how to use it
(CLI, library, and the platform UI), and how the code behind it works end to end.

- New to Guardrails? Start at [Concepts](#1-concepts).
- Just want to write rules? Jump to the [Policy Reference](./policy-reference.md).
- Want to understand the implementation? See [Engine internals](#5-engine-internals)
  and [Platform integration](#6-platform-integration-back--frontend).

---

## Table of contents

1. [Concepts](#1-concepts)
2. [The three ways to use Guardrails](#2-the-three-ways-to-use-guardrails)
3. [Writing a policy](#3-writing-a-policy)
4. [The CLI](#4-the-cli)
5. [Engine internals](#5-engine-internals)
6. [Platform integration (backend + frontend)](#6-platform-integration-backend--frontend)
7. [The reachability model](#7-the-reachability-model)
8. [Authoring path #2: suggestions](#8-authoring-path-2-suggestions)
9. [Waivers](#9-waivers)
10. [Output formats & exit codes](#10-output-formats--exit-codes)
11. [Testing & development](#11-testing--development)
12. [Scope, limits & roadmap](#12-scope-limits--roadmap)

---

## 1. Concepts

Most cloud security tooling checks **individual resources** ("is this bucket
public?"). Guardrails checks **relationships and reachability** — the things that
only exist once you assemble the whole architecture:

- *"the internet must never reach the database"*
- *"dev must never reach prod"*
- *"no world-open SSH"*
- *"instance egress must go through the NAT"*
- *"no VPC may share a transit gateway with another account"*

You declare these as **invariants** — rules your architecture must *always*
satisfy — and the engine checks them against the real, scanned cloud graph in
Neo4j. The same deterministic engine is designed to later run over a
**Terraform-plan-overlaid graph in CI**, so a violation can be caught *before* it
merges.

```
weave.guardrails.yaml ─▶ engine ─▶ GuardrailReport
                          ▲
   live graph (Neo4j) ────┘   selectors → predicates → reachability
```

### The shape of a rule

Every invariant is the same three-part sentence:

> **pick a set of resources** (a *selector*) → **state a constraint on it**
> (a *predicate*) → **set a severity**.

```yaml
version: 1
scope: { accounts: ["123456789012"], regions: ["us-east-1"] }
groups:
  internet:  { pseudo: internet }
  sensitive: { type: [LambdaFunction, Instance], name_matches: "*data*|*secret*" }
invariants:
  - id: sensitive-not-internet-reachable
    severity: critical
    not_path: { from: internet, to: sensitive }
```

---

## 2. The three ways to use Guardrails

Guardrails ships as one engine with three front doors:

| Surface | Who it's for | Entry point |
|---|---|---|
| **CLI** (`cw-guardrails`) | engineers, CI pipelines | `src/cw_guardrails/cli.py` |
| **Python library** (`cw_guardrails`) | other services (the platform backend) | `evaluate_guardrails(...)` |
| **Platform UI** (🚦 tab) | everyone, no YAML required | `frontend/src/guardrails/` + backend `api/guardrails.py` |

All three resolve to the **same** `evaluate_guardrails()` → `GuardrailReport`
path. The CLI talks to Neo4j directly; the platform wraps the library as an
authenticated, multi-tenant feature with persisted policies and historical
reports.

---

## 3. Writing a policy

A policy (`weave.guardrails.yaml`) has four parts:

```yaml
version: 1
scope:    { accounts: ["1234..."], regions: ["us-east-1"] }   # which cloud to check
groups:   { web: { tag: "tier=web" } }                        # named, reusable selectors
invariants:                                                    # the rules
  - id: ...
    severity: ...
    <predicate>: { ... }
waivers:  [ ... ]                                              # expiring exceptions
```

### Selectors — how you point at resources

A selector is an inline object whose fields **AND** together, the **name of a
group**, or the **`internet`** pseudo-selector. All fields are optional.

| Field | Matches |
|---|---|
| `type` | resource type, or a list of types |
| `tag` | a resource tag (`key=value`, or just `key` = "present") |
| `name_matches` | name glob; `*` wildcard, `\|` alternation |
| `account` | owning account id |
| `region` | region |
| `cidr` | resource's CIDR block is inside this CIDR |
| `id` | one exact resource uid (ARN) |
| `pseudo: internet` | the public internet (use as a path source/target) |

### The predicate catalog

| Predicate | Asserts |
|---|---|
| `not_ingress` | no security group in `select` has an open inbound rule on `ports` from `from` |
| `not_public` | nothing in `select` is inbound-reachable from the internet |
| `not_in_public_subnet` | nothing in `select` sits in an IGW-routed subnet (placement, not reachability) |
| `not_path` | no network path exists from `from` to `to` (the isolation workhorse) |
| `only_via` | every path from `from` to `to` must traverse `through` (a chokepoint) |
| `property` | each resource's `field` must `equals` / be `in` / `matches` a constraint |
| `must_have` | each resource must be related to a neighbor of type `has` |
| `no_shared_tgw` | no VPC in `select` attaches to a transit gateway shared with other accounts |

Every invariant declares **exactly one** predicate — this is enforced by a
pydantic validator (`Invariant._exactly_one_predicate`).

The full field-by-field spec with examples for every predicate lives in
**[`docs/policy-reference.md`](./policy-reference.md)**. Two ready-made policies
ship in [`policies/`](../policies):

- `starter-pack.yaml` — a library of common rules to copy from.
- `demo-219130470859.yaml` — exercises every predicate kind against the live demo
  account.

---

## 4. The CLI

```bash
pip install -e .          # or install the cw-guardrails wheel

# Check a policy against the live graph (exit 1 on any high/critical failure)
cw-guardrails check --policy weave.guardrails.yaml -f text     # or json | sarif

# Override the policy's scope from the command line
cw-guardrails check -p weave.guardrails.yaml --account 123456789012 --region us-east-1

# Write SARIF for GitHub code scanning
cw-guardrails check -p weave.guardrails.yaml -f sarif -o guardrails.sarif

# Generate candidate rules from your live cloud (ratchet / fix-first)
cw-guardrails suggest --account 123456789012 --region us-east-1
```

### Neo4j connection

The CLI connects with the standard Neo4j env vars (or flags):

| Env var | Flag | Default |
|---|---|---|
| `NEO4J_URI` | `--neo4j-uri` | `bolt://localhost:7687` |
| `NEO4J_USER` | `--neo4j-user` | `neo4j` |
| `NEO4J_PASSWORD` | `--neo4j-password` | `neo4j` |

### `check` flags

| Flag | Meaning |
|---|---|
| `--policy` / `-p` | path to the policy YAML (required) |
| `--account` / `-a` | account id, repeatable — **overrides** `scope.accounts` |
| `--region` / `-r` | region, repeatable — overrides `scope.regions` |
| `--format` / `-f` | `text` (default), `json`, or `sarif` |
| `--out` / `-o` | write to a file instead of stdout |

`check` exits **1** if any failing invariant is `high` or `critical`; otherwise
**0**. That's the contract a CI gate keys off.

---

## 5. Engine internals

The package layout (`src/cw_guardrails/`):

```
policy.py        pydantic policy INPUT models + YAML loader
models.py        result models (Severity, Violation, GuardrailReport) — what the engine EMITS
graph.py         in-memory Graph + account-scoped Neo4j fetch + derived indexes
selectors.py     selector → set of node uids
reachability.py  internet exposure, lateral reach, egress chokepoint
predicates.py    one evaluator per predicate kind → list[Violation]
engine.py        evaluate_policy: run every invariant, apply waivers, build report
suggest.py       generate candidate rules from the live graph
report.py        text / json / sarif renderers
entry.py         evaluate_guardrails: fetch graph + evaluate (the library entrypoint)
cli.py           the cw-guardrails Typer app
```

### The data flow of one evaluation

```
policy YAML ──load_policy()──▶ Policy (pydantic)
                                  │
account/region scope             │
        │                        ▼
   fetch_graph(driver) ────▶ Graph (nodes, edges, derived indexes)
                                  │
                                  ▼
        evaluate_policy(policy, graph)
                                  │  for each invariant:
                                  │    EVALUATORS[kind](inv, graph, ctx) → list[Violation]
                                  │    _apply_waivers(...)  → (active, waived)
                                  │    status = FAIL / WAIVED / PASS / ERROR
                                  ▼
                          GuardrailReport
```

### `policy.py` — the contract surface

This is the **single source of truth for what you can express**. It defines:

- `SelectorSpec` — the selector vocabulary (all fields optional, `extra="forbid"`
  so typos are rejected at parse time).
- One pydantic model per predicate's parameter block (`NotIngress`, `FromTo`,
  `OnlyVia`, `PropertyCheck`, `MustHave`, `SelectOnly`).
- The `PREDICATES` map: YAML key → (attribute name, model).
- `Invariant`, with a `model_validator` that enforces **exactly one** predicate
  per rule, and `predicate_kind` / `predicate` accessor properties.
- `Waiver`, including a validator that normalizes an unquoted YAML date
  (`2026-09-01`, which PyYAML parses to a `date`) back into a string.
- `load_policy(source)` — `yaml.safe_load` + `Policy.model_validate`.

Because YAML is a JSON superset, `load_policy` accepts JSON too.

### `models.py` — what the engine emits

- `Severity` (`info`→`critical`) and `SEV_RANK`. `FAIL_THRESHOLD` is the rank of
  `high`: a failing invariant at or above it makes the run exit non-zero.
- `Status`: `pass` / `fail` / `waived` / `error`.
- `Violation` — one concrete breach with `resource` uid, friendly `name`,
  human-readable `message`, an evidence `path` (list of uids), and an optional
  `waiver_reason`.
- `InvariantResult` — per-rule outcome (status + active violations + waived ones).
- `GuardrailReport` — the top-level result. `exit_code()`, `summary()`, and
  `failed`/`passed` live here. **This is the stable public object** the CLI,
  library callers, and the platform all consume.

### `graph.py` — the in-memory graph

The engine **never** queries Neo4j directly during evaluation. It fetches once
into an in-memory `Graph`, so the exact same code path works on the live graph
and (later) on a graph with a Terraform delta overlaid.

`fetch_graph(driver, account_id, regions)`:

1. Walks `(:AwsAccount {uid})-[*0..5]->(n)` scoped to the account, filtering by
   region when regions are given. Fetch semantics are ported from the
   document-ingestion reconciliation engine.
2. Picks the **specific** Neo4j label per node (skips the generic `:CloudResource`
   / `:Resource` meta-labels) via `node_type()`.
3. Folds `SecurityGroup -[:HAS_INBOUND_RULE]-> :SGRule` rows back onto their
   group as `props["inbound"]`.
4. Calls `build_indexes()`.

`build_indexes(g)` computes the derived indexes that power reachability — and
it's idempotent, so tests build a `Graph` by hand and call it directly (no Neo4j
needed):

- `public_subnets` — subnets whose route table `ROUTES_TO` an `InternetGateway`.
- `subnet_of` — resource uid → its subnet (from `CONTAINS_INSTANCE` /
  `CONTAINS_LAMBDA`).
- `vpc_of_subnet` — subnet → VPC (from `HAS_SUBNET`).
- `protected_by` — resource → its security groups (from `PROTECTED_BY`).
- `_vpc_parent` — a **union-find** over network-connected VPCs: two VPCs are
  unioned if they `PEERS_WITH` or share a transit gateway (via
  `TgwVpcAttachment`). `vpcs_connected(a, b)` then answers "are these two VPCs on
  the same network?" in near-constant time.

`sg_admits(graph, dst, src)` is the security-group gate used by lateral
reachability. Documented approximation: a destination admits a source when an
inbound rule is world-open, references the source's SG, or is an RFC1918 CIDR
(any in-cloud private source). A destination with **no** inbound rules is closed
(default-deny); a resource with no SG at all is treated as open.

### `selectors.py` — resolving a selector to uids

`resolve(selector, graph, groups)` returns a `set[str]` of node uids. A string is
either `"internet"` (→ the `INTERNET` sentinel) or a group name; otherwise it's a
`SelectorSpec` whose set fields are intersected (`AND`). Helpers handle tag
matching (dict or `[{Key,Value}]` shapes), CIDR subset math (`ipaddress`), and
glob→regex translation (`glob_re`, which supports `*` and `|` alternation).

### `predicates.py` — one evaluator per kind

Each evaluator takes `(inv, graph, EvalContext)` and returns `list[Violation]`.
`EvalContext` carries the groups, an optional Neo4j `driver` (only `no_shared_tgw`
needs it for a live cross-account query), and the `account_id`. The `EVALUATORS`
dict at the bottom maps kind → function; `engine.py` dispatches through it.

Evaluators are **pure over the graph** wherever possible, so the same code runs
over a Terraform-overlaid graph later. The posture predicates (`not_ingress`,
`property`) read node props directly; the reachability predicates (`not_public`,
`not_in_public_subnet`, `not_path`, `only_via`) delegate to `reachability.py`.

### `engine.py` — orchestration

`evaluate_policy(policy, graph, *, driver, account_id)`:

- For each invariant, dispatch to its evaluator. **Any exception is caught** and
  turned into an `ERROR` result — a single bad predicate can't crash the whole
  run.
- `_apply_waivers()` splits violations into `active` vs `waived`. Status is
  `FAIL` if anything is still active, `WAIVED` if every violation was covered by
  an active waiver, else `PASS`.
- Assemble the `GuardrailReport` (with graph node/edge counts and scope).

---

## 6. Platform integration (backend + frontend)

Beyond the CLI, Guardrails is a first-class feature inside the CloudWeave tenant
platform. The engine is consumed as the `cw_guardrails` library; the platform
adds authentication, persistence, history, continuous evaluation, and a UI.

### Backend — `tenant-plane/backend/src/cw_backend/api/guardrails.py`

A FastAPI router that wraps the library. Because the engine and Neo4j driver are
**sync**, evaluation runs in a threadpool (`run_in_threadpool`) so it never blocks
the event loop. All endpoints require auth (`get_current_user`).

| Method & path | Purpose |
|---|---|
| `GET /api/guardrails/policy` | fetch the tenant's stored policy YAML |
| `PUT /api/guardrails/policy` | validate (`load_policy`) and store the policy |
| `POST /api/guardrails/evaluate` | run the stored policy against live Neo4j, **persist** the report, return it |
| `POST /api/guardrails/preview` | dry-run a *draft* policy without persisting (powers live preview) |
| `GET /api/guardrails/reports` | list historical report summaries (newest first) |
| `GET /api/guardrails/reports/{id}` | fetch one full stored report |
| `GET /api/guardrails/suggestions` | generate candidate rules from the live graph |

Persisting every evaluation gives **compliance-over-time for free** — the report
history is just rows in Postgres.

### Persistence — migration `0004_guardrails.py`

Two tables:

- `guardrail_policy` — a single-row store (`id=1`) holding the current policy
  `content`, plus `updated_by` / `updated_at`.
- `guardrail_reports` — one row per evaluation: `account_ids`, `regions`, the
  `passed`/`failed`/`violations` counts, the full `summary` and `report` JSONB,
  a `trigger` (`manual` or `scan`), `created_by`, and an indexed `created_at`.

### Continuous evaluation — `scan/guardrails_hook.py`

`evaluate_after_scan(...)` is called by the scan worker after every successful
scan. It's **best-effort**: a guardrails failure must never fail the scan, so the
whole thing is wrapped in a `try/except` that just logs. It re-evaluates the
stored policy, persists a report with `trigger="scan"`, and publishes a
`guardrails.evaluated` event on the Redis bus so the frontend scoreboard can
refresh live.

### Frontend — the 🚦 Guardrails tab (`frontend/src/guardrails/`)

| File | Role |
|---|---|
| `api.ts` | typed client — the **only** place that knows the endpoint shapes |
| `store.ts` | Zustand store: load / recheck / save / suggestions / accept |
| `GuardrailsView.tsx` | the tab UI: scoreboard, rule rows, suggestions, editor |
| `RuleBuilder.tsx` | no-YAML rule builder with live preview |
| `ruleCatalog.ts` | the predicate catalog the builder offers |
| `guardrails.css` | styles |

The tab is registered in `components/Sidebar.tsx` (`{ id: 'guardrails', icon:
'🚦', title: 'Guardrails' }`) and rendered in `components/Canvas.tsx`
(`activeView === 'guardrails' && <GuardrailsView />`).

**UX flow:**

- On first open the store `load()`s: GET the policy, and if one exists, POST
  `evaluate` and render the report.
- The **scoreboard** shows passing / failing / waived counts and graph size.
- Each rule renders as a row; failing rules auto-expand to show violations. Each
  violation with a `resource` uid gets a **`map ↗`** button that calls
  `explorerStore.flyTo(uid)` and switches to the Explorer tab — closing the loop
  from "a rule failed" to "here's the exact resource on the map".
- **✨ Generate rules** calls `/suggestions` and lists RATCHET (already passing —
  adopt to lock in) and FIX-FIRST (would flag existing problems) candidates;
  **+ add** appends the candidate's YAML to the policy draft.
- **✎ Edit policy** opens a raw YAML editor; **Save & re-check** PUTs then
  re-evaluates.
- **＋ New rule** opens the `RuleBuilder`, which uses `POST /preview` to show
  "what would this rule do?" against the live graph before you commit it.

The frontend types in `api.ts` mirror `models.py` exactly (`Violation`,
`InvariantResult`, `GuardrailReport`, `Candidate`), so the report object flows
unmodified from the Python engine to the React UI.

---

## 7. The reachability model

`reachability.py` is the heart of the relationship-aware checks. It's **ported
from the AI-Agent reachability checkers**, reduced to what the predicates need and
kept deterministic so it can run over a Terraform-overlaid graph in CI. Three
models:

1. **Internet exposure** (`internet_facing`) — a resource of an inbound-reachable
   type (`Instance`, `RdsInstance`, `LoadBalancer`) sitting in a public
   (IGW-routed) subnet. An `Instance` additionally needs a world-open SG ingress
   to count as *inbound*-reachable. Returns `uid → evidence path`
   (`[INTERNET, subnet, uid]`). A Lambda in a VPC subnet is **not** inbound
   reachable this way — its placement risk is caught by `not_in_public_subnet`
   instead.

2. **Lateral reach** (`reaches` / `any_reach`) — BFS over resources within
   network-connected VPCs (same VPC, peered, or sharing a transit gateway), each
   hop gated by the destination's security groups (`sg_admits`). `any_reach`
   handles an `INTERNET` source by deferring to `internet_facing`. A `blocked`
   set lets `only_via` remove a chokepoint and ask "is there still a path?".

3. **Egress chokepoint** (`egress_bypass`) — a resource in a public subnet
   egresses straight through the IGW, bypassing any required NAT. Each such
   resource is reported with its path.

**Documented non-goals (tracked follow-ups, matching AI-Agent's fuller
checkers):** NACL rule ordering, per-route TGW blackholes, and exact host-IP CIDR
math. The current model uses subnet routing + security-group gating + VPC
connectivity.

---

## 8. Authoring path #2: suggestions

Writing rules from scratch is hard, so `suggest.py` reads your live graph and
proposes rules. Each generator computes current state and emits a `Candidate`
tagged:

- **RATCHET** — already passing; adopt it to lock the good state in.
- **FIX-FIRST** — would flag N existing resources; adopt it to *start tracking* a
  problem you already have.

The five generators: world-open admin ports, public databases, sensitive
workloads in public subnets, instance egress via NAT, and cross-account shared
TGW. Accepting a candidate appends its `rule_yaml` to the policy. This is the
"ratchet / fix-first" workflow — exposed on the CLI (`cw-guardrails suggest`) and
in the UI (**✨ Generate rules**).

---

## 9. Waivers

A waiver is an **explicit, expiring exception**. It suppresses a specific
violation (or a whole invariant) with a reason and an expiry date.

```yaml
waivers:
  - invariant: no-world-open-admin-ports
    target: { id: "arn:aws:ec2:us-east-1:1234...:security-group/sg-bastion" }
    reason: "MFA-gated bastion, approved by security 2026-06"
    expires: 2026-09-01
```

Key property: **an expired waiver re-arms the finding** (`engine._active` checks
`date.today() <= expires`). Exceptions can't rot silently — once the date passes,
the violation comes back as `FAIL`. A waiver with no `target` covers the whole
invariant; a malformed date is treated as still-active (so a typo never silently
drops a real finding).

---

## 10. Output formats & exit codes

`report.py` renders a `GuardrailReport` three ways:

- **text** — human-readable summary for terminals (`render_text`).
- **json** — the full `GuardrailReport` (`model_dump_json`), for programmatic use.
- **sarif** — SARIF 2.1.0 for **GitHub code scanning** (`render_sarif`), mapping
  severity to SARIF levels (`critical`/`high`→`error`, `medium`→`warning`,
  `low`/`info`→`note`).

**Severity** ∈ `info | low | medium | high | critical`. A failing invariant at
**`high` or `critical`** makes `check` exit **1** (CI-blocking); `medium` and
below are reported but exit **0**.

---

## 11. Testing & development

```bash
pip install -e ".[dev]"
pytest                       # fixture-based unit tests — no Neo4j needed
ruff check src tests         # lint
ruff format --check src tests
mypy src                     # type check
```

Tests build a `Graph` by hand and call `build_indexes()` directly, so the entire
engine (selectors, predicates, reachability, waivers, suggestions) is covered
without a database. CI (`.github/workflows/ci.yml`) runs lint + format + mypy +
pytest on every push and PR to `main`.

### Using the library directly

```python
from neo4j import GraphDatabase
from cw_guardrails import evaluate_guardrails

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j"))
report = evaluate_guardrails(
    open("weave.guardrails.yaml", "rb").read(),
    neo4j_driver=driver,
    account_ids=["123456789012"],   # optional; overrides policy scope
    regions=["us-east-1"],          # optional
)
print(report.summary())
raise SystemExit(report.exit_code())   # 0 clean, 1 blocking failure
```

`evaluate_guardrails` (in `entry.py`) loads the policy, fetches the graph for
each scoped account, **merges** multiple accounts into one graph (de-duping edges
and rebuilding indexes over the union), and evaluates. Cross-account lateral
reach therefore works across the accounts you scope in.

---

## 12. Scope, limits & roadmap

Honest limits (all roadmap follow-ups):

- **Identity reachability** (which IAM role can reach a resource or assume into
  another account) — needs the scanner's IAM assume-role edges. Planned.
- **NACL rule ordering** and **per-route transit-gateway blackholes** in
  reachability — current model is subnet routing + SG gating + VPC connectivity.
- **`not_ingress`** is exact CIDR membership, not subnet math (asking for
  `10.0.0.0/8` won't match a rule scoped to `10.1.0.0/16`).
- **`property` / `must_have`** are only as rich as the scanner's stored
  fields/labels.
- **Multi-account** lateral reach is evaluated across the union of the accounts
  you scope; resources in accounts you didn't fetch aren't traversed (except
  `no_shared_tgw`, which queries live).

The north-star follow-up is the **pre-merge PR gate**: overlay a Terraform plan
delta onto the live graph and run the same deterministic engine in CI, so an
architecture-breaking change fails the PR before it merges. The engine was built
graph-pure specifically to make that possible.

---

## See also

- [`README.md`](../README.md) — quick start.
- [`docs/policy-reference.md`](./policy-reference.md) — the complete, field-by-field
  policy language reference with examples for every predicate.
- [`policies/starter-pack.yaml`](../policies/starter-pack.yaml) — copy-paste rule
  library.
