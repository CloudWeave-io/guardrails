# Phase 4 — The Pre-Merge PR Gate (Terraform-Plan Overlay)

> Status: **PLANNED** (decisions locked 2026-06-11) · Owner: guardrails
> Prerequisites: Phases 1–2 shipped (engine, backend platform, frontend tab, history).

The loop-closer: the same invariant that shows red on the Guardrails dashboard
**blocks the pull request that would have caused it** — before the
infrastructure exists. A PR that adds a VPC peering bridging dev into prod
fails CI with the rule id, the named breach path, and a deep link into
CloudWeave.

Nobody else closes this loop. Checkov/tfsec lint resources in isolation;
CloudWeave evaluates the *change against the real cross-account graph*: the
plan's deltas are overlaid onto the live graph in memory, and the exact same
deterministic engine that powers the dashboard evaluates "the world as it
would be after merge."

---

## 1. Locked decisions

| # | Decision | Choice | Rationale |
|---|---|---|---|
| D1 | Where evaluation runs | **Backend endpoint** (`POST /api/guardrails/pr-check`) | CI holds one CloudWeave API token — no Neo4j creds in GitHub. Every PR evaluation lands in report history (trigger `pr-check`) → the dashboard shows PRs on the trend. Engine + policy versions are always the platform's. |
| D2 | Policy source of truth | **Hybrid: stored + additive** | The platform-stored policy is the enforced floor — a PR can never weaken the policy it is checked against. An optional `weave.guardrails.yaml` in the infra repo may **add** stricter rules (its own invariants/groups), never remove, redefine, or waive stored ones. |
| D3 | Gate threshold (default) | Fail on **NEW violations at severity ≥ high** | Pre-existing debt must not block unrelated PRs (ratchet principle). `--strict` / `fail_on: all-high` opt-in. |
| D4 | Failure mode | **Fail-closed** | If the endpoint is unreachable the check errors (= blocked when marked required). Soft-rollout via `continue-on-error: true` at the workflow level, not ours. |
| D5 | Repo waivers | **Rejected in v1** | Waivers weaken; they live only in the stored policy. (v2 consideration: allow repo waivers scoped to repo-defined rules only.) |
| D6 | Planned peering/TGW status | **Assumed active** | A planned `aws_vpc_peering_connection` is treated as connected — the security-conservative assumption. |
| D7 | Synthetic uid scheme | `tf:<plan address>` (e.g. `tf:aws_vpc_peering_connection.dev_prod`) | Deterministic, readable in violation messages, can never collide with ARNs. Nodes carry `planned: true` + `tf_address` props. |
| D8 | Plan upload shape | **Action pre-filters the plan** to `resource_changes` (non-no-op) + `configuration` + `terraform_version` | Drops `prior_state`/`planned_values` — 10–100× smaller and removes most sensitive material before it leaves CI. |

---

## 2. End-to-end flow

```
infra repo PR                    GitHub Actions                       CloudWeave tenant backend
─────────────                    ──────────────                       ─────────────────────────
terraform code change
        │
        ▼
                     terraform plan -out=tf.plan
                     terraform show -json tf.plan > plan.json
                     [action] filter plan.json  (D8)
                     [action] POST /api/guardrails/pr-check ──────▶  auth: api token (scope guardrails:pr-check)
                              { plan, repo_policy?, context }        1. load stored policy
                                                                     2. merge additive repo policy   (§5)
                                                                     3. fetch live graph (in-memory)
                                                                     4. evaluate  → BASELINE report
                                                                     5. overlay plan deltas          (§3)
                                                                     6. evaluate  → AFTER report
                                                                     7. diff → mark NEW violations   (§4)
                                                                     8. persist report (trigger=pr-check,
                                                                        PR context; raw plan NOT stored)
                     ◀──────────────────────────────────────────    { gate, report, sarif, summary }
                     [action] upload SARIF → PR annotations
                     [action] sticky PR comment (table + deep link)
                     [action] exit 1 if gate=fail  ──▶  ❌ check blocks merge
                                                                     Dashboard: history row "pr-check ·
                                                                     org/infra#142", NEW badges, trend
```

---

## 3. Component: plan overlay (`cw_guardrails/overlay/`)

New engine-repo package. Pure functions — no Neo4j, no I/O — exactly like the
rest of the engine, so it is unit-testable from JSON fixtures.

```
overlay/
  __init__.py      overlay_plan(graph, plan) -> OverlayResult
  plan.py          parse + normalize `terraform show -json` shape
  mapping.py       TF resource type -> node/edge builders (the table below)
  resolve.py       reference resolution (literal ids + symbolic refs)
  apply.py         create/update/delete/replace onto a copied Graph
```

```python
@dataclass
class OverlayResult:
    graph: Graph                  # deep-copied + deltas applied + indexes rebuilt
    mapped: int                   # resource_changes successfully mapped
    unmapped_types: list[str]     # TF types we ignored (surfaced in report + PR comment)
    planned_uids: set[str]        # synthetic uids added (for "planned" flagging)

def overlay_plan(base: Graph, plan: dict) -> OverlayResult: ...
```

### 3.1 Terraform plan anatomy we consume

From `terraform show -json` we read only:

- `resource_changes[]` — `address`, `type`, `change.actions`
  (`["create"]`, `["update"]`, `["delete"]`, `["delete","create"]` = replace),
  `change.before`, `change.after`, `change.after_unknown`.
- `configuration.root_module.resources[].expressions.<field>.references[]`
  — to resolve fields that are *known after apply* (they reference another
  planned resource).

### 3.2 Resource mapping table (v1)

| Terraform type | Graph node | Props mapped | Edges created |
|---|---|---|---|
| `aws_vpc` | `Vpc` | `vpc_id`†, `cidr_block`, tags→name | — |
| `aws_subnet` | `Subnet` | `subnet_id`†, `vpc_id`, `cidr_block`, `availability_zone` | `HAS_SUBNET` from VPC |
| `aws_instance` | `Instance` | `subnet_id`, `private_ip`, tags→name | `CONTAINS_INSTANCE` from subnet; `PROTECTED_BY` → each `vpc_security_group_ids` |
| `aws_lambda_function` (with `vpc_config`) | `LambdaFunction` | name | `CONTAINS_LAMBDA` from each subnet |
| `aws_db_instance` | `RdsInstance` | engine, name | placement v1-limited (see §10) |
| `aws_lb` | `LoadBalancer` | `scheme`, name | — |
| `aws_security_group` | `SecurityGroup` | `group_id`†, `vpc_id`, name; inline `ingress[]` → `props.inbound[]` (`{protocol, from_port, to_port, cidrs, source_sg_id}`) | — |
| `aws_security_group_rule` (type=ingress) / `aws_vpc_security_group_ingress_rule` | — (folds into SG) | appended to owning SG's `props.inbound` (owner = live node by `group_id` or planned by ref) | — |
| `aws_route_table` | `RouteTable` | `vpc_id`, inline `route[]` | `ROUTES_TO` per route target |
| `aws_route` | — (folds into RT) | — | `ROUTES_TO` RT → gateway (igw/nat/tgw/pcx by id field present) |
| `aws_route_table_association` | — | — | `USES_ROUTE_TABLE` subnet → RT |
| `aws_internet_gateway`(+`_attachment`) | `InternetGateway` | `vpc_id` | — |
| `aws_nat_gateway` | `NatGateway` | `subnet_id` | — |
| `aws_ec2_transit_gateway` | `TransitGateway` | `tgw_id`† | — |
| `aws_ec2_transit_gateway_vpc_attachment` | `TgwVpcAttachment` | `tgw_id`, `vpc_id`, `owner_account_id` | — (union-find reads props) |
| `aws_vpc_peering_connection` (+`_accepter`) | `VpcPeeringConnection` | `requester_vpc_id`=`vpc_id`, `accepter_vpc_id`=`peer_vpc_id`, `status: active` (D6) | `HAS_PEERING`/`PEERS_WITH` to resolvable VPC nodes |
| `aws_iam_role` | `IamRole` | name, raw `assume_role_policy` | — (scanner-derived fields unavailable — §10) |

† identity prop used to bind a *live* node on update/delete.

**Engine-semantics note (important):** VPC connectivity in reachability comes
from the *existence* of an active `VpcPeeringConnection` / `TgwVpcAttachment`
node (union-find over props), and public-subnet detection from
`Subnet -USES_ROUTE_TABLE-> RT -ROUTES_TO-> InternetGateway`. The mapping
above deliberately produces exactly those shapes — that is the contract that
makes `not_path` / `not_public` / `only_via` light up on planned changes.

Anything not in the table → counted in `unmapped_types` and **surfaced** (PR
comment + report summary), never silently dropped.

### 3.3 Reference resolution (`resolve.py`)

Three-pass, deterministic:

1. **Create pass** — every `create` (and the create half of replace) becomes a
   node with uid `tf:<address>`, props from `change.after` literals,
   `planned: true`, `tf_address`, `account`/`region` from the provider context.
2. **Resolve pass** — for each prop in `after_unknown` (e.g. a subnet's
   `vpc_id` referencing a VPC created in the same plan), look up
   `configuration...expressions.<field>.references[0]`, normalize the address
   (strip `.id`/index), and substitute the referenced resource's synthetic uid.
   For *literal* ids referencing **existing** infra (e.g. `vpc_id: "vpc-22b…"`),
   bind to the live node via prop lookup (`vpc_id`/`subnet_id`/`group_id`).
3. **Edge pass** — emit the table's edges using the resolved endpoints (live
   uid or synthetic uid alike).

### 3.4 Delta application (`apply.py`)

Operates on a **deep copy** of the base graph (the baseline evaluation must
see the untouched graph):

- `create` → add node + edges.
- `update` → bind live node (by † identity prop / `before.arn`), merge `after`
  props; SG inline `ingress` replaces `props.inbound` wholesale; route/rule
  sub-resources re-fold.
- `delete` → bind via `change.before` (`before.arn` / † id), remove node +
  all incident edges; SG-rule deletes remove the matching `inbound` entry.
- `replace` → delete(before) + create(after) (new synthetic uid).
- Finally `build_indexes(overlaid)` — public subnets, containment, SG folding,
  union-find all recompute over the merged world. **No new index code needed.**

---

## 4. Component: baseline diff (`diff.py` + model changes)

```python
def diff_reports(before: GuardrailReport, after: GuardrailReport) -> GuardrailReport:
    """Return `after` with every violation/waived entry annotated new=True/False.
    Key = (invariant id, violation.resource). Planned resources (tf: uids) are
    always new. Severity/message changes on an existing key stay pre-existing."""
```

Model additions (additive, backward-compatible with stored reports):

- `Violation.new: bool | None = None` — `None` for non-PR evaluations.
- `GuardrailReport.gate(fail_on: str) -> bool` — `"new-high"` (default; any
  NEW violation at ≥ high), `"new-any"`, `"all-high"` (strict).
- `report.summary()` gains `new_violations` when annotated.
- SARIF: NEW violations are `level: error` results tagged
  `properties.new: true`; pre-existing downgraded to `note` so PR annotations
  highlight only what the PR introduces.
- CLI: `cw-guardrails check --plan plan.json [--fail-on new-high|new-any|all-high]`
  — same overlay module over direct Neo4j, for local dev runs (not the CI path).

---

## 5. Component: hybrid policy merge (`merge.py`)

```python
def merge_policies(stored: Policy, repo: Policy | None) -> Policy
```

Rules (enforced with explicit 422 errors, never silent):

1. Stored policy is evaluated **whole** — nothing in the repo file can remove,
   replace, re-scope, or re-severity a stored rule.
2. Repo invariants are **added**, report-ids namespaced `repo/<id>` (so dashboards
   distinguish provenance); duplicate ids *within* the repo file → error.
3. Repo groups merge only if the name is **not** already defined in the stored
   policy (redefinition could silently re-target a stored rule) → error.
4. `waivers:` present in the repo file → error: *"waivers must live in the
   platform policy"* (D5).
5. Repo `scope:` is ignored (scoping is per-rule); a warning is returned.

---

## 6. Component: backend (`tenant-plane/backend`)

### 6.1 Machine tokens (CI auth)

New table + minimal admin surface (production-grade from day one, tiny scope):

```python
class ApiTokenRecord(Base):           # migration 000X_api_tokens
    id: UUID pk
    name: str                          # "github-infra-repo"
    token_hash: str                    # sha256 of the secret; plaintext shown once
    scopes: list[str]                  # ["guardrails:pr-check"]
    created_by: str
    created_at / last_used_at: datetime
```

- `POST /api/tokens` (admin/user JWT) → `{ token: "cwt_<43 url-safe chars>" }` once.
- `GET /api/tokens` / `DELETE /api/tokens/{id}` — list (no secrets) / revoke.
- Auth dependency `require_scope("guardrails:pr-check")` accepts **either** a
  user JWT or a `cwt_` token with the scope; bumps `last_used_at`.

### 6.2 The endpoint

```
POST /api/guardrails/pr-check          (scope: guardrails:pr-check)
{
  "plan":        { …filtered terraform show -json… },   # ≤ 5 MB (413 above)
  "repo_policy": "yaml…" | null,                        # additive (§5)
  "account_ids": [...] | null,                          # default: stored-policy accounts
  "regions":     [...] | null,
  "context":     { "repo": "CloudWeave-io/infra", "pr": 142,
                   "sha": "ab12cd3", "branch": "add-peering", "url": "…" }
}
→ 200
{
  "id": "<report uuid>",
  "gate": "pass" | "fail",
  "fail_on": "new-high",
  "summary": { "rules": 9, "new_violations": 1, "pre_existing": 6,
               "planned_resources_mapped": 4, "unmapped_types": ["aws_s3_bucket"] },
  "report": { …GuardrailReport, violations carry "new"… },
  "sarif":  "…ready to upload…"
}
```

Implementation notes:

- Runs in the threadpool like `/evaluate` (sync Neo4j driver).
- Two evaluations (baseline + overlaid) of the **merged** policy; one fetch —
  overlay works on a deep copy (§3.4).
- Persists a `GuardrailReportRecord` with `trigger="pr-check"` and the PR
  context inside `summary` → appears in history/trend automatically.
  **The raw plan is never persisted** (it can contain sensitive `after`
  values even filtered) and never logged.
- Guards: 5 MB body cap, 60 s evaluation timeout, per-token rate limit
  (10/min), `resource_changes` count cap (2 000).

### 6.3 Scan-hook symmetry

No change: the existing scan-complete hook keeps evaluating the **stored**
policy only. Repo-additive rules exist only inside PR evaluations (they are
the infra team's local ratchet, not the org floor).

---

## 7. Component: GitHub Action (`guardrails` repo, `action/`)

Composite action, referenced as `CloudWeave-io/guardrails/action@main`.

```yaml
# action/action.yml (sketch)
inputs:
  api-url:        { required: true }
  api-token:      { required: true }            # cwt_… from repo secrets
  plan-json:      { required: true }            # path to terraform show -json output
  repo-policy:    { required: false }           # path to additive weave.guardrails.yaml
  fail-on:        { default: "new-high" }
  comment:        { default: "true" }           # sticky PR comment
  upload-sarif:   { default: "true" }
runs:
  using: composite
  steps:
    - filter plan  →  jq '{terraform_version, configuration,
                          resource_changes: [.resource_changes[]
                            | select(.change.actions != ["no-op"])]}'   # D8
    - POST pr-check; capture { gate, summary, report, sarif }
    - write guardrails.sarif  → github/codeql-action/upload-sarif      # PR annotations
    - upsert sticky PR comment (marker <!-- cw-guardrails -->)
    - exit 1 when gate == "fail"                                       # D4 fail-closed
```

Sticky PR comment format:

```
🚦 CloudWeave Guardrails — ❌ 1 new violation (6 pre-existing unchanged)

| | rule | severity | resource | evidence |
|--|--|--|--|--|
| 🆕 | prod-dev-isolation | critical | tf:aws_vpc_peering_connection.dev_prod (planned) | cross-dev-vpc ▸ pcx (planned) ▸ cross-prod-vpc |

unmapped types ignored: aws_s3_bucket
→ open this report in CloudWeave: https://…/?view=guardrails&report=<id>
```

Consumer workflow snippet (goes in the infra repo docs):

```yaml
- run: terraform plan -out=tf.plan && terraform show -json tf.plan > plan.json
- uses: CloudWeave-io/guardrails/action@main
  with:
    api-url:   ${{ vars.CLOUDWEAVE_API_URL }}
    api-token: ${{ secrets.CLOUDWEAVE_API_TOKEN }}
    plan-json: plan.json
```

Mark the check **required** in branch protection → the gate actually blocks.

---

## 8. Component: frontend

Small, additive (history browser already does the heavy lifting):

1. **History rows**: `pr-check` trigger chip rendered with the PR context —
   `pr-check · CloudWeave-io/infra #142` (from the summary), linked to the PR URL.
2. **NEW badges**: when a loaded report's violations carry `new: true`, show a
   `🆕 new` pill on those rows (style: existing `gr-rule-count` pattern, red).
3. **Deep link**: support `/?view=guardrails&report=<id>` on boot —
   `graphStore.activeView = 'guardrails'` + `viewReport(id)` (the PR comment
   links straight to the evidence).
4. **Planned-resource chips**: evidence-path chips for `tf:` uids render with a
   dashed border + "planned" tooltip and no fly-to (nothing to fly to yet).

---

## 9. Test plan

**Unit (engine repo)** — JSON plan fixtures under `tests/plans/`:

| fixture | asserts |
|---|---|
| `create_peering_cross_env.json` | pcx node + props; union-find connects the two VPCs; `not_path` fires; violation `new: true`; synthetic uid in path |
| `sg_add_world_ingress.json` | standalone rule folds onto existing SG (live bind via `group_id`); `not_ingress` fires |
| `route_to_igw.json` | private subnet flips public (`USES_ROUTE_TABLE`+`ROUTES_TO` chain); `not_in_public_subnet` fires on existing instance |
| `delete_nat.json` | delete binds via `before.arn`; `only_via` egress fires |
| `replace_subnet.json` | replace = delete+create; no orphan edges |
| `unknown_refs.json` | subnet→vpc both planned; `after_unknown` resolved via configuration references |
| `unmapped_types.json` | S3/bucket-policy changes ignored, listed in `unmapped_types` |
| `noop_plan.json` | zero deltas → after == before → gate pass, 0 new |

Diff: same violation before+after → not new; severity-changed key → still not
new; `tf:` resource → always new. Merge: each of §5's five rules has a
positive + error test.

**Backend**: token auth (valid scope / wrong scope / revoked), 413 cap,
persistence shape (`trigger`, context in summary, **no plan stored**), SARIF
in response.

**E2E (live env)**: hand-built filtered plan adding a peering between two live
isolated VPCs → endpoint returns `gate: fail` with 1 NEW critical; dashboard
history shows the `pr-check` row; the report's evidence path renders with a
planned chip. (This doubles as the demo.)

**Reachability regression**: the AI-Agent's 49 scenarios remain the corpus for
any reachability change (none planned in this phase).

---

## 10. Honest limits (v1, documented in README)

- **Root module only** for symbolic reference resolution; `module.*` addresses
  resolve in v1.1 (recursive `module_calls` walk). Literal-id references into
  modules work regardless.
- **Scanner-derived props don't exist on planned nodes** (e.g. `public_trust`
  on IamRole) — `property` rules can't evaluate enriched fields for planned
  resources; raw plan fields only. Surfaced as a per-rule note, not a silent pass.
- **RDS subnet placement** via `db_subnet_group` is not traversed in v1
  (`RdsInstance` lands unplaced → placement predicates skip it, noted).
- `count`/`for_each` instances map per-instance only when the plan enumerates
  them (it does in `resource_changes`); unknown-count expansions are listed
  unmapped.
- Inherited engine limits apply unchanged (no NACL ordering, exact-CIDR
  `not_ingress`, no per-route TGW blackholes).
- Drift: the baseline is the live graph **at evaluation time**, which may
  differ from the state the plan was computed against. Acceptable: the gate
  asks "does this change break an invariant *now*", and re-running the check
  re-evaluates.

---

## 11. Work breakdown & acceptance

| Phase | Deliverable | Acceptance | Size |
|---|---|---|---|
| **4.0** Overlay core | `overlay/` package: parse, mapping table, 3-pass resolve, apply, `OverlayResult`; fixtures + ~15 unit tests | all §9 unit fixtures green; `peering` fixture flips `not_path` on the conftest graph | ~1.5 sessions |
| **4.1** Diff + CLI | `diff.py`, model `new` flag, gate modes, SARIF new-tagging, `check --plan --fail-on` | golden: pre-existing suppressed, planned always new; CLI exit codes per mode | ~0.5 |
| **4.2** Policy merge | `merge.py` + 422 errors | §5 rules each tested both ways | ~0.5 |
| **4.3** Backend | `api_tokens` migration + endpoints, `pr-check` endpoint, persistence, guards | E2E live-env check passes; history shows pr-check row; no plan persisted | ~1 |
| **4.4** Action + docs | `action/action.yml`, filter step, SARIF upload, sticky comment, consumer workflow doc | sandbox repo PR blocked by a peering plan; annotations + comment + deep link render | ~1 |
| **4.5** Frontend | PR chips, NEW badges, deep link, planned chips | Playwright: deep link opens the PR report; NEW badge on the planned violation | ~0.5 |

Total ≈ **5 sessions**. 4.0→4.1→4.2 are engine-repo-only and shippable/CI-green
independently; 4.3+ touch backend/frontend.

## 12. Demo script (once built)

1. Dashboard: `prod-dev-isolation` is green after the pcx teardown (or use the
   sandbox account pair).
2. Open a PR in the sandbox infra repo adding `aws_vpc_peering_connection`
   between a dev and a prod VPC.
3. CI: ❌ **CloudWeave Guardrails — 1 new violation** · the PR comment names the
   rule, the planned pcx, and the dev▸pcx▸prod path; inline SARIF annotation
   on the Terraform file.
4. Click the deep link → the Guardrails tab opens that exact pr-check report:
   NEW badge, planned chip in the evidence path, history row `pr-check · infra#1`.
5. Close: "the rule you watched fail on the live graph is the same rule that
   just refused to let it happen again."
