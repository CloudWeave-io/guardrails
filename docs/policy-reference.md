# Weave Guardrails — Policy Reference

What you can express in `weave.guardrails.yaml`, with examples. Every rule is:
**pick a set of resources (a selector) → state a constraint on it (a predicate) →
set a severity.**

A policy has four parts:

```yaml
version: 1
scope:    { accounts: ["1234..."], regions: ["us-east-1"] }   # which cloud to check
groups:   { web: { tag: "tier=web" } }                        # named selectors
invariants:                                                    # the rules
  - id: ...
    severity: ...
    <predicate>: { ... }
waivers:  [ ... ]                                              # expiring exceptions
```

---

## Selectors — how you point at resources

A selector is an inline object whose fields **AND** together, or the **name of a
group**, or the **`internet`** pseudo-selector. All fields are optional.

| Field | Matches | Example |
|---|---|---|
| `type` | resource type, or a list of types | `{ type: SecurityGroup }` · `{ type: [Instance, RdsInstance] }` |
| `tag` | a resource tag (`key=value`, or just `key` to mean "present") | `{ tag: "env=prod" }` |
| `name_matches` | name glob; `*` wildcard, `\|` alternation | `{ name_matches: "*prod-db*\|*payments*" }` |
| `account` | owning account id | `{ account: "988436168215" }` |
| `region` | region | `{ region: "eu-west-1" }` |
| `cidr` | resource's CIDR block is inside this CIDR | `{ type: Subnet, cidr: "10.0.0.0/8" }` |
| `id` | one exact resource uid (ARN) | `{ id: "arn:aws:ec2:...:vpc/vpc-123" }` |
| `pseudo: internet` | the public internet (use as a path source/target) | `{ pseudo: internet }` |

Combine fields to narrow:

```yaml
groups:
  prod_public_db: { type: RdsInstance, tag: "env=prod", region: "us-east-1" }
  internet:       { pseudo: internet }      # or just write the string `internet`
```

Resolved types are whatever the scanner emits — `Vpc`, `Subnet`, `Instance`,
`LambdaFunction`, `RdsInstance`, `SecurityGroup`, `RouteTable`, `InternetGateway`,
`NatGateway`, `TransitGateway`, `TgwVpcAttachment`, `VpcPeeringConnection`,
`LoadBalancer`, `NetworkAcl`, …

---

## The predicate catalog

### 1. `not_ingress` — no open inbound rule
No security group in `select` may have an inbound rule on `ports` from source `from`.

| Param | Meaning | Default |
|---|---|---|
| `select` | which security groups | required |
| `ports` | list of ports to forbid; empty = **any** port | `[]` |
| `from` | source CIDR | `0.0.0.0/0` |

```yaml
# No world-open SSH / RDP / database ports
- id: no-world-open-admin-ports
  severity: critical
  not_ingress: { select: { type: SecurityGroup }, ports: [22, 3389, 3306, 5432], from: "0.0.0.0/0" }

# Nothing at all open to the whole internet (any port)
- id: no-world-open-ingress
  severity: high
  not_ingress: { select: { type: SecurityGroup }, from: "0.0.0.0/0" }

# A partner CIDR must never reach the prod data SG
- id: partner-cannot-reach-data
  severity: high
  not_ingress: { select: { type: SecurityGroup, tag: "tier=data" }, from: "203.0.113.0/24" }
```
*Note:* matches when the rule literally lists the `from` CIDR and a listed port falls in the rule's port range. It is exact CIDR membership, not subset math.

---

### 2. `not_public` — not inbound-reachable from the internet
No resource in `select` may be reachable **inbound** from the internet. "Reachable"
= in an IGW-routed (public) subnet, and for an Instance also having a world-open SG
ingress. (Load balancers / RDS count by placement; Lambda is excluded — it isn't
reached inbound via a subnet.)

```yaml
- id: db-not-public
  severity: critical
  not_public: { select: { type: RdsInstance } }

- id: prod-instances-not-public
  severity: high
  not_public: { select: { type: Instance, tag: "env=prod" } }
```

---

### 3. `not_in_public_subnet` — not placed in a public subnet
No resource in `select` may sit in an IGW-routed subnet — **regardless of SGs**.
Stricter than `not_public`: it's about *placement*, not reachability.

```yaml
- id: sensitive-not-in-public-subnet
  severity: critical
  not_in_public_subnet: { select: { tag: "data=sensitive" } }

- id: databases-stay-private
  severity: high
  not_in_public_subnet: { select: { type: RdsInstance } }
```

---

### 4. `not_path` — no path between two sets
No network path may exist from any resource in `from` to any in `to`. Either side
can be the `internet` pseudo-selector. This is the workhorse for **isolation**.

```yaml
# The classic: internet must never reach the database
- id: no-internet-to-db
  severity: critical
  not_path: { from: internet, to: { type: RdsInstance } }

# Tier isolation: web must not reach data directly
- id: web-not-to-data
  severity: high
  not_path: { from: web, to: data }          # web, data are groups

# Environment isolation: dev must not reach prod
- id: dev-not-to-prod
  severity: high
  not_path: { from: { tag: "env=dev" }, to: { tag: "env=prod" } }

# Cross-account isolation: nothing here should reach the partner account
- id: no-path-to-partner-account
  severity: high
  not_path: { from: { type: Instance }, to: { account: "988436168215" } }
```
*Reach model:* internet→X (inbound exposure) and X→Y lateral over network-connected
VPCs (same VPC, peering, or a shared transit gateway), gated by the destination's
security groups.

---

### 5. `only_via` — every path must pass a chokepoint
Every path from `from` to `to` must traverse a `through` resource; a path that
**bypasses** it is a violation.

```yaml
# Instance egress to the internet must go through a NAT (fully supported pattern)
- id: egress-only-via-nat
  severity: high
  only_via: { from: { type: Instance }, to: internet, through: { type: NatGateway } }

# Generic chokepoint: the app tier may only reach data via the db-proxy
- id: data-only-via-proxy
  severity: high
  only_via: { from: { tag: "tier=app" }, to: { tag: "tier=data" }, through: { name_matches: "*db-proxy*" } }
```
*Note:* the egress-to-internet pattern is the solid one; the generic resource
chokepoint is best-effort (path-with-node-removed).

---

### 6. `property` — a resource property must satisfy a constraint
For each resource in `select`, the property `field` must match `equals`, be `in` a
list, or `matches` a regex. The field name is whatever the scanner stores.

```yaml
# Encryption at rest
- id: rds-encrypted
  severity: critical
  property: { select: { type: RdsInstance }, field: StorageEncrypted, equals: true }

# Instance-type allowlist
- id: approved-instance-types
  severity: medium
  property: { select: { type: Instance }, field: InstanceType, in: ["t3.micro", "t3.small", "m5.large"] }

# Naming convention
- id: subnet-naming
  severity: low
  property: { select: { type: Subnet }, field: name, matches: "^(pub|priv)-[a-z]+-[0-9]$" }
```

---

### 7. `must_have` — a required related resource
Each resource in `select` must be related (by any edge) to a neighbor of type `has`.

```yaml
# Every instance must be protected by a security group
- id: instances-have-sg
  severity: high
  must_have: { select: { type: Instance }, has: SecurityGroup }

# Every public subnet must have a network ACL
- id: public-subnet-has-nacl
  severity: medium
  must_have: { select: { type: Subnet }, has: NetworkAcl }
```
*Note:* depends on the scanner emitting the neighbor type as a node.

---

### 8. `no_shared_tgw` — no cross-account transit gateway
No VPC in `select` may attach to a transit gateway that is also attached by **other
accounts** (transitive cross-account blast radius). This one runs a live cross-account
lookup.

```yaml
- id: no-cross-account-shared-tgw
  severity: high
  no_shared_tgw: { select: { type: Vpc } }
```

---

## Severity & exit codes

`severity` ∈ `info | low | medium | high | critical`. A failing invariant at
**`high` or `critical`** makes `cw-guardrails check` exit **1** (CI-blocking);
`medium` and below are reported but exit **0**.

---

## Waivers — explicit, expiring exceptions

A waiver suppresses a specific violation (or a whole invariant) with a reason and an
expiry. **An expired waiver re-arms the finding** — so exceptions can't rot silently.

```yaml
waivers:
  # Allow one approved jump box to keep world-open SSH until a date
  - invariant: no-world-open-admin-ports
    target: { id: "arn:aws:ec2:us-east-1:1234...:security-group/sg-jumpbox" }
    reason: "MFA-gated bastion, approved by security 2026-06"
    expires: 2026-09-01

  # Waive an entire rule (no target) while a migration is in flight
  - invariant: dev-not-to-prod
    reason: "temporary during prod cutover"
    expires: 2026-07-15
```

---

## What the engine can't (yet) express

Honest limits — all are roadmap follow-ups:

- **Identity reachability** (who/which IAM role can reach a resource or assume into
  another account) — needs the scanner's IAM assume-role edges. Planned.
- **NACL rule ordering** and **per-route transit-gateway blackholes** in reachability —
  current model uses subnet routing + security-group gating + VPC connectivity.
- **`not_ingress`** is exact CIDR membership, not subnet math (asking for `10.0.0.0/8`
  won't match a rule scoped to `10.1.0.0/16`).
- **`property` / `must_have`** are only as rich as the scanner's stored fields/labels.
- **Multi-account** lateral reach is evaluated across the union of `scope.accounts`
  you fetch; resources in accounts you didn't scope aren't traversed (except
  `no_shared_tgw`, which queries live).

---

## A full worked example

```yaml
version: 1
scope:
  accounts: ["123456789012"]
  regions:  ["us-east-1"]

groups:
  internet:   { pseudo: internet }
  web:        { tag: "tier=web" }
  data:       { tag: "tier=data" }
  sensitive:  { tag: "data=sensitive" }
  prod_db:    { type: RdsInstance, tag: "env=prod" }
  nat:        { type: NatGateway }

invariants:
  - id: no-world-open-admin-ports
    severity: critical
    not_ingress: { select: { type: SecurityGroup }, ports: [22, 3389, 3306, 5432], from: "0.0.0.0/0" }

  - id: db-not-internet-reachable
    severity: critical
    not_path: { from: internet, to: prod_db }

  - id: sensitive-not-in-public-subnet
    severity: critical
    not_in_public_subnet: { select: sensitive }

  - id: web-not-to-data
    severity: high
    not_path: { from: web, to: data }

  - id: egress-only-via-nat
    severity: high
    only_via: { from: { type: Instance }, to: internet, through: nat }

  - id: prod-db-encrypted
    severity: critical
    property: { select: prod_db, field: StorageEncrypted, equals: true }

  - id: no-cross-account-shared-tgw
    severity: high
    no_shared_tgw: { select: { type: Vpc } }

waivers:
  - invariant: no-world-open-admin-ports
    target: { id: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-bastion" }
    reason: "approved bastion"
    expires: 2026-12-31
```

Run it: `cw-guardrails check --policy weave.guardrails.yaml -f text` (or `sarif`
for CI), or generate candidates from your live cloud with
`cw-guardrails suggest --account 123456789012 --region us-east-1`.
