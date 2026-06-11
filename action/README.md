# CloudWeave Guardrails — PR Gate Action

Fail a pull request when its Terraform change would newly break an architecture
invariant. The plan is overlaid onto your **live** CloudWeave graph and the same
engine that powers the dashboard evaluates "the world as it would be after merge"
— so a peering that bridges dev into prod, a route that exposes a private subnet,
or a security-group rule opening a port to the world is caught *before* it merges.

## Quick start

1. **Mint a machine token** in CloudWeave (Settings → API tokens, scope
   `guardrails:pr-check`) and add it to the repo as the secret
   `CLOUDWEAVE_API_TOKEN`. Add your tenant URL as the variable
   `CLOUDWEAVE_API_URL`.

2. **Add the workflow** (`.github/workflows/guardrails.yml`):

```yaml
name: Guardrails
on: pull_request

permissions:
  contents: read
  pull-requests: write      # sticky comment
  security-events: write    # SARIF annotations

jobs:
  guardrails:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
      - run: terraform init
      - run: terraform plan -out=tf.plan
      - run: terraform show -json tf.plan > plan.json

      - uses: CloudWeave-io/guardrails/action@main
        with:
          api-url:   ${{ vars.CLOUDWEAVE_API_URL }}
          api-token: ${{ secrets.CLOUDWEAVE_API_TOKEN }}
          plan-json: plan.json
          # repo-policy: weave.guardrails.yaml   # optional, additive-only
          # fail-on: new-high                    # new-high | new-any | all-high
```

3. **Make it required**: branch protection → require the `guardrails` check.
   Now a violating PR cannot merge.

## What it does

- Filters the plan to `resource_changes` + `configuration` (10–100× smaller,
  strips most state) before anything leaves CI.
- Calls `POST /api/guardrails/pr-check`; the backend evaluates the stored policy
  (the un-weakenable floor) merged with your optional additive repo policy,
  baseline vs. overlaid, and returns only what the plan *introduced*.
- Uploads SARIF (new violations annotate the PR), posts a sticky comment with the
  breach evidence + a deep link into the dashboard, and exits non-zero on a gated
  failure.

## Inputs

| input | default | notes |
|---|---|---|
| `api-url` | — | tenant backend base URL |
| `api-token` | — | `cwt_` token, scope `guardrails:pr-check` |
| `plan-json` | — | `terraform show -json` output path |
| `repo-policy` | `""` | additive `weave.guardrails.yaml` (may only ADD rules) |
| `fail-on` | `new-high` | `new-high` \| `new-any` \| `all-high` |
| `comment` | `true` | sticky PR comment |
| `upload-sarif` | `true` | needs `security-events: write` |

## Outputs

`gate` (`pass`/`fail`), `new-violations` (count), `report-id` (deep-links to
`<api-url>/?view=guardrails&report=<id>`).

## The additive repo policy

`repo-policy` lets a team ratchet *stricter* than the org floor. It may add its
own invariants (reported namespaced `repo/<id>`) and groups, but it can never
remove, redefine, re-scope, or waive a stored rule — those attempts fail the
check with an explicit error. Waivers live only in the platform policy.
