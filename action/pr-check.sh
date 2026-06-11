#!/usr/bin/env bash
# Filter the Terraform plan, call the CloudWeave PR-gate endpoint, and emit the
# SARIF + sticky-comment artifacts the composite action uploads. Pure bash + jq +
# curl so it needs no toolchain in the consumer repo.
set -euo pipefail

: "${CW_API_URL:?api-url required}"
: "${CW_API_TOKEN:?api-token required}"
: "${CW_PLAN_JSON:?plan-json required}"

if [[ ! -f "$CW_PLAN_JSON" ]]; then
  echo "::error::plan json not found: $CW_PLAN_JSON"
  exit 1
fi

# 1. Shrink the plan to what the engine reads (resource_changes minus no-ops,
#    configuration, terraform_version) — 10-100x smaller and drops most state.
filtered=$(jq '{
  terraform_version,
  configuration,
  resource_changes: [ (.resource_changes // [])[]
    | select((.change.actions // []) as $a | $a != ["no-op"] and $a != ["read"]) ]
}' "$CW_PLAN_JSON")

# 2. Optional additive repo policy.
repo_policy_json=null
if [[ -n "${CW_REPO_POLICY:-}" && -f "${CW_REPO_POLICY:-}" ]]; then
  repo_policy_json=$(jq -Rs . < "$CW_REPO_POLICY")
fi

# 3. Build the request body.
body=$(jq -n \
  --argjson plan "$filtered" \
  --argjson repo_policy "$repo_policy_json" \
  --arg fail_on "${CW_FAIL_ON:-new-high}" \
  --arg repo "${CW_REPO:-}" \
  --arg pr "${CW_PR_NUMBER:-}" \
  --arg sha "${CW_SHA:-}" \
  --arg branch "${CW_BRANCH:-}" \
  --arg url "${CW_PR_URL:-}" \
  '{
    plan: $plan,
    repo_policy: $repo_policy,
    fail_on: $fail_on,
    context: { repo: $repo, pr: ($pr | if . == "" then null else tonumber end),
               sha: $sha, branch: $branch, url: $url }
  }')

# 4. Call the gate (capture body + status separately).
http_out=$(mktemp)
status=$(curl -sS -o "$http_out" -w '%{http_code}' \
  -X POST "${CW_API_URL%/}/api/guardrails/pr-check" \
  -H "Authorization: Bearer ${CW_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data-binary @<(printf '%s' "$body") || echo 000)

if [[ "$status" != "200" ]]; then
  echo "::error::pr-check call failed (HTTP $status): $(head -c 500 "$http_out")"
  exit 1
fi

# 5. Artifacts: SARIF for code scanning, markdown for the sticky comment.
jq -r '.sarif' "$http_out" > guardrails.sarif

gate=$(jq -r '.gate' "$http_out")
new=$(jq -r '.summary.new_violations // 0' "$http_out")
preexisting=$(jq -r '(.summary.violations // 0) - (.summary.new_violations // 0)' "$http_out")
report_id=$(jq -r '.id' "$http_out")
mapped=$(jq -r '.summary.planned_resources_mapped // 0' "$http_out")
unmapped=$(jq -r '(.summary.unmapped_types // []) | join(", ")' "$http_out")
dash_url="${CW_API_URL%/}/?view=guardrails&report=${report_id}"

{
  if [[ "$gate" == "fail" ]]; then
    echo "🚦 **CloudWeave Guardrails — ❌ ${new} new violation(s)** (${preexisting} pre-existing unchanged)"
  else
    echo "🚦 **CloudWeave Guardrails — ✅ no new violations** (${preexisting} pre-existing unchanged)"
  fi
  echo ""
  echo "| | rule | severity | resource | evidence |"
  echo "|--|--|--|--|--|"
  jq -r '
    [ .report.results[] as $r | $r.violations[] | select(.new) | {
        id: $r.id, sev: $r.severity, name: (.name // .resource),
        msg: (.message | gsub("\\|"; "\\\\|"))
      } ]
    | (if length == 0 then [] else .[0:20] end)[]
    | "| 🆕 | \(.id) | \(.sev) | \(.name) | \(.msg) |"
  ' "$http_out"
  echo ""
  echo "_mapped ${mapped} planned resource(s)$([[ -n "$unmapped" ]] && echo "; ignored unmapped types: ${unmapped}")_"
  echo ""
  echo "→ [open this report in CloudWeave](${dash_url})"
} > guardrails-comment.md

echo "gate=$gate"            >> "$GITHUB_OUTPUT"
echo "new_violations=$new"  >> "$GITHUB_OUTPUT"
echo "report_id=$report_id" >> "$GITHUB_OUTPUT"

{
  echo "## 🚦 CloudWeave Guardrails"
  cat guardrails-comment.md
} >> "$GITHUB_STEP_SUMMARY"

echo "gate=$gate new=$new report=$report_id"
