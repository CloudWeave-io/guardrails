"""Hybrid policy merge (locked decision D2).

The platform-stored policy is the enforced floor — nothing in an infra repo's
optional `weave.guardrails.yaml` can remove, replace, re-scope, or waive a
stored rule. The repo file may only ADD stricter rules (and its own groups).
Violations of these constraints are explicit errors, never silent.
"""

from __future__ import annotations

from cw_guardrails.policy import Policy, load_policy


class PolicyMergeError(ValueError):
    """A repo policy tried to weaken or conflict with the stored policy."""


def merge_policies(stored: Policy, repo_yaml: str | None) -> tuple[Policy, list[str]]:
    """Merge an optional additive repo policy into the stored one.

    Repo invariants are namespaced `repo/<id>` so report provenance is visible.
    Returns (merged policy, warnings).
    """
    if not repo_yaml or not repo_yaml.strip():
        return stored, []
    repo = load_policy(repo_yaml)
    warnings: list[str] = []

    if repo.waivers:
        raise PolicyMergeError(
            "repo policy may not declare waivers — waivers live in the platform policy"
        )
    redefined = sorted(set(repo.groups) & set(stored.groups))
    if redefined:
        raise PolicyMergeError(
            f"repo policy redefines stored group(s): {', '.join(redefined)} — "
            "redefinition could silently re-target a stored rule"
        )
    if repo.scope.accounts or repo.scope.regions:
        warnings.append("repo policy `scope:` is ignored — scoping is per-rule (rule `accounts:`)")

    seen: set[str] = set()
    added = []
    for inv in repo.invariants:
        if inv.id in seen:
            raise PolicyMergeError(f"duplicate rule id in repo policy: {inv.id!r}")
        seen.add(inv.id)
        added.append(inv.model_copy(update={"id": f"repo/{inv.id}"}))

    merged = Policy(
        version=stored.version,
        scope=stored.scope,
        groups={**stored.groups, **repo.groups},
        invariants=[*stored.invariants, *added],
        waivers=stored.waivers,
    )
    return merged, warnings
