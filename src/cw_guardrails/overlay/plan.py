"""Parse `terraform show -json` output into the minimal shape the overlay consumes.

We read only `resource_changes` (what the plan does) and the
`configuration.root_module` expression references (how planned resources point
at each other before their ids exist). Everything else — prior_state,
planned_values — is ignored, and the GitHub Action strips it before upload.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ResourceChange:
    address: str
    type: str
    actions: list[str]  # ["create"] | ["update"] | ["delete"] | ["delete","create"]
    before: dict
    after: dict
    after_unknown: dict

    @property
    def creates(self) -> bool:
        return "create" in self.actions

    @property
    def deletes(self) -> bool:
        return "delete" in self.actions

    @property
    def updates(self) -> bool:
        return self.actions == ["update"]


@dataclass
class ParsedPlan:
    changes: list[ResourceChange] = field(default_factory=list)
    # address -> flattened field path ("vpc_id", "vpc_config.subnet_ids") -> referenced addresses
    refs: dict[str, dict[str, list[str]]] = field(default_factory=dict)


# Reference heads that are not managed resources (we only chase resource refs).
_NON_RESOURCE_HEADS = {"var", "local", "data", "module", "each", "count", "path", "terraform"}

_SKIP_ACTIONS: tuple[list[str], ...] = ([], ["no-op"], ["read"])


def _normalize_ref(ref: str) -> str | None:
    """'aws_vpc.new.id' / 'aws_vpc.new[0]' -> 'aws_vpc.new'; var/local/module refs -> None."""
    parts = ref.split(".")
    if len(parts) < 2 or parts[0] in _NON_RESOURCE_HEADS:
        return None
    return f"{parts[0]}.{parts[1].split('[')[0]}"


def _flatten_expressions(exprs: dict, prefix: str, out: dict[str, list[str]]) -> None:
    """Walk configuration expressions, recording references per dotted field path.
    List indices are dropped — multiple blocks of the same kind aggregate."""
    for key, val in exprs.items():
        path = f"{prefix}{key}"
        if isinstance(val, dict):
            refs = val.get("references")
            if isinstance(refs, list):
                for r in refs:
                    if isinstance(r, str) and (addr := _normalize_ref(r)):
                        bucket = out.setdefault(path, [])
                        if addr not in bucket:
                            bucket.append(addr)
            nested = {
                k: v
                for k, v in val.items()
                if k not in ("references", "constant_value") and isinstance(v, (dict, list))
            }
            if nested:
                _flatten_expressions(nested, f"{path}.", out)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    _flatten_expressions(item, f"{path}.", out)


def parse_plan(plan: dict) -> ParsedPlan:
    parsed = ParsedPlan()
    for rc in plan.get("resource_changes") or []:
        if rc.get("mode") == "data":
            continue
        ch = rc.get("change") or {}
        actions = ch.get("actions") or []
        if actions in _SKIP_ACTIONS:
            continue
        parsed.changes.append(
            ResourceChange(
                address=rc.get("address", ""),
                type=rc.get("type", ""),
                actions=actions,
                before=ch.get("before") or {},
                after=ch.get("after") or {},
                after_unknown=ch.get("after_unknown") or {},
            )
        )
    root = (plan.get("configuration") or {}).get("root_module") or {}
    for res in root.get("resources") or []:
        out: dict[str, list[str]] = {}
        _flatten_expressions(res.get("expressions") or {}, "", out)
        if out:
            parsed.refs[res.get("address", "")] = out
    return parsed
