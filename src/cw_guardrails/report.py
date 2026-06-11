"""Render a GuardrailReport as text, JSON, or SARIF (for GitHub code scanning)."""

from __future__ import annotations

import json

from cw_guardrails.models import GuardrailReport, Severity, Status

_ICON = {Status.PASS: "PASS ", Status.FAIL: "FAIL ", Status.WAIVED: "WAIVE", Status.ERROR: "ERROR"}
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_text(report: GuardrailReport) -> str:
    s = report.summary()
    lines = [
        f"\n  Weave Guardrails - accounts {report.account_ids} {report.regions}",
        f"  graph: {report.graph_nodes} nodes, {report.graph_edges} edges",
        f"  {s['passed']} passed, {s['failed']} failed, {s['waived']} waived "
        f"({s['violations']} violations)\n",
    ]
    if "new_violations" in s:
        lines.insert(3, f"  plan overlay: {s['new_violations']} NEW violation(s) vs baseline\n")
    for r in report.results:
        lines.append(f"  [{_ICON[r.status]}] {r.id}  ({r.severity})")
        if r.description:
            lines.append(f"          {r.description}")
        for v in r.violations:
            tag = "NEW " if v.new else ""
            lines.append(f"          -> {tag}{v.message}")
        for v in r.waived:
            lines.append(f"          ~ (waived: {v.waiver_reason}) {v.message}")
        lines.append("")
    lines.append(f"  exit {report.exit_code()}")
    return "\n".join(lines)


def render_json(report: GuardrailReport) -> str:
    return report.model_dump_json(indent=2)


def render_sarif(report: GuardrailReport) -> str:
    rules, results = [], []
    seen: set[str] = set()
    for r in report.results:
        if r.id not in seen:
            seen.add(r.id)
            rules.append(
                {
                    "id": r.id,
                    "shortDescription": {"text": r.description or r.id},
                    "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity]},
                }
            )
        for v in r.violations:
            # Baseline-diffed reports: NEW violations keep full severity; the
            # pre-existing ones drop to notes so PR annotations highlight only
            # what the change introduces.
            level = _SARIF_LEVEL[r.severity] if v.new is not False else "note"
            entry = {
                "ruleId": r.id,
                "level": level,
                "message": {"text": ("NEW: " if v.new else "") + v.message},
                "locations": [{"logicalLocations": [{"fullyQualifiedName": v.resource or r.id}]}],
            }
            if v.new is not None:
                entry["properties"] = {"new": v.new}
            results.append(entry)
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "cw-guardrails", "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
