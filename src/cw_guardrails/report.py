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
    for r in report.results:
        lines.append(f"  [{_ICON[r.status]}] {r.id}  ({r.severity})")
        if r.description:
            lines.append(f"          {r.description}")
        for v in r.violations:
            lines.append(f"          -> {v.message}")
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
            results.append(
                {
                    "ruleId": r.id,
                    "level": _SARIF_LEVEL[r.severity],
                    "message": {"text": v.message},
                    "locations": [
                        {"logicalLocations": [{"fullyQualifiedName": v.resource or r.id}]}
                    ],
                }
            )
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
