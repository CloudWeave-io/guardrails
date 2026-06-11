"""cw-guardrails CLI — check a policy against the live graph."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import json

import typer
from neo4j import GraphDatabase

from cw_guardrails.entry import evaluate_guardrails, evaluate_guardrails_with_plan
from cw_guardrails.graph import fetch_graph
from cw_guardrails.report import render_json, render_sarif, render_text
from cw_guardrails.suggest import suggest_rules

app = typer.Typer(
    add_completion=False, help="Verify architecture invariants against the live CloudWeave graph."
)


@app.command()
def check(
    policy: Annotated[
        Path,
        typer.Option(
            "--policy", "-p", exists=True, readable=True, help="Path to weave.guardrails.yaml"
        ),
    ],
    account: Annotated[
        list[str],
        typer.Option("--account", "-a", help="Account id (repeatable). Overrides policy scope."),
    ] = [],
    region: Annotated[list[str], typer.Option("--region", "-r", help="Region (repeatable).")] = [],
    fmt: Annotated[str, typer.Option("--format", "-f", help="text | json | sarif")] = "text",
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write to a file instead of stdout.")
    ] = None,
    plan: Annotated[
        Path | None,
        typer.Option(
            "--plan",
            exists=True,
            readable=True,
            help="terraform show -json output: overlay the plan and gate on NEW violations.",
        ),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", help="Gate mode with --plan: new-high | new-any | all-high"),
    ] = "new-high",
    neo4j_uri: Annotated[str, typer.Option(envvar="NEO4J_URI")] = "bolt://localhost:7687",
    neo4j_user: Annotated[str, typer.Option(envvar="NEO4J_USER")] = "neo4j",
    neo4j_password: Annotated[str, typer.Option(envvar="NEO4J_PASSWORD")] = "neo4j",
) -> None:
    """Evaluate the policy; exit 1 on any high/critical violation (CI-friendly).

    With --plan, evaluates the Terraform-overlaid graph instead and exits by
    the --fail-on gate (pre-existing violations never block by default).
    """
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    try:
        if plan is not None:
            report, overlay = evaluate_guardrails_with_plan(
                policy.read_bytes(),
                neo4j_driver=driver,
                plan=json.loads(plan.read_text(encoding="utf-8")),
                account_ids=account or None,
                regions=region or None,
            )
        else:
            report = evaluate_guardrails(
                policy.read_bytes(),
                neo4j_driver=driver,
                account_ids=account or None,
                regions=region or None,
            )
    finally:
        driver.close()

    rendered = {"json": render_json, "sarif": render_sarif}.get(fmt, render_text)(report)
    if out is not None:
        out.write_text(rendered, encoding="utf-8")
        typer.echo(f"wrote {out}", err=True)
    else:
        typer.echo(rendered)

    if plan is not None:
        if overlay.unmapped_types:
            typer.echo(f"  unmapped types ignored: {', '.join(overlay.unmapped_types)}", err=True)
        raise typer.Exit(code=1 if report.gate_failed(fail_on) else 0)
    raise typer.Exit(code=report.exit_code())


@app.command()
def suggest(
    account: Annotated[
        str, typer.Option("--account", "-a", help="Account id to generate rules from.")
    ],
    region: Annotated[list[str], typer.Option("--region", "-r")] = [],
    neo4j_uri: Annotated[str, typer.Option(envvar="NEO4J_URI")] = "bolt://localhost:7687",
    neo4j_user: Annotated[str, typer.Option(envvar="NEO4J_USER")] = "neo4j",
    neo4j_password: Annotated[str, typer.Option(envvar="NEO4J_PASSWORD")] = "neo4j",
) -> None:
    """Generate candidate invariants from the live graph (ratchet / fix-first)."""
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    try:
        graph = fetch_graph(driver, account, region)
        cands = suggest_rules(graph, driver=driver, account_id=account)
    finally:
        driver.close()

    typer.echo(f"\n  Suggested guardrails for account {account} (from your live graph)\n")
    typer.echo("  RATCHET - already passing, adopt to lock in:")
    for c in [x for x in cands if not x.violations]:
        typer.echo(f"    [+] {c.id}  ({c.severity})\n          {c.rationale}")
    typer.echo("\n  FIX-FIRST - adopt to start tracking an existing problem:")
    for c in [x for x in cands if x.violations]:
        typer.echo(f"    [!] {c.id}  ({c.severity})   would flag {len(c.violations)} now")
        for v in c.violations:
            typer.echo(f"          - {v}")


if __name__ == "__main__":
    app()
