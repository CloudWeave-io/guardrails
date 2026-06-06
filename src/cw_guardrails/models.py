"""Result models — what the engine emits. (Policy *input* models live in policy.py.)"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEV_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# A failing invariant at or above this severity makes the CLI exit non-zero.
FAIL_THRESHOLD = SEV_RANK[Severity.HIGH]


class Status(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    WAIVED = "waived"  # every violation matched an active waiver
    ERROR = "error"  # the predicate could not be evaluated


class Violation(BaseModel):
    """One concrete breach of an invariant, with evidence."""

    resource: str = ""  # uid of the offending resource (or "" for graph-level)
    name: str = ""  # friendly name
    message: str  # human-readable evidence
    path: list[str] = Field(default_factory=list)  # uids forming the evidence path
    waiver_reason: str | None = None  # set when downgraded by a waiver


class InvariantResult(BaseModel):
    id: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    predicate: str = ""  # which predicate kind fired (e.g. "not_path")
    status: Status = Status.PASS
    violations: list[Violation] = Field(default_factory=list)
    waived: list[Violation] = Field(default_factory=list)


class GuardrailReport(BaseModel):
    account_ids: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    graph_nodes: int = 0
    graph_edges: int = 0
    results: list[InvariantResult] = Field(default_factory=list)

    @property
    def failed(self) -> list[InvariantResult]:
        return [r for r in self.results if r.status == Status.FAIL]

    @property
    def passed(self) -> list[InvariantResult]:
        return [r for r in self.results if r.status == Status.PASS]

    def worst_failed_rank(self) -> int:
        return max((SEV_RANK[r.severity] for r in self.failed), default=-1)

    def exit_code(self) -> int:
        """0 = clean (no high/critical failure); 1 = blocking failure."""
        return 1 if self.worst_failed_rank() >= FAIL_THRESHOLD else 0

    def summary(self) -> dict[str, int]:
        return {
            "rules": len(self.results),
            "passed": len(self.passed),
            "failed": len(self.failed),
            "waived": sum(1 for r in self.results if r.status == Status.WAIVED),
            "violations": sum(len(r.violations) for r in self.results),
        }
