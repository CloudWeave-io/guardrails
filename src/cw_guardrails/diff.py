"""Baseline diff — mark which violations a plan overlay INTRODUCED.

Key = (invariant id, violation resource uid). A violation present in the
baseline (active or waived) stays pre-existing even if its message or path
changed; planned resources (synthetic `tf:` uids) can never be in the
baseline, so they are always new. The ratchet: pre-existing debt never blocks
an unrelated PR.
"""

from __future__ import annotations

from cw_guardrails.models import GuardrailReport


def annotate_new(baseline: GuardrailReport, after: GuardrailReport) -> GuardrailReport:
    """Annotate `after` in place (and return it): every violation gets new=True/False."""
    base_keys = {(r.id, v.resource) for r in baseline.results for v in (*r.violations, *r.waived)}
    for r in after.results:
        for v in (*r.violations, *r.waived):
            v.new = (r.id, v.resource) not in base_keys
    return after
