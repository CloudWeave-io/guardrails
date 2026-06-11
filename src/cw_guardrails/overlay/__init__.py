"""Terraform-plan overlay — evaluate "the world as it would be after merge".

Public surface: `overlay_plan(base_graph, plan_dict) -> OverlayResult`.
"""

from cw_guardrails.overlay.apply import OverlayResult, overlay_plan
from cw_guardrails.overlay.resolve import is_planned_uid, synthetic_uid

__all__ = ["OverlayResult", "overlay_plan", "is_planned_uid", "synthetic_uid"]
