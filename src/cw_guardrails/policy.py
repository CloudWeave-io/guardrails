"""Policy input models + YAML loader.

A policy is the contract a team writes (or generates). It parses into these
pydantic models, which the engine evaluates. The selector vocabulary and the
predicate catalog are both defined here, so this file is the single source of
truth for "what you can express".
"""

from __future__ import annotations

from datetime import date as _date
from typing import Annotated, Any, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cw_guardrails.models import Severity


class SelectorSpec(BaseModel):
    """An inline resource selector. Fields AND together. All optional."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    type: str | list[str] | None = None
    tag: str | None = None  # "key=value" or "key" (key present)
    name_matches: str | None = None  # glob with '*' and '|' alternation
    account: str | None = None
    region: str | None = None
    cidr: str | None = None
    id: str | None = None
    pseudo: str | None = None  # "internet"


# A selector reference is either an inline spec or a group name (string).
SelectorRef = Union[str, SelectorSpec]


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    accounts: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)


# ── predicate parameter blocks ───────────────────────────────────────────────
class NotIngress(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    select: SelectorRef
    ports: list[int] = Field(default_factory=list)  # empty = any port
    from_: str = Field("0.0.0.0/0", alias="from")


class SelectOnly(BaseModel):
    model_config = ConfigDict(extra="forbid")
    select: SelectorRef


class FromTo(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    from_: SelectorRef = Field(alias="from")
    to: SelectorRef


class OnlyVia(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    from_: SelectorRef = Field(alias="from")
    to: SelectorRef
    through: SelectorRef


class PropertyCheck(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")
    select: SelectorRef
    field: str
    equals: Any | None = None
    in_: list[Any] | None = Field(default=None, alias="in")
    matches: str | None = None


class MustHave(BaseModel):
    model_config = ConfigDict(extra="forbid")
    select: SelectorRef
    has: str  # a neighbor resource type the selected node must be related to


# Map YAML predicate key -> (attribute name on Invariant, model).
PREDICATES: dict[str, tuple[str, type[BaseModel]]] = {
    "not_ingress": ("not_ingress", NotIngress),
    "not_public": ("not_public", SelectOnly),
    "not_in_public_subnet": ("not_in_public_subnet", SelectOnly),
    "not_path": ("not_path", FromTo),
    "only_via": ("only_via", OnlyVia),
    "property": ("property_", PropertyCheck),
    "must_have": ("must_have", MustHave),
    "no_shared_tgw": ("no_shared_tgw", SelectOnly),
}


class Invariant(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    id: str
    description: str = ""
    severity: Severity = Severity.MEDIUM

    not_ingress: NotIngress | None = None
    not_public: SelectOnly | None = None
    not_in_public_subnet: SelectOnly | None = None
    not_path: FromTo | None = None
    only_via: OnlyVia | None = None
    property_: PropertyCheck | None = Field(default=None, alias="property")
    must_have: MustHave | None = None
    no_shared_tgw: SelectOnly | None = None

    @model_validator(mode="after")
    def _exactly_one_predicate(self) -> Invariant:
        present = [attr for _, (attr, _m) in PREDICATES.items() if getattr(self, attr) is not None]
        if len(present) != 1:
            raise ValueError(
                f"invariant '{self.id}' must declare exactly one predicate, found {len(present)}: "
                f"{present or 'none'}"
            )
        return self

    @property
    def predicate_kind(self) -> str:
        for key, (attr, _m) in PREDICATES.items():
            if getattr(self, attr) is not None:
                return key
        return ""

    @property
    def predicate(self) -> BaseModel:
        return getattr(self, PREDICATES[self.predicate_kind][0])


class Waiver(BaseModel):
    model_config = ConfigDict(extra="forbid")
    invariant: str  # invariant id this waiver applies to
    target: SelectorSpec | None = None  # which resource(s); None = whole invariant
    reason: str = ""
    expires: str | None = None  # ISO date; past => waiver inactive (re-arms finding)

    @field_validator("expires", mode="before")
    @classmethod
    def _coerce_date(cls, v: object) -> object:
        # YAML parses an unquoted 2026-09-01 into a date — normalize to a string.
        return v.isoformat() if isinstance(v, _date) else v


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    scope: Scope = Field(default_factory=Scope)
    groups: dict[str, SelectorSpec] = Field(default_factory=dict)
    invariants: Annotated[list[Invariant], Field(min_length=1)]
    waivers: list[Waiver] = Field(default_factory=list)


def load_policy(source: str | bytes) -> Policy:
    """Parse YAML (or JSON — YAML is a superset) into a validated Policy."""
    if isinstance(source, bytes):
        source = source.decode("utf-8")
    data = yaml.safe_load(source)
    if not isinstance(data, dict):
        raise ValueError("policy must be a YAML mapping at the top level")
    return Policy.model_validate(data)
