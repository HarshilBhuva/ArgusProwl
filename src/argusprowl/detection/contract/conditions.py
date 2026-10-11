"""Condition model for the Phase 4.1 Detection Rule Contract.

A single atomic condition is a semantic triple:

    field
    operator
    value

Rules compose conditions with AND / OR / NOT (see
``app/detection/contract/logical.py``).  Condition execution belongs to
a later phase; this module locks the *structure* and the validation
semantics.

Missing-field semantics are explicit (see ``MissingFieldPolicy`` in
``app/detection/contract/operators.py``).  A missing field NEVER silently
becomes ``False``, ``0``, or ``""``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from argusprowl.detection.contract.operators import (
    DEFAULT_MISSING_FIELD_POLICY,
    OPERATOR_ALIASES,
    MissingFieldPolicy,
    Operator,
)

# Regex used to validate field references.  Prefixes of the form
# ``attributes["QueryName"]`` are permitted so source-specific telemetry
# stays reachable through ``NormalizedEvent.attributes``.
_FIELD_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*"
    r"(\[\"(?:[^\"\\]|\\.)*\"\])?"
    r"(\.[A-Za-z_][A-Za-z0-9_]*)?$"
)


@dataclass(frozen=True, slots=True)
class Condition:
    """An atomic detection condition.

    Attributes:
        field: Canonical field name, or ``attributes["QueryName"]`` /
            dotted path for source-specific telemetry.
        operator: Comparison operator from the contract vocabulary.
        value: Expected value; optional for ``exists``.
        missing_field_policy: Behavior when *field* is absent.
        description: Optional human-readable intent of this condition.
    """

    field: str
    operator: Operator | str
    value: Any = None
    missing_field_policy: MissingFieldPolicy = DEFAULT_MISSING_FIELD_POLICY
    description: str | None = None

    def __post_init__(self) -> None:
        """Normalize operator and validate the condition shape."""
        object.__setattr__(self, "operator", _coerce_operator(self.operator))
        if not isinstance(self.field, str) or not _FIELD_RE.match(self.field):
            raise ValueError(
                f"Condition field is malformed: {self.field!r}. "
                "Expected a canonical field like 'process_name' or "
                'attributes["QueryName"].'
            )
        if self.operator is Operator.EXISTS:
            # exists ignores value; allow arbitrary value but keep it None
            object.__setattr__(self, "value", None)
        elif isinstance(self.operator, Operator) and self.operator in (
            Operator.IN,
            Operator.NOT_IN,
        ):
            if not isinstance(self.value, (list, tuple, set, frozenset)):
                raise ValueError(
                    f"Operator {self.operator.value} requires a collection value, "
                    f"got {type(self.value).__name__}."
                )
            if not self.value:
                raise ValueError(f"Operator {self.operator.value} requires a non-empty collection.")
            object.__setattr__(self, "value", list(self.value))
        if isinstance(self.missing_field_policy, str):
            try:
                object.__setattr__(
                    self,
                    "missing_field_policy",
                    MissingFieldPolicy(self.missing_field_policy.strip().lower()),
                )
            except ValueError as exc:
                raise ValueError(
                    f"Unknown missing_field_policy {self.missing_field_policy!r}. "
                    f"Valid: {[p.value for p in MissingFieldPolicy]}"
                ) from exc
        if not isinstance(self.missing_field_policy, MissingFieldPolicy):
            raise ValueError(
                f"missing_field_policy must be a MissingFieldPolicy, "
                f"got {self.missing_field_policy!r}."
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain mapping compatible with YAML/JSON."""
        return {
            "field": self.field,
            "operator": self.operator.value
            if isinstance(self.operator, Operator)
            else str(self.operator),
            "value": self.value,
            "missing_field_policy": self.missing_field_policy.value,
            "description": self.description,
        }

    def to_short_string(self) -> str:
        """Render a short canonical string like ``process_name equals powershell.exe``."""
        value = "" if self.value is None else f" {self.value!r}"
        return f"{self.field} {self.operator.value}{value}"


def _coerce_operator(operator: Operator | str) -> Operator:
    """Resolve an operator from its canonical or alias spelling.

    Args:
        operator: Explicit ``Operator`` or a string (canonical or alias).

    Returns:
        The canonical :class:`Operator`.

    Raises:
        ValueError: If the string is not a known operator.
    """
    if isinstance(operator, Operator):
        return operator
    if not isinstance(operator, str):
        raise ValueError(
            f"Condition operator must be an Operator or str, got {type(operator).__name__}."
        )
    lowered = operator.strip().lower()
    if lowered in OPERATOR_ALIASES:
        return OPERATOR_ALIASES[lowered]
    try:
        return Operator(lowered)
    except ValueError as exc:
        raise ValueError(
            f"Unsupported condition operator {operator!r}. "
            f"Supported operators: {[op.value for op in Operator]}"
        ) from exc


@dataclass(frozen=True, slots=True)
class FieldReference:
    """A reference to a canonical field with metadata about it.

    Phase 4.1 does not implement a full schema registry; this small
    helper documents how a rule may declare which fields it relies on,
    in addition to the inline ``Condition.field`` strings.
    """

    field: str
    required: bool = True
    source: str | None = None  # e.g. "canonical" or "attributes['QueryName']"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {"field": self.field, "required": self.required, "source": self.source}


__all__: Final[list[str]] = [
    "Condition",
    "FieldReference",
    "_coerce_operator",
]
