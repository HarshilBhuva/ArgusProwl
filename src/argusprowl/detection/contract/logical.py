"""Logical composition for the Phase 4.1 Detection Rule Contract.

Rules compose atomic conditions and nested groups with AND / OR / NOT.

The contract defines the *structure*; a later-phase execution engine
implements evaluation.  Phase 4.1 must not build a full expression
language — this module only fixes the semantics:

- ``AND``: every member must hold.
- ``OR``: at least one member must hold.
- ``NOT``: the wrapped expression must not hold.

With the default ``fail_closed`` missing-field policy, a missing field
causes its atomic condition to yield *non-match*, which propagates
through this boolean structure naturally. A rule may declare a different
policy explicitly per condition (see ``MissingFieldPolicy``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from argusprowl.detection.contract.conditions import Condition
from argusprowl.exceptions.exceptions import ValidationError


class LogicOperator(StrEnum):
    """Logical combinators supported by the rule contract."""

    AND = "and"
    OR = "or"
    NOT = "not"


@dataclass(frozen=True, slots=True)
class LogicalExpression:
    """A node in the rule condition tree.

    Either wraps a single :class:`Condition` (``operator`` is ``None``)
    or composes children with a :class:`LogicOperator`.

    Attributes:
        operator: Logic operator for composition, or ``None`` when this
            node is a leaf condition.
        condition: Atomic condition (leaf nodes only).
        children: Sub-expressions (non-leaf nodes only).
    """

    operator: LogicOperator | None = None
    condition: Condition | None = None
    children: tuple[LogicalExpression, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Validate node shape."""
        if self.condition is not None and self.operator is not None:
            raise ValueError("LogicalExpression cannot have both a condition and an operator.")
        if self.condition is None and self.operator is None:
            raise ValueError("LogicalExpression must be either a condition or an operator node.")
        if self.operator is not None:
            if not isinstance(self.operator, LogicOperator):
                raise ValueError(
                    f"Logical operator must be a LogicOperator, got {self.operator!r}."
                )
            if self.operator is LogicOperator.NOT and len(self.children) != 1:
                raise ValueError("NOT expression requires exactly one child.")
            if self.operator in (LogicOperator.AND, LogicOperator.OR) and not self.children:
                raise ValueError(
                    f"{self.operator.value.upper()} expression requires at least one child."
                )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the tree to plain YAML/JSON-friendly mappings."""
        if self.condition is not None:
            return {"condition": self.condition.to_dict()}
        return {
            "operator": self.operator.value
            if isinstance(self.operator, LogicOperator)
            else str(self.operator),
            "children": [child.to_dict() for child in self.children],
        }


def logic_operator(symbol: str | LogicOperator) -> LogicOperator:
    """Resolve a logic operator from its canonical spelling.

    Args:
        symbol: ``LogicOperator`` or a string like ``"and"``.

    Returns:
        The canonical :class:`LogicOperator`.

    Raises:
        ValidationError: Unknown logical operator.
    """
    if isinstance(symbol, LogicOperator):
        return symbol
    lowered = str(symbol).strip().lower()
    try:
        return LogicOperator(lowered)
    except ValueError as exc:
        raise ValidationError(f"Unknown logical operator {symbol!r}.") from exc


__all__: Final[list[str]] = [
    "LogicOperator",
    "LogicalExpression",
    "logic_operator",
]
