"""Operator vocabulary for the Phase 4.1 Detection Rule Contract.

Defines the minimal, extensible set of comparison operators a rule
condition may reference.  This is a **semantic contract**: it declares
the vocabulary, not the evaluation engine.

The execution engine (later phase) must implement these operators;
Phase 4.1 only locks the vocabulary and their semantics.

See Also:
    ``app/detection/contract/conditions.py`` for the condition model.
"""

from enum import StrEnum, auto
from typing import Final


class Operator(StrEnum):
    """Comparison operators available to detection rule conditions.

    Values are stable lowercase strings so they survive YAML/JSON
    serialization and replay.
    """

    EQUALS = "equals"
    """Field value is exactly equal to the condition value.

    Type-aware: ``1 == 1`` is true; ``"1" == 1`` is **false**.
    """

    NOT_EQUALS = "not_equals"
    """Field value is not equal to the condition value (type-aware)."""

    CONTAINS = "contains"
    """For strings: substring.  For sequences: membership.  For mappings: key."""

    STARTS_WITH = "starts_with"
    """String starts with the condition value."""

    ENDS_WITH = "ends_with"
    """String ends with the condition value."""

    REGEX = "regex"
    """String matches the condition value as a regular expression (re.search)."""

    EXISTS = "exists"
    """Tests whether the field is present and not ``None``.

    ``value`` is ignored; keep it ``None``.
    """

    GREATER_THAN = "greater_than"
    """Field value is strictly greater than the condition value."""

    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    """Field value is greater than or equal to the condition value."""

    LESS_THAN = "less_than"
    """Field value is strictly less than the condition value."""

    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    """Field value is less than or equal to the condition value."""

    IN = "in"
    """Field value is a member of the condition value (which must be a list/set)."""

    NOT_IN = "not_in"
    """Field value is not a member of the condition value (list/set)."""


#: Human-readable alias map used by YAML rule files that predate the
#: canonical spelling.  Kept small and explicit; do not grow this into
#: a synonym engine.
OPERATOR_ALIASES: Final[dict[str, Operator]] = {
    "==": Operator.EQUALS,
    "eq": Operator.EQUALS,
    "!=": Operator.NOT_EQUALS,
    "ne": Operator.NOT_EQUALS,
    "contains": Operator.CONTAINS,
    "startswith": Operator.STARTS_WITH,
    "endswith": Operator.ENDS_WITH,
    "match": Operator.REGEX,
    "regex": Operator.REGEX,
    "exists": Operator.EXISTS,
    ">": Operator.GREATER_THAN,
    "gt": Operator.GREATER_THAN,
    ">=": Operator.GREATER_THAN_OR_EQUAL,
    "gte": Operator.GREATER_THAN_OR_EQUAL,
    "<": Operator.LESS_THAN,
    "lt": Operator.LESS_THAN,
    "<=": Operator.LESS_THAN_OR_EQUAL,
    "lte": Operator.LESS_THAN_OR_EQUAL,
    "in": Operator.IN,
    "not_in": Operator.NOT_IN,
}


class MissingFieldPolicy(StrEnum):
    """Define how a condition behaves when the referenced field is absent.

    The contract requires explicit missing-field semantics.  A missing
    field must NEVER silently become ``False``, ``0``, or ``""``.
    """

    EVALUATE = auto()
    """The condition is evaluated normally against ``None``.

    The only operators that can legitimately pass against ``None`` are
    ``exists`` (false) and ``not_exists``-style negation handled at the
    logical level. Most operators evaluate to *non-match* rather than
    erroring.
    """

    FAIL_OPEN = auto()
    """Missing field causes the condition to match (rare; use with care).

    Intended for defensive rules that want to alert when telemetry is
    absent.  Must be declared explicitly by the rule author.
    """

    FAIL_CLOSED = auto()
    """Missing field causes the condition to fail (default, safest)."""


# Default policy applied when a rule does not declare one.
DEFAULT_MISSING_FIELD_POLICY: Final[MissingFieldPolicy] = MissingFieldPolicy.FAIL_CLOSED
