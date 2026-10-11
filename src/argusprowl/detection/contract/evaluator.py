"""Condition evaluator for the Phase 4.1 Detection Rule Contract.

Implements stateless evaluation of atomic conditions and logical expressions
against a single NormalizedEvent.  This is the execution engine for the
contract defined in app.detection.contract.* and is intentionally separate
from the imperative detector implementations.

The evaluator is strict about types, deterministic, and never executes
arbitrary code or unsafe operations.

Field resolution supports:
- Canonical fields (process_name, src_ip, dst_port, ...)
- Source-specific attributes via attributes["QueryName"]
- Simple dotted paths (attributes.fileinfo.filename)

Missing-field semantics follow the declared MissingFieldPolicy:
- fail_closed: absent field → non-match
- fail_open: absent field → match
- evaluate: treat absent field as None and evaluate normally

Operators are type-aware; for example, integer 80 is not equal to string "80".

Evidence and explanation are generated only on successful matches.
"""

from __future__ import annotations

import re
from typing import Any, Final

from argusprowl.detection.contract.conditions import Condition
from argusprowl.detection.contract.logical import LogicalExpression, LogicOperator
from argusprowl.detection.contract.operators import (
    MissingFieldPolicy,
    Operator,
)
from argusprowl.models.normalized_event import NormalizedEvent

# Regex to parse field references like "attributes[\"QueryName\"]" or "fileinfo.filename"
_FIELD_REF_RE: Final[re.Pattern[str]] = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)(\[\"([^\"]*)\"\])?(\.[A-Za-z_][A-Za-z0-9_]*)*$"
)


class ConditionEvaluator:
    """Stateless evaluator for DetectionRule conditions against a NormalizedEvent.

    This class is intentionally stateless; it does not cache regex patterns or
    compile rules.  It is safe to instantiate per evaluation.

    Attributes:
        event: The NormalizedEvent being evaluated.
        rule_id: Optional rule identity for evidence/explanation.
        rule_version: Optional rule version for result.
    """

    def __init__(
        self,
        event: NormalizedEvent,
        rule_id: str | None = None,
        rule_version: int | None = None,
    ) -> None:
        self._event = event
        self._rule_id = rule_id
        self._rule_version = rule_version

    def evaluate_condition(self, condition: Condition) -> tuple[bool, list[dict[str, Any]]]:
        """Evaluate a single atomic condition against the event.

        Args:
            condition: The condition to evaluate.

        Returns:
            Tuple of (matched, evidence_list).  Evidence is empty on non-match.
        """
        field_value = self._resolve_field(condition.field)
        policy = condition.missing_field_policy

        # Handle missing field according to policy
        if field_value is None and policy == MissingFieldPolicy.FAIL_CLOSED:
            return False, []
        if field_value is None and policy == MissingFieldPolicy.FAIL_OPEN:
            return True, []
        # For evaluate policy, treat None as a value and proceed

        # Operator-specific evaluation
        try:
            if condition.operator == Operator.EXISTS:
                matched = field_value is not None
                evidence = self._build_evidence(condition, field_value, matched)
                return matched, evidence

            if field_value is None:
                # Operator requires a value but field is absent
                return False, []

            if condition.operator == Operator.EQUALS:
                matched = self._equals(field_value, condition.value)
            elif condition.operator == Operator.NOT_EQUALS:
                matched = not self._equals(field_value, condition.value)
            elif condition.operator == Operator.CONTAINS:
                matched = self._contains(field_value, condition.value)
            elif condition.operator == Operator.STARTS_WITH:
                matched = self._starts_with(field_value, condition.value)
            elif condition.operator == Operator.ENDS_WITH:
                matched = self._ends_with(field_value, condition.value)
            elif condition.operator == Operator.REGEX:
                matched = self._regex(field_value, condition.value)
            elif condition.operator == Operator.GREATER_THAN:
                matched = self._greater_than(field_value, condition.value)
            elif condition.operator == Operator.GREATER_THAN_OR_EQUAL:
                matched = self._greater_than_or_equal(field_value, condition.value)
            elif condition.operator == Operator.LESS_THAN:
                matched = self._less_than(field_value, condition.value)
            elif condition.operator == Operator.LESS_THAN_OR_EQUAL:
                matched = self._less_than_or_equal(field_value, condition.value)
            elif condition.operator == Operator.IN:
                matched = self._in(field_value, condition.value)
            elif condition.operator == Operator.NOT_IN:
                matched = not self._in(field_value, condition.value)
            else:
                # Unsupported operator
                raise ValueError(f"Unsupported operator: {condition.operator}")

            evidence = self._build_evidence(condition, field_value, matched)
            return matched, evidence

        except (TypeError, ValueError):
            # Deterministic failure on type errors or invalid operations
            return False, []

    def evaluate_logical_expression(
        self, expression: LogicalExpression
    ) -> tuple[bool, list[dict[str, Any]]]:
        """Evaluate a logical expression tree.

        Args:
            expression: The logical expression to evaluate.

        Returns:
            Tuple of (matched, evidence_list).  Evidence is a list of all evidence
            from child evaluations.
        """
        if expression.condition is not None:
            return self.evaluate_condition(expression.condition)

        if expression.operator == LogicOperator.AND:
            return self._evaluate_and(expression.children)
        if expression.operator == LogicOperator.OR:
            return self._evaluate_or(expression.children)
        if expression.operator == LogicOperator.NOT:
            return self._evaluate_not(expression.children)

        raise ValueError(f"Unknown logical operator: {expression.operator}")

    def _resolve_field(self, field_ref: str) -> Any:
        """Resolve a field reference to its value in the event.

        Supports:
        - Canonical fields: process_name, src_ip, dst_port, ...
        - Source-specific: attributes["QueryName"]
        - Dotted paths: attributes.fileinfo.filename

        Returns:
            The resolved value, or None if the field is absent.
        """
        if not isinstance(field_ref, str) or not field_ref.strip():
            return None

        if not _FIELD_REF_RE.match(field_ref):
            return None

        # Split into base and path components
        parts = field_ref.split(".", 1)
        base = parts[0]
        path = parts[1] if len(parts) > 1 else None

        # Handle attributes["key"] syntax
        attr_match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\[\"([^\"]+)\"\](.*)$", base)
        if attr_match:
            attr_name = attr_match.group(1)
            key = attr_match.group(2)
            suffix = attr_match.group(3)

            if attr_name != "attributes":
                return None

            # Get attributes dict
            attrs = self._event.attributes
            if not isinstance(attrs, dict):
                return None

            value = attrs.get(key)
            if value is None:
                return None

            # Apply dotted suffix if present
            if suffix:
                return self._resolve_dotted(value, suffix)

            return value

        # Handle canonical field
        canonical_value = self._get_canonical_field(base)
        if canonical_value is not None:
            if path:
                return self._resolve_dotted(canonical_value, path)
            return canonical_value

        # Handle attributes without bracket syntax
        if base == "attributes":
            if path:
                return self._resolve_dotted(self._event.attributes, path)
            return self._event.attributes

        return None

    def _get_canonical_field(self, field_name: str) -> Any:
        """Get the value of a canonical field from the event.

        Canonical fields include: source_type, event_type, timestamp, hostname,
        sensor, src_ip, src_port, dst_ip, dst_port, protocol, username,
        process_name, command_line, severity.
        """
        mapping = {
            "source_type": self._event.source_type,
            "event_type": self._event.event_type,
            "timestamp": self._event.timestamp,
            "hostname": self._event.hostname,
            "sensor": self._event.sensor,
            "src_ip": self._event.src_ip,
            "src_port": self._event.src_port,
            "dst_ip": self._event.dst_ip,
            "dst_port": self._event.dst_port,
            "protocol": self._event.protocol,
            "username": self._event.username,
            "process_name": self._event.process_name,
            "command_line": self._event.command_line,
            "severity": self._event.severity,
        }
        return mapping.get(field_name)

    def _resolve_dotted(self, obj: Any, path: str) -> Any:
        """Resolve a dotted path in a nested structure.

        Examples:
            obj = {"fileinfo": {"filename": "test.exe"}}
            path = "fileinfo.filename" → "test.exe"

        Returns:
            The resolved value, or None if any component is missing or wrong type.
        """
        if not isinstance(path, str) or not path.strip():
            return None

        parts = path.split(".")
        current = obj

        for part in parts:
            if current is None:
                return None
            if isinstance(current, dict):
                current = current.get(part)
            elif hasattr(current, "__getitem__"):
                try:
                    current = current[part]
                except (KeyError, IndexError, TypeError):
                    return None
            else:
                return None

        return current

    def _equals(self, left: Any, right: Any) -> bool:
        """Type-aware equality comparison.

        Returns True only if types match and values are equal.
        """
        return left == right and type(left) is type(right)

    def _contains(self, container: Any, value: Any) -> bool:
        """Membership or substring check.

        For strings: substring check.
        For sequences: membership check.
        For mappings: key check.
        """
        if isinstance(container, str):
            return isinstance(value, str) and value in container
        if isinstance(container, (list, tuple, set, frozenset)):
            return value in container
        if isinstance(container, dict):
            return value in container
        return False

    def _starts_with(self, container: Any, value: Any) -> bool:
        """String starts-with check."""
        if isinstance(container, str) and isinstance(value, str):
            return container.startswith(value)
        return False

    def _ends_with(self, container: Any, value: Any) -> bool:
        """String ends-with check."""
        if isinstance(container, str) and isinstance(value, str):
            return container.endswith(value)
        return False

    def _regex(self, container: Any, pattern: Any) -> bool:
        """Regex matching using re.search.

        Returns False on invalid regex patterns.
        """
        if not isinstance(container, str) or not isinstance(pattern, str):
            return False

        try:
            import re as regex_module

            return bool(regex_module.search(pattern, container))
        except re.error:
            return False

    def _greater_than(self, left: Any, right: Any) -> bool:
        """Numeric greater-than comparison.

        Only works for compatible numeric types.
        """
        try:
            return float(left) > float(right)
        except (TypeError, ValueError):
            return False

    def _greater_than_or_equal(self, left: Any, right: Any) -> bool:
        """Numeric greater-than-or-equal comparison."""
        try:
            return float(left) >= float(right)
        except (TypeError, ValueError):
            return False

    def _less_than(self, left: Any, right: Any) -> bool:
        """Numeric less-than comparison."""
        try:
            return float(left) < float(right)
        except (TypeError, ValueError):
            return False

    def _less_than_or_equal(self, left: Any, right: Any) -> bool:
        """Numeric less-than-or-equal comparison."""
        try:
            return float(left) <= float(right)
        except (TypeError, ValueError):
            return False

    def _in(self, value: Any, collection: Any) -> bool:
        """Membership check.

        Collection must be a list, tuple, set, or frozenset.
        """
        if isinstance(collection, (list, tuple, set, frozenset)):
            return value in collection
        return False

    def _build_evidence(
        self, condition: Condition, observed: Any, matched: bool
    ) -> list[dict[str, Any]]:
        """Build evidence entry for a condition evaluation.

        Only builds evidence if matched is True.
        """
        if not matched:
            return []

        evidence = {
            "field": condition.field,
            "observed": observed,
            "condition": condition.to_short_string(),
        }

        if self._rule_id is not None:
            evidence["rule_id"] = self._rule_id
        if self._rule_version is not None:
            evidence["rule_version"] = self._rule_version
        if self._event.event_id is not None:
            evidence["event_id"] = self._event.event_id

        return [evidence]

    def _evaluate_and(
        self, children: tuple[LogicalExpression, ...]
    ) -> tuple[bool, list[dict[str, Any]]]:
        """Evaluate AND expression with short-circuiting."""
        all_matched = True
        all_evidence: list[dict[str, Any]] = []

        for child in children:
            matched, evidence = self.evaluate_logical_expression(child)
            if not matched:
                all_matched = False
                # Continue to collect all evidence for completeness
                all_evidence.extend(evidence)
                break
            all_evidence.extend(evidence)

        return all_matched, all_evidence

    def _evaluate_or(
        self, children: tuple[LogicalExpression, ...]
    ) -> tuple[bool, list[dict[str, Any]]]:
        """Evaluate OR expression with short-circuiting."""
        any_matched = False
        all_evidence: list[dict[str, Any]] = []

        for child in children:
            matched, evidence = self.evaluate_logical_expression(child)
            if matched:
                any_matched = True
                all_evidence.extend(evidence)
                break
            all_evidence.extend(evidence)

        return any_matched, all_evidence

    def _evaluate_not(
        self, children: tuple[LogicalExpression, ...]
    ) -> tuple[bool, list[dict[str, Any]]]:
        """Evaluate NOT expression."""
        if len(children) != 1:
            raise ValueError("NOT expression requires exactly one child")

        matched, evidence = self.evaluate_logical_expression(children[0])
        return not matched, evidence


__all__ = ["ConditionEvaluator"]
