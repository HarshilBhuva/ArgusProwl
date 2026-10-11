"""Rule factory — construct contract rules from plain mappings.

YAML is treated as one possible *representation* of the Detection Rule
Contract, never the semantic authority.  This factory consumes
dictionary-shaped data (as produced by a YAML/JSON loader or a
programmatic caller) and returns validated contract objects.

Sigma and programmatic construction are future interoperability targets;
this factory documents the stable boundary a future Sigma importer would
implement against.
"""

from __future__ import annotations

from typing import Any, Final

from argusprowl.constants.severity import Severity
from argusprowl.detection.contract.conditions import Condition
from argusprowl.detection.contract.logical import LogicalExpression, LogicOperator
from argusprowl.detection.contract.rule import DetectionRule, RuleApplicability
from argusprowl.exceptions.exceptions import ValidationError


def _parse_conditions(data: Any) -> LogicalExpression | Condition | None:
    """Parse a condition tree from a mapping or list.

    Supported shapes::

        {"field": "...", "operator": "...", "value": ...}             # atomic
        {"and": [ ... ]} or {"or": [...]} or {"not": {...}}          # logical
        [ {"and": [...]} ]                                            # logical list

    Args:
        data: Condition tree representation.

    Returns:
        A :class:`Condition` or :class:`LogicalExpression`, or ``None``.
    """
    if data is None:
        return None
    if isinstance(data, dict):
        if "field" in data:
            try:
                return Condition(
                    field=data["field"],
                    operator=data.get("operator", "equals"),
                    value=data.get("value"),
                    missing_field_policy=data.get("missing_field_policy", "fail_closed"),
                    description=data.get("description"),
                )
            except ValueError as exc:
                raise ValidationError(f"Invalid condition: {exc}") from exc
        for key in ("and", "or", "not"):
            if key in data:
                children = data[key]
                if key == "not":
                    if isinstance(children, dict):
                        children = [children]
                    nodes = _parse_conditions_list(children)
                    if len(nodes) != 1:
                        raise ValidationError("NOT expression requires exactly one child.")
                    return LogicalExpression(operator=LogicOperator.NOT, children=tuple(nodes))
                nodes = _parse_conditions_list(children)
                return LogicalExpression(
                    operator=LogicOperator.AND if key == "and" else LogicOperator.OR,
                    children=tuple(nodes),
                )
        raise ValidationError(f"Invalid condition mapping: {data!r}")
    if isinstance(data, list):
        nodes = _parse_conditions_list(data)
        if len(nodes) == 1:
            return nodes[0]
        return LogicalExpression(operator=LogicOperator.AND, children=tuple(nodes))
    raise ValidationError(f"Invalid conditions value: {data!r}")


def _parse_conditions_list(data: Any) -> list[LogicalExpression | Condition]:
    """Parse a list of condition children."""
    if not isinstance(data, list):
        raise ValidationError("Logical composition children must be a list.")
    nodes: list[LogicalExpression | Condition] = []
    for item in data:
        parsed = _parse_conditions(item)
        if isinstance(parsed, Condition):
            parsed = LogicalExpression(condition=parsed)
        if parsed is None:
            raise ValidationError("Logical composition contains an empty child.")
        nodes.append(parsed)
    return nodes


def _parse_severity(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity.from_string(str(value))
    except ValueError as exc:
        raise ValidationError(f"Invalid severity: {value!r}. {exc}") from exc


def rule_from_dict(data: dict[str, Any]) -> DetectionRule:
    """Build a validated :class:`DetectionRule` from a plain mapping.

    Args:
        data: Mapping with rule fields.  Uses the same conventions as
            the ``rules/*.yaml`` files, plus the contract fields
            (``conditions``, ``applicability``, ``tactic``, ...).

    Returns:
        A validated :class:`DetectionRule`.

    Raises:
        ValidationError: Structural/contract violation.
    """
    try:
        severity = _parse_severity(data.get("severity", "MEDIUM"))
        conditions = _parse_conditions(data.get("conditions"))

        applicability_data = data.get("applicability") or {}
        if not isinstance(applicability_data, dict):
            raise ValidationError("applicability must be a mapping.")
        applicability = RuleApplicability(
            source_types=tuple(applicability_data.get("source_types", ())),
            event_types=tuple(applicability_data.get("event_types", ())),
            protocols=tuple(applicability_data.get("protocols", ())),
            hosts=tuple(applicability_data.get("hosts", ())),
            sensors=tuple(applicability_data.get("sensors", ())),
        )

        temporal_data = data.get("temporal")
        temporal = None
        if temporal_data:
            from argusprowl.detection.contract.rule import TemporalSpec

            seq = tuple(
                Condition(field=c["field"], operator=c.get("operator"), value=c.get("value"))
                for c in temporal_data.get("sequence", ())
            )
            temporal = TemporalSpec(
                within_seconds=temporal_data.get("within_seconds"),
                min_count=temporal_data.get("min_count"),
                group_by=tuple(temporal_data.get("group_by", ())),
                ordered=bool(temporal_data.get("ordered", False)),
                sequence=seq,
            )

        return DetectionRule(
            rule_id=str(data["rule_id"]),
            name=str(data["name"]),
            description=str(data.get("description", "")),
            version=int(data.get("version", 1)),
            enabled=bool(data.get("enabled", True)),
            severity=severity,
            confidence=float(data.get("confidence", 0.7)),
            tags=tuple(data.get("tags", ())),
            tactic=data.get("tactic"),
            technique=data.get("technique"),
            subtechnique=data.get("subtechnique"),
            references=tuple(data.get("references", ())),
            author=data.get("author"),
            applicability=applicability,
            conditions=conditions,
            temporal=temporal,
            metadata=dict(data.get("metadata", {})),
        )
    except KeyError as exc:
        raise ValidationError(f"Missing required rule field: {exc.args[0]}.") from exc
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Invalid rule definition: {exc}") from exc


__all__: Final[list[str]] = [
    "_parse_conditions",
    "rule_from_dict",
]
