"""DetectionRule — the canonical Phase 4.1 rule contract.

This module defines what **a detection rule IS** in argusprowl,
independent of any serialization format.  YAML files, Sigma imports,
and programmatic rule construction are all *representations* of this
contract — never the semantic authority.

A rule answers three questions:

1. What does it consume?  (source applicability / conditions)
2. What does it detect?   (conditions, temporal shape)
3. What does it produce?  (severity, confidence, evidence contract)

Temporal / correlation semantics are **reserved** for later phases.  The
``temporal`` field of this model documents future intent without
implementing execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from argusprowl.constants.severity import Severity
from argusprowl.detection.contract.conditions import Condition
from argusprowl.detection.contract.logical import LogicalExpression
from argusprowl.exceptions.exceptions import ValidationError

#: Canonical rule-id prefix convention.  Documented, not enforced: rule
#: ids must be stable and human-readable, e.g. ``TH-NET-C2-001``.
RULE_ID_PREFIX: Final[str] = "TH-"

#: Earliest supported rule version.  Versions are 1-based.
MIN_RULE_VERSION: Final[int] = 1

#: Required fields that make a rule identity valid.
_REQUIRED_IDENTITY_FIELDS: Final[tuple[str, ...]] = ("rule_id", "name")


@dataclass(frozen=True, slots=True)
class RuleApplicability:
    """Declare which telemetry a rule applies to.

    The contract deliberately keeps canonical applicability narrow.
    Source-specific fields remain reachable through condition field
    references (``attributes["QueryName"]``), preserving the
    canonical-vs-attributes architectural split.
    """

    source_types: tuple[str, ...] = ()
    event_types: tuple[str, ...] = ()
    protocols: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    sensors: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """True where the rule does not constrain applicability."""
        return not any(
            (self.source_types, self.event_types, self.protocols, self.hosts, self.sensors)
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain mapping."""
        return {
            "source_types": list(self.source_types),
            "event_types": list(self.event_types),
            "protocols": list(self.protocols),
            "hosts": list(self.hosts),
            "sensors": list(self.sensors),
        }


@dataclass(frozen=True, slots=True)
class TemporalSpec:
    """Declarative description of future stateful detection semantics.

    Phase 4.1 **reserved** this concept: the model documents it so a
    later execution engine can implement it without changing the rule
    contract.  No state storage or execution exists yet.

    Examples of future semantics this must be able to express::

        within_time: 60 seconds
        min_count: 5
        group_by: [src_ip]
        ordered: true
        sequence: [process_create, network_connection]
    """

    within_seconds: int | None = None
    min_count: int | None = None
    group_by: tuple[str, ...] = ()
    ordered: bool = False
    sequence: tuple[Condition, ...] = ()

    def __post_init__(self) -> None:
        """Validate reserved temporal semantics without executing them."""
        if self.within_seconds is not None and (
            isinstance(self.within_seconds, bool) or self.within_seconds <= 0
        ):
            raise ValidationError("Temporal within_seconds must be a positive integer.")
        if self.min_count is not None and (isinstance(self.min_count, bool) or self.min_count < 1):
            raise ValidationError("Temporal min_count must be an integer >= 1.")
        if not isinstance(self.ordered, bool):
            raise ValidationError("Temporal ordered must be a boolean.")
        if any(not isinstance(field, str) or not field.strip() for field in self.group_by):
            raise ValidationError("Temporal group_by values must be non-empty strings.")

    @property
    def is_stateful(self) -> bool:
        """True where the rule declares temporal/correlation behavior."""
        return any(
            (
                self.within_seconds is not None,
                self.min_count is not None,
                bool(self.group_by),
                self.ordered,
                bool(self.sequence),
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain mapping."""
        return {
            "within_seconds": self.within_seconds,
            "min_count": self.min_count,
            "group_by": list(self.group_by),
            "ordered": self.ordered,
            "sequence": [c.to_dict() for c in self.sequence],
        }


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """Canonical detection rule contract.

    Attributes:
        rule_id: Stable, human-readable identity (e.g. ``TH-EXEC-001``).
        name: Short display name.
        description: Longer description of what the rule detects.
        version: Positive integer; changes to condition/severity/confidence
            bump the version. Independent of engine implementation.
        enabled: Whether the rule may generate detections. Disabled rules
            remain loadable and validatable.
        severity: Deterministic detection severity.
        confidence: Explicit confidence in ``[0.0, 1.0]``.
        tags: Free-form classification tags.
        tactic / technique / subtechnique: Optional MITRE ATT&CK metadata.
        references: Optional external references (URLs, advisories...).
        author: Optional owner/author of the rule.
        applicability: Source/event/protocol applicability declaration.
        condition: Root of the condition tree (a condition or a logical
            composition).
        temporal: Reserved stateful semantics for later phases.
        metadata: Optional extra key-value context.
    """

    rule_id: str
    name: str
    description: str = ""
    version: int = MIN_RULE_VERSION
    enabled: bool = True
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.7
    tags: tuple[str, ...] = ()
    tactic: str | None = None
    technique: str | None = None
    subtechnique: str | None = None
    references: tuple[str, ...] = ()
    author: str | None = None
    applicability: RuleApplicability = field(default_factory=RuleApplicability)
    conditions: LogicalExpression | Condition | None = None
    temporal: TemporalSpec | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate identity and contract guarantees."""
        if not isinstance(self.rule_id, str) or not self.rule_id.strip():
            raise ValidationError("Rule rule_id must be a non-empty string.")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValidationError("Rule name must be a non-empty string.")
        if (
            isinstance(self.version, bool)
            or not isinstance(self.version, int)
            or self.version < MIN_RULE_VERSION
        ):
            raise ValidationError(f"Rule version must be an integer >= {MIN_RULE_VERSION}.")
        if not isinstance(self.enabled, bool):
            raise ValidationError("Rule enabled must be a boolean.")
        if not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool):
            raise ValidationError(f"Rule confidence must be numeric, got {self.confidence!r}.")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValidationError(
                f"Rule confidence must be within [0.0, 1.0], got {self.confidence}."
            )
        if not isinstance(self.severity, Severity):
            raise ValidationError(f"Rule severity must be a Severity, got {self.severity!r}.")
        if self.conditions is not None and not isinstance(
            self.conditions, (Condition, LogicalExpression)
        ):
            raise ValidationError(
                "Rule conditions must be a Condition, a LogicalExpression, or None; "
                f"got {type(self.conditions).__name__}."
            )

    @property
    def is_enabled(self) -> bool:
        """Mirror the enable/disable semantics for readable call sites."""
        return self.enabled

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain YAML/JSON-friendly mapping."""
        conditions = None
        if isinstance(self.conditions, (Condition, LogicalExpression)):
            conditions = self.conditions.to_dict()
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "enabled": self.enabled,
            "severity": self.severity.name,
            "confidence": float(self.confidence),
            "tags": list(self.tags),
            "tactic": self.tactic,
            "technique": self.technique,
            "subtechnique": self.subtechnique,
            "references": list(self.references),
            "author": self.author,
            "applicability": self.applicability.to_dict(),
            "conditions": conditions,
            "temporal": self.temporal.to_dict() if self.temporal else None,
            "metadata": dict(self.metadata),
        }


def validate_rule(rule: DetectionRule) -> list[str]:
    """Return a list of contract violations for *rule*.

    Deterministic and side-effect free.  The dataclass ``__post_init__``
    already raises for hard failures; this function additionally reports
    recoverable soft issues (e.g. conditional fields) as a list.

    Args:
        rule: Rule to validate.

    Returns:
        List of human-readable violation strings.  Empty when valid.
    """
    errors: list[str] = []
    if not isinstance(rule, DetectionRule):
        return ["Rule must be a DetectionRule instance."]
    if not rule.rule_id or not rule.rule_id.strip():
        errors.append("rule_id is required.")
    if not rule.name or not rule.name.strip():
        errors.append("name is required.")
    if rule.version < MIN_RULE_VERSION:
        errors.append(f"version must be >= {MIN_RULE_VERSION}.")
    if not 0.0 <= float(rule.confidence) <= 1.0:
        errors.append("confidence must be within [0.0, 1.0].")
    if rule.conditions is None:
        errors.append("conditions are required (or must be declared reserved).")
    return errors


__all__: Final[list[str]] = [
    "RULE_ID_PREFIX",
    "DetectionRule",
    "RuleApplicability",
    "TemporalSpec",
    "validate_rule",
]
