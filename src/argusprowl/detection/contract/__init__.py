"""Phase 4.1 — Detection Rule Contract.

This package defines the semantic contract for a detection rule and its
result, independent of any serialization (YAML, Sigma, programmatic) and
independent of the eventual execution engine.

Contents:
    - ``operators``: the operator vocabulary + missing-field policy.
    - ``conditions``: the atomic condition model (field / operator / value).
    - ``logical``: AND / OR / NOT composition.
    - ``evidence``: EvidenceItem and Explanation.
    - ``rule``: DetectionRule, RuleApplicability, TemporalSpec.
    - ``factory``: construct rules from plain mappings (YAML-like).

The existing ``app.models.DetectionResult`` remains the single runtime
result model. It is extended in Phase 4.1 rather than duplicated here.
"""

from argusprowl.detection.contract.conditions import Condition, FieldReference
from argusprowl.detection.contract.evidence import EvidenceItem, Explanation
from argusprowl.detection.contract.logical import LogicalExpression, LogicOperator
from argusprowl.detection.contract.operators import (
    DEFAULT_MISSING_FIELD_POLICY,
    MissingFieldPolicy,
    Operator,
)
from argusprowl.detection.contract.rule import (
    DetectionRule,
    RuleApplicability,
    TemporalSpec,
    validate_rule,
)

__all__ = [
    "DEFAULT_MISSING_FIELD_POLICY",
    "Condition",
    "DetectionRule",
    "EvidenceItem",
    "Explanation",
    "FieldReference",
    "LogicOperator",
    "LogicalExpression",
    "MissingFieldPolicy",
    "Operator",
    "RuleApplicability",
    "TemporalSpec",
    "validate_rule",
]
