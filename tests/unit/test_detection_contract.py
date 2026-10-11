"""Focused unit tests for the Phase 4.1 detection contracts."""

from uuid import uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.detection.contract.conditions import Condition
from argusprowl.detection.contract.evidence import EvidenceItem, Explanation
from argusprowl.detection.contract.factory import rule_from_dict
from argusprowl.detection.contract.logical import LogicalExpression, LogicOperator
from argusprowl.detection.contract.operators import MissingFieldPolicy, Operator
from argusprowl.detection.contract.rule import (
    DetectionRule,
    RuleApplicability,
    TemporalSpec,
    validate_rule,
)
from argusprowl.exceptions.exceptions import ValidationError
from argusprowl.models.detection_result import DetectionResult


def _condition(field: str = "process_name") -> Condition:
    return Condition(field=field, operator=Operator.EQUALS, value="powershell.exe")


def test_valid_rule_construction() -> None:
    rule = DetectionRule(
        rule_id="TH-EXEC-001",
        name="Encoded PowerShell",
        description="Detects PowerShell with encoded commands.",
        version=2,
        severity=Severity.HIGH,
        confidence=0.92,
        conditions=_condition(),
    )

    assert rule.rule_id == "TH-EXEC-001"
    assert rule.version == 2
    assert validate_rule(rule) == []


@pytest.mark.parametrize("rule_id", ("", "   "))
def test_invalid_rule_id_is_rejected(rule_id: str) -> None:
    with pytest.raises(ValidationError, match="rule_id"):
        DetectionRule(rule_id=rule_id, name="Valid", conditions=_condition())


@pytest.mark.parametrize("name", ("", "   "))
def test_invalid_name_is_rejected(name: str) -> None:
    with pytest.raises(ValidationError, match="name"):
        DetectionRule(rule_id="TH-TEST-001", name=name, conditions=_condition())


def test_invalid_severity_is_rejected() -> None:
    with pytest.raises(ValidationError, match="severity"):
        DetectionRule(  # type: ignore[arg-type]
            rule_id="TH-TEST-001",
            name="Invalid severity",
            severity="HIGH",
            conditions=_condition(),
        )


@pytest.mark.parametrize("confidence", (-0.01, 1.01))
def test_invalid_confidence_is_rejected(confidence: float) -> None:
    with pytest.raises(ValidationError, match="confidence"):
        DetectionRule(
            rule_id="TH-TEST-001",
            name="Invalid confidence",
            confidence=confidence,
            conditions=_condition(),
        )


def test_invalid_operator_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported condition operator"):
        Condition(field="process_name", operator="approximately", value="powershell.exe")


def test_missing_field_policy_is_explicit_and_exists_ignores_value() -> None:
    condition = Condition(
        field='attributes["QueryName"]',
        operator=Operator.CONTAINS,
        value="example.com",
    )
    exists = Condition(field="command_line", operator=Operator.EXISTS, value=True)

    assert condition.missing_field_policy is MissingFieldPolicy.FAIL_CLOSED
    assert exists.value is None
    assert exists.missing_field_policy is MissingFieldPolicy.FAIL_CLOSED


def test_and_composition_is_representable() -> None:
    expression = LogicalExpression(
        operator=LogicOperator.AND,
        children=(
            LogicalExpression(condition=_condition()),
            LogicalExpression(condition=Condition("command_line", Operator.CONTAINS, "-enc")),
        ),
    )

    assert expression.to_dict()["operator"] == "and"
    assert len(expression.children) == 2


def test_or_composition_is_representable() -> None:
    expression = LogicalExpression(
        operator=LogicOperator.OR,
        children=(
            LogicalExpression(condition=_condition("process_name")),
            LogicalExpression(condition=_condition("command_line")),
        ),
    )

    assert expression.to_dict()["operator"] == "or"


def test_not_composition_requires_one_child() -> None:
    child = LogicalExpression(condition=_condition())
    expression = LogicalExpression(operator=LogicOperator.NOT, children=(child,))

    assert expression.to_dict()["operator"] == "not"
    with pytest.raises(ValueError, match="exactly one child"):
        LogicalExpression(operator=LogicOperator.NOT, children=())


def test_disabled_rule_remains_valid_but_is_not_enabled() -> None:
    rule = DetectionRule(
        rule_id="TH-TEST-001", name="Disabled", enabled=False, conditions=_condition()
    )

    assert rule.enabled is False
    assert rule.is_enabled is False
    assert validate_rule(rule) == []


def test_rule_metadata_and_temporal_intent_are_preserved() -> None:
    rule = DetectionRule(
        rule_id="TH-NET-C2-001",
        name="Outbound C2",
        version=3,
        severity=Severity.HIGH,
        confidence=0.85,
        tags=("c2", "outbound"),
        tactic="Command and Control",
        technique="T1071",
        subtechnique="T1071.001",
        references=("https://attack.mitre.org/techniques/T1071/001/",),
        author="argusprowl Team",
        applicability=RuleApplicability(
            source_types=("zeek",),
            event_types=("network_connection",),
            protocols=("tcp",),
        ),
        conditions=_condition("dst_port"),
        temporal=TemporalSpec(within_seconds=60, min_count=5, group_by=("src_ip",)),
    )

    serialized = rule.to_dict()
    assert serialized["version"] == 3
    assert serialized["tags"] == ["c2", "outbound"]
    assert serialized["applicability"]["event_types"] == ["network_connection"]
    assert serialized["temporal"]["within_seconds"] == 60
    assert rule.temporal is not None and rule.temporal.is_stateful


def test_evidence_structure_and_explanation_are_serializable() -> None:
    event_id = uuid4()
    evidence = EvidenceItem(
        field="process_name",
        observed="powershell.exe",
        condition="equals powershell.exe",
        event_id=event_id,
        value="powershell.exe",
    )
    explanation = Explanation(
        summary="PowerShell executed with encoded command.",
        reason="process_name and command_line conditions matched.",
        evidence=(evidence,),
        confidence=0.92,
        severity="HIGH",
    )

    serialized = explanation.to_dict()
    assert serialized["evidence"][0]["event_id"] == str(event_id)
    assert serialized["confidence"] == 0.92


def test_detection_result_serialization_round_trip() -> None:
    result = DetectionResult(
        rule_id="TH-EXEC-001",
        event_id=uuid4(),
        matched=True,
        severity=Severity.HIGH,
        confidence=0.92,
        description="Encoded PowerShell detected.",
        explanation="process_name matched powershell.exe.",
        evidence=[
            {
                "field": "process_name",
                "observed": "powershell.exe",
                "condition": "equals powershell.exe",
            }
        ],
        version=2,
    )

    restored = DetectionResult.from_dict(result.to_dict())
    assert restored.to_dict() == result.to_dict()


def test_rule_factory_round_trip_shape_and_invalid_structures() -> None:
    data = {
        "rule_id": "TH-EXEC-001",
        "name": "Encoded PowerShell",
        "severity": "HIGH",
        "confidence": 0.92,
        "conditions": {
            "and": [
                {"field": "process_name", "operator": "equals", "value": "powershell.exe"},
                {"field": "command_line", "operator": "contains", "value": "-enc"},
            ]
        },
    }

    rule = rule_from_dict(data)
    assert rule.to_dict()["conditions"]["operator"] == "and"

    with pytest.raises(ValidationError, match="Invalid severity"):
        rule_from_dict({**data, "severity": "DANGEROUS"})
    with pytest.raises(ValidationError, match="Invalid condition"):
        rule_from_dict({**data, "conditions": {"field": "x", "operator": "unknown"}})
