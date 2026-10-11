"""Unit tests for Phase 4.6A Context & Intelligence data contracts.

Validates construction, boundary conditions, invalid input handling,
immutability, and dictionary serialization roundtrips.
"""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.models.context import (
    ContextualAssessment,
    EntityContext,
    EvidenceType,
    FusionEvidence,
    PrevalenceResult,
    ThreatIntelReputation,
    ThreatIntelVerdict,
)
from argusprowl.models.detection_result import DetectionResult

# --- ThreatIntelVerdict & EvidenceType Enums ---


def test_threat_intel_verdict_from_string():
    """Verify verdict parsing from case-insensitive strings."""
    assert ThreatIntelVerdict.from_string("malicious") == ThreatIntelVerdict.MALICIOUS
    assert ThreatIntelVerdict.from_string("BENIGN") == ThreatIntelVerdict.BENIGN
    with pytest.raises(ValueError, match="Unknown threat intel verdict"):
        ThreatIntelVerdict.from_string("INVALID_VERDICT")


def test_evidence_type_from_string():
    """Verify evidence type parsing from case-insensitive strings."""
    assert EvidenceType.from_string("supporting") == EvidenceType.SUPPORTING
    assert EvidenceType.from_string("CONTRADICTORY") == EvidenceType.CONTRADICTORY
    with pytest.raises(ValueError, match="Unknown evidence type"):
        EvidenceType.from_string("NEUTRAL")


# --- EntityContext ---


def test_entity_context_valid_construction():
    """Verify valid construction and defaults of EntityContext."""
    ctx = EntityContext(
        host="workstation-01",
        process_name="powershell.exe",
        pid=1234,
        username="domain\\user",
        src_ip="192.168.1.10",
        dst_ip="203.0.113.5",
        dst_port=443,
        domain="example.com",
    )
    assert ctx.host == "workstation-01"
    assert ctx.pid == 1234
    assert ctx.src_ip == "192.168.1.10"
    assert ctx.dst_port == 443


def test_entity_context_boundary_and_validation():
    """Verify boundary conditions for pid, ports, and IP addresses."""
    # Port boundaries
    EntityContext(dst_port=0)
    EntityContext(dst_port=65535)
    with pytest.raises(ValueError, match="dst_port must be between 0 and 65535"):
        EntityContext(dst_port=-1)
    with pytest.raises(ValueError, match="dst_port must be between 0 and 65535"):
        EntityContext(dst_port=65536)

    # PID boundaries
    EntityContext(pid=0)
    with pytest.raises(ValueError, match="pid must be a non-negative integer"):
        EntityContext(pid=-5)

    # IP address validation
    EntityContext(src_ip="10.0.0.1", dst_ip="2001:db8::1")
    with pytest.raises(ValueError, match="src_ip must be a valid IP address"):
        EntityContext(src_ip="999.999.999.999")
    with pytest.raises(ValueError, match="dst_ip must be a valid IP address"):
        EntityContext(dst_ip="invalid_host")


def test_entity_context_immutability():
    """Verify EntityContext is immutable."""
    ctx = EntityContext(host="server-01")
    with pytest.raises((FrozenInstanceError, AttributeError)):
        ctx.host = "server-02"  # type: ignore


def test_entity_context_serialization():
    """Verify EntityContext to_dict and from_dict roundtrip."""
    ctx = EntityContext(
        host="srv1",
        process_name="cmd.exe",
        pid=100,
        src_ip="10.0.0.5",
        dst_ip="1.1.1.1",
        dst_port=53,
    )
    serialized = ctx.to_dict()
    deserialized = EntityContext.from_dict(serialized)
    assert ctx == deserialized


# --- ThreatIntelReputation ---


def test_threat_intel_reputation_valid():
    """Verify valid construction of ThreatIntelReputation."""
    rep = ThreatIntelReputation(
        indicator="203.0.113.5",
        verdict=ThreatIntelVerdict.MALICIOUS,
        confidence=0.9,
        categories=("c2", "botnet"),
        source="local_cache",
    )
    assert rep.indicator == "203.0.113.5"
    assert rep.verdict == ThreatIntelVerdict.MALICIOUS
    assert rep.confidence == 0.9
    assert rep.categories == ("c2", "botnet")


def test_threat_intel_reputation_confidence_boundaries():
    """Verify confidence bounded to [0.0, 1.0]."""
    ThreatIntelReputation(indicator="1.1.1.1", confidence=0.0)
    ThreatIntelReputation(indicator="1.1.1.1", confidence=1.0)
    with pytest.raises(ValueError, match=r"confidence must be between 0\.0 and 1\.0"):
        ThreatIntelReputation(indicator="1.1.1.1", confidence=-0.1)
    with pytest.raises(ValueError, match=r"confidence must be between 0\.0 and 1\.0"):
        ThreatIntelReputation(indicator="1.1.1.1", confidence=1.05)


def test_threat_intel_reputation_validation():
    """Verify invalid indicator, verdict, and categories raise ValueError."""
    with pytest.raises(ValueError, match="indicator must be a non-empty string"):
        ThreatIntelReputation(indicator="   ")

    with pytest.raises(ValueError, match="verdict must be ThreatIntelVerdict"):
        ThreatIntelReputation(indicator="1.1.1.1", verdict="MALICIOUS")  # type: ignore

    with pytest.raises(ValueError, match="categories must contain non-empty strings"):
        ThreatIntelReputation(indicator="1.1.1.1", categories=("",))


def test_threat_intel_reputation_immutability():
    """Verify ThreatIntelReputation is immutable."""
    rep = ThreatIntelReputation(indicator="1.1.1.1")
    with pytest.raises((FrozenInstanceError, AttributeError)):
        rep.confidence = 0.5  # type: ignore


def test_threat_intel_reputation_serialization():
    """Verify serialization roundtrip for ThreatIntelReputation."""
    rep = ThreatIntelReputation(
        indicator="evil.com",
        verdict=ThreatIntelVerdict.SUSPICIOUS,
        confidence=0.75,
        categories=("phishing",),
        source="feed_a",
    )
    serialized = rep.to_dict()
    deserialized = ThreatIntelReputation.from_dict(serialized)
    assert rep == deserialized


# --- PrevalenceResult ---


def test_prevalence_result_valid_and_boundaries():
    """Verify PrevalenceResult metrics validation."""
    res = PrevalenceResult(
        dest_host_count=10,
        process_dest_count=2,
        is_rare_destination=False,
        is_environment_wide=True,
    )
    assert res.dest_host_count == 10
    assert res.is_environment_wide is True

    with pytest.raises(ValueError, match="dest_host_count must be a non-negative integer"):
        PrevalenceResult(dest_host_count=-1)

    with pytest.raises(ValueError, match="process_dest_count must be a non-negative integer"):
        PrevalenceResult(process_dest_count=-2)


def test_prevalence_result_immutability():
    """Verify PrevalenceResult is immutable."""
    res = PrevalenceResult(dest_host_count=1)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        res.dest_host_count = 5  # type: ignore


def test_prevalence_result_serialization():
    """Verify PrevalenceResult serialization roundtrip."""
    res = PrevalenceResult(
        dest_host_count=1,
        process_dest_count=1,
        is_rare_destination=True,
        is_environment_wide=False,
    )
    serialized = res.to_dict()
    deserialized = PrevalenceResult.from_dict(serialized)
    assert res == deserialized


# --- FusionEvidence ---


def test_fusion_evidence_valid_and_boundaries():
    """Verify FusionEvidence construction and weight bounds [-1.0, 1.0]."""
    ev_sup = FusionEvidence(
        evidence_type=EvidenceType.SUPPORTING,
        category="prevalence",
        description="Rare destination contacted",
        weight=0.15,
        metadata={"host_count": 1},
    )
    assert ev_sup.weight == 0.15

    # Weight boundaries
    FusionEvidence(
        evidence_type=EvidenceType.CONTRADICTORY,
        category="reputation",
        description="Known benign CDN",
        weight=-1.0,
    )
    FusionEvidence(
        evidence_type=EvidenceType.SUPPORTING,
        category="attribution",
        description="Unsigned binary",
        weight=1.0,
    )

    with pytest.raises(ValueError, match=r"weight must be between -1\.0 and 1\.0"):
        FusionEvidence(
            evidence_type=EvidenceType.SUPPORTING,
            category="test",
            description="desc",
            weight=1.5,
        )

    with pytest.raises(ValueError, match=r"weight must be between -1\.0 and 1\.0"):
        FusionEvidence(
            evidence_type=EvidenceType.CONTRADICTORY,
            category="test",
            description="desc",
            weight=-1.1,
        )


def test_fusion_evidence_validation():
    """Verify invalid category, description, and evidence_type raise ValueError."""
    with pytest.raises(ValueError, match="evidence_type must be EvidenceType"):
        FusionEvidence(
            evidence_type="SUPPORTING",  # type: ignore
            category="test",
            description="desc",
            weight=0.1,
        )

    with pytest.raises(ValueError, match="category must be a non-empty string"):
        FusionEvidence(
            evidence_type=EvidenceType.SUPPORTING,
            category="  ",
            description="desc",
            weight=0.1,
        )

    with pytest.raises(ValueError, match="description must be a non-empty string"):
        FusionEvidence(
            evidence_type=EvidenceType.SUPPORTING,
            category="test",
            description="",
            weight=0.1,
        )


def test_fusion_evidence_immutability():
    """Verify FusionEvidence is immutable."""
    ev = FusionEvidence(
        evidence_type=EvidenceType.SUPPORTING,
        category="test",
        description="desc",
        weight=0.1,
    )
    with pytest.raises((FrozenInstanceError, AttributeError)):
        ev.weight = 0.5  # type: ignore


def test_fusion_evidence_serialization():
    """Verify serialization roundtrip for FusionEvidence."""
    ev = FusionEvidence(
        evidence_type=EvidenceType.CONTRADICTORY,
        category="reputation",
        description="Known enterprise vendor domain",
        weight=-0.35,
        metadata={"domain": "microsoft.com"},
    )
    serialized = ev.to_dict()
    deserialized = FusionEvidence.from_dict(serialized)
    assert ev == deserialized


# --- ContextualAssessment ---


def test_contextual_assessment_valid_construction():
    """Verify valid construction of ContextualAssessment with nested elements."""
    det_res = DetectionResult(
        rule_id="beaconing_c2",
        event_id=uuid4(),
        matched=True,
        severity=Severity.HIGH,
        confidence=0.85,
        description="Beaconing detected",
    )
    entity_ctx = EntityContext(
        host="workstation-23",
        process_name="powershell.exe",
        pid=4820,
    )
    sup_ev = FusionEvidence(
        evidence_type=EvidenceType.SUPPORTING,
        category="prevalence",
        description="Rare destination",
        weight=0.15,
    )
    con_ev = FusionEvidence(
        evidence_type=EvidenceType.CONTRADICTORY,
        category="reputation",
        description="No negative threat intel",
        weight=-0.05,
    )

    assessment = ContextualAssessment(
        detection_result=det_res,
        final_confidence=0.90,
        severity=Severity.CRITICAL,
        entity_context=entity_ctx,
        supporting_evidence=(sup_ev,),
        contradictory_evidence=(con_ev,),
        explanation="Suspicious C2 beaconing with rare destination",
        investigation_pivots=("Inspect parent process", "Check DNS queries"),
    )

    assert assessment.final_confidence == 0.90
    assert assessment.severity == Severity.CRITICAL
    assert len(assessment.supporting_evidence) == 1
    assert len(assessment.contradictory_evidence) == 1
    assert assessment.investigation_pivots == ("Inspect parent process", "Check DNS queries")


def test_contextual_assessment_validation():
    """Verify boundary conditions and constraint validation in ContextualAssessment."""
    det_res = DetectionResult(
        rule_id="rule1",
        event_id=uuid4(),
        matched=True,
        confidence=0.5,
    )

    # final_confidence bounds
    with pytest.raises(ValueError, match=r"final_confidence must be between 0\.0 and 1\.0"):
        ContextualAssessment(detection_result=det_res, final_confidence=-0.1)

    with pytest.raises(ValueError, match=r"final_confidence must be between 0\.0 and 1\.0"):
        ContextualAssessment(detection_result=det_res, final_confidence=1.1)

    # Evidence type mismatch checks
    sup_ev = FusionEvidence(
        evidence_type=EvidenceType.SUPPORTING,
        category="cat",
        description="desc",
        weight=0.1,
    )
    con_ev = FusionEvidence(
        evidence_type=EvidenceType.CONTRADICTORY,
        category="cat",
        description="desc",
        weight=-0.1,
    )

    # Passing contradictory evidence in supporting tuple
    with pytest.raises(
        ValueError, match="supporting_evidence items must have evidence_type SUPPORTING"
    ):
        ContextualAssessment(
            detection_result=det_res,
            supporting_evidence=(con_ev,),
        )

    # Passing supporting evidence in contradictory tuple
    with pytest.raises(
        ValueError, match="contradictory_evidence items must have evidence_type CONTRADICTORY"
    ):
        ContextualAssessment(
            detection_result=det_res,
            contradictory_evidence=(sup_ev,),
        )


def test_contextual_assessment_immutability():
    """Verify ContextualAssessment is immutable."""
    det_res = DetectionResult(
        rule_id="rule1",
        event_id=uuid4(),
        matched=True,
    )
    assessment = ContextualAssessment(detection_result=det_res)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        assessment.final_confidence = 0.9  # type: ignore


def test_contextual_assessment_serialization_roundtrip():
    """Verify full dictionary serialization/deserialization of ContextualAssessment."""
    det_res = DetectionResult(
        rule_id="beaconing_c2",
        event_id=uuid4(),
        matched=True,
        severity=Severity.HIGH,
        confidence=0.85,
        description="Beaconing activity observed",
        explanation="24 periodic connections to remote IP",
    )
    entity_ctx = EntityContext(
        host="workstation-23",
        process_name="powershell.exe",
        pid=4820,
        dst_ip="203.0.113.50",
        dst_port=8443,
    )
    sup_ev = FusionEvidence(
        evidence_type=EvidenceType.SUPPORTING,
        category="prevalence",
        description="Rare destination in environment",
        weight=0.15,
    )
    con_ev = FusionEvidence(
        evidence_type=EvidenceType.CONTRADICTORY,
        category="reputation",
        description="Clean reputation in cache",
        weight=-0.1,
    )

    assessment = ContextualAssessment(
        detection_result=det_res,
        final_confidence=0.90,
        severity=Severity.CRITICAL,
        entity_context=entity_ctx,
        supporting_evidence=(sup_ev,),
        contradictory_evidence=(con_ev,),
        explanation="High severity assessment due to rare destination",
        investigation_pivots=("Decode base64 command line", "Check parent process PID 4820"),
        created_at=datetime.now(UTC),
    )

    serialized = assessment.to_dict()
    deserialized = ContextualAssessment.from_dict(serialized)

    assert deserialized.assessment_id == assessment.assessment_id
    assert deserialized.detection_result.rule_id == det_res.rule_id
    assert deserialized.final_confidence == 0.90
    assert deserialized.severity == Severity.CRITICAL
    assert deserialized.entity_context == entity_ctx
    assert deserialized.supporting_evidence == (sup_ev,)
    assert deserialized.contradictory_evidence == (con_ev,)
    assert deserialized.investigation_pivots == (
        "Decode base64 command line",
        "Check parent process PID 4820",
    )
    assert deserialized.created_at == assessment.created_at
