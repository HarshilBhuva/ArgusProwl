"""Unit tests for EvidenceFusionEngine (Phase 4.6C).

Tests deterministic scoring, evidence polarity, severity mapping, explanation generation,
investigation pivots, input immutability, and boundary handling.
"""

from uuid import uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.intelligence.fusion import EvidenceFusionEngine
from argusprowl.models.context import (
    EntityContext,
    EvidenceType,
    PrevalenceResult,
    ThreatIntelReputation,
    ThreatIntelVerdict,
)
from argusprowl.models.detection_result import DetectionResult


@pytest.fixture
def base_detection() -> DetectionResult:
    """Create a default matching DetectionResult."""
    return DetectionResult(
        rule_id="DET-NET-004-BEACONING",
        event_id=uuid4(),
        matched=True,
        confidence=0.85,
        severity=Severity.HIGH,
        description="Beaconing pattern detected.",
    )


@pytest.fixture
def fusion_engine() -> EvidenceFusionEngine:
    """Create default EvidenceFusionEngine."""
    return EvidenceFusionEngine()


def test_base_confidence_preserved(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Base detector confidence is preserved when no contextual adjustments apply."""
    assessment = fusion_engine.fuse(detection_result=base_detection)
    assert assessment.final_confidence == 0.85
    assert assessment.severity == Severity.CRITICAL
    assert len(assessment.supporting_evidence) == 1
    assert assessment.supporting_evidence[0].category == "temporal"
    assert assessment.supporting_evidence[0].weight == 0.0
    assert len(assessment.contradictory_evidence) == 0


def test_rare_destination_supporting(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Rare destination adds supporting evidence with configured weight."""
    prevalence = PrevalenceResult(dest_host_count=1, process_dest_count=1, is_rare_destination=True)
    assessment = fusion_engine.fuse(detection_result=base_detection, prevalence=prevalence)

    assert assessment.final_confidence == 1.0  # clamp(0.85 + 0.15)
    rare_ev = [e for e in assessment.supporting_evidence if e.category == "prevalence"]
    assert len(rare_ev) == 1
    assert rare_ev[0].weight == 0.15
    assert rare_ev[0].evidence_type == EvidenceType.SUPPORTING


def test_environment_wide_destination_contradictory(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Environment-wide destination adds contradictory evidence and reduces score."""
    prevalence = PrevalenceResult(
        dest_host_count=120, process_dest_count=80, is_environment_wide=True
    )
    assessment = fusion_engine.fuse(detection_result=base_detection, prevalence=prevalence)

    assert assessment.final_confidence == 0.45  # 0.85 - 0.40
    assert assessment.severity == Severity.MEDIUM
    env_ev = [e for e in assessment.contradictory_evidence if e.category == "prevalence"]
    assert len(env_ev) == 1
    assert env_ev[0].weight == -0.40
    assert env_ev[0].evidence_type == EvidenceType.CONTRADICTORY


def test_malicious_ti_supporting(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """MALICIOUS TI verdict adds supporting evidence scaled by confidence."""
    ti = ThreatIntelReputation(
        indicator="203.0.113.50",
        verdict=ThreatIntelVerdict.MALICIOUS,
        confidence=0.80,
        categories=("c2", "botnet"),
        source="ThreatFeedA",
    )
    assessment = fusion_engine.fuse(detection_result=base_detection, reputation=ti)

    # 0.85 + (0.25 * 0.80) = 0.85 + 0.20 = 1.05 -> clamp(1.0)
    assert assessment.final_confidence == 1.0
    ti_ev = [e for e in assessment.supporting_evidence if e.category == "reputation"]
    assert len(ti_ev) == 1
    assert ti_ev[0].weight == 0.20
    assert "MALICIOUS" in ti_ev[0].description


def test_suspicious_ti_supporting(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """SUSPICIOUS TI verdict adds supporting evidence scaled by confidence."""
    ti = ThreatIntelReputation(
        indicator="203.0.113.50",
        verdict=ThreatIntelVerdict.SUSPICIOUS,
        confidence=1.0,
        categories=("scanner",),
    )
    assessment = fusion_engine.fuse(detection_result=base_detection, reputation=ti)

    assert assessment.final_confidence == 0.95  # 0.85 + 0.10
    ti_ev = [e for e in assessment.supporting_evidence if e.category == "reputation"]
    assert len(ti_ev) == 1
    assert ti_ev[0].weight == 0.10


def test_benign_ti_contradictory(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """BENIGN TI verdict adds contradictory evidence scaled by confidence."""
    ti = ThreatIntelReputation(
        indicator="203.0.113.50",
        verdict=ThreatIntelVerdict.BENIGN,
        confidence=1.0,
        categories=("cdn",),
    )
    assessment = fusion_engine.fuse(detection_result=base_detection, reputation=ti)

    # Note: categories contains "cdn" -> benign infrastructure category weight -0.35
    assert assessment.final_confidence == 0.50  # 0.85 - 0.35
    ti_ev = [e for e in assessment.contradictory_evidence if e.category == "infrastructure"]
    assert len(ti_ev) == 1
    assert ti_ev[0].weight == -0.35


def test_unknown_ti_no_adjustment(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """UNKNOWN TI verdict produces no score adjustment and states verdict unavailable."""
    ti = ThreatIntelReputation(
        indicator="203.0.113.50", verdict=ThreatIntelVerdict.UNKNOWN, confidence=0.0
    )
    assessment = fusion_engine.fuse(detection_result=base_detection, reputation=ti)

    assert assessment.final_confidence == 0.85
    assert "No threat-intelligence verdict was available" in assessment.explanation


def test_process_attribution(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Process identity in EntityContext adds process attribution evidence."""
    ctx = EntityContext(
        host="workstation-01",
        process_name="powershell.exe",
        pid=4820,
        src_ip="192.168.1.100",
        dst_ip="203.0.113.50",
    )
    assessment = fusion_engine.fuse(detection_result=base_detection, entity_context=ctx)

    # Base 0.85 + Attribution 0.10 + Suspicious process (script interpreter powershell.exe) 0.10 = 1.05 -> 1.0
    assert assessment.final_confidence == 1.0
    attr_ev = [e for e in assessment.supporting_evidence if e.category == "attribution"]
    assert len(attr_ev) == 1
    assert attr_ev[0].weight == 0.10
    assert "powershell.exe" in attr_ev[0].description


def test_expected_system_context(fusion_engine: EvidenceFusionEngine) -> None:
    """Expected system process adds contradictory execution context evidence."""
    det = DetectionResult(
        rule_id="DET-SYS-001",
        event_id=uuid4(),
        matched=True,
        confidence=0.50,
        metadata={"is_expected_system_process": True},
    )
    ctx = EntityContext(process_name="svchost.exe", pid=1024)
    assessment = fusion_engine.fuse(detection_result=det, entity_context=ctx)

    # 0.50 + 0.10 (attribution) - 0.10 (expected system) = 0.50
    exec_ev = [e for e in assessment.contradictory_evidence if e.category == "execution_context"]
    assert len(exec_ev) == 1
    assert exec_ev[0].weight == -0.10


def test_score_clamping_upper_and_lower(fusion_engine: EvidenceFusionEngine) -> None:
    """Scores above 1.0 clamp to 1.0 and below 0.0 clamp to 0.0."""
    high_det = DetectionResult(rule_id="DET-01", event_id=uuid4(), matched=True, confidence=0.90)
    prevalence_rare = PrevalenceResult(dest_host_count=1, is_rare_destination=True)
    ti_malicious = ThreatIntelReputation(
        indicator="203.0.113.1", verdict=ThreatIntelVerdict.MALICIOUS, confidence=1.0
    )
    ctx = EntityContext(process_name="powershell.exe", pid=123)

    high_assessment = fusion_engine.fuse(
        detection_result=high_det,
        entity_context=ctx,
        prevalence=prevalence_rare,
        reputation=ti_malicious,
    )
    assert high_assessment.final_confidence == 1.0

    low_det = DetectionResult(rule_id="DET-02", event_id=uuid4(), matched=True, confidence=0.20)
    prevalence_wide = PrevalenceResult(dest_host_count=200, is_environment_wide=True)
    ti_benign = ThreatIntelReputation(
        indicator="203.0.113.1", verdict=ThreatIntelVerdict.BENIGN, confidence=1.0
    )

    low_assessment = fusion_engine.fuse(
        detection_result=low_det, prevalence=prevalence_wide, reputation=ti_benign
    )
    # 0.20 - 0.40 - 0.30 = -0.50 -> 0.0
    assert low_assessment.final_confidence == 0.0
    assert low_assessment.severity == Severity.INFO


def test_severity_mapping_boundaries(fusion_engine: EvidenceFusionEngine) -> None:
    """Verify exact confidence boundary thresholds map to correct Severity enum values."""
    assert fusion_engine._map_confidence_to_severity(0.0) == Severity.INFO
    assert fusion_engine._map_confidence_to_severity(0.29) == Severity.INFO
    assert fusion_engine._map_confidence_to_severity(0.30) == Severity.LOW
    assert fusion_engine._map_confidence_to_severity(0.44) == Severity.LOW
    assert fusion_engine._map_confidence_to_severity(0.45) == Severity.MEDIUM
    assert fusion_engine._map_confidence_to_severity(0.59) == Severity.MEDIUM
    assert fusion_engine._map_confidence_to_severity(0.60) == Severity.HIGH
    assert fusion_engine._map_confidence_to_severity(0.84) == Severity.HIGH
    assert fusion_engine._map_confidence_to_severity(0.85) == Severity.CRITICAL
    assert fusion_engine._map_confidence_to_severity(1.0) == Severity.CRITICAL


def test_evidence_polarity_guarantee(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Supporting evidence contains ONLY SUPPORTING items; contradictory contains ONLY CONTRADICTORY."""
    prevalence = PrevalenceResult(dest_host_count=100, is_environment_wide=True)
    ctx = EntityContext(process_name="powershell.exe", pid=100)
    ti = ThreatIntelReputation(
        indicator="203.0.113.1", verdict=ThreatIntelVerdict.MALICIOUS, confidence=1.0
    )

    assessment = fusion_engine.fuse(
        detection_result=base_detection, entity_context=ctx, prevalence=prevalence, reputation=ti
    )

    for ev in assessment.supporting_evidence:
        assert ev.evidence_type == EvidenceType.SUPPORTING
    for ev in assessment.contradictory_evidence:
        assert ev.evidence_type == EvidenceType.CONTRADICTORY


def test_evidence_ordering_deterministic(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Evidence tuples maintain identical category and description ordering across multiple executions."""
    ctx = EntityContext(process_name="powershell.exe", pid=100)
    prevalence = PrevalenceResult(dest_host_count=1, is_rare_destination=True)
    ti = ThreatIntelReputation(
        indicator="203.0.113.1", verdict=ThreatIntelVerdict.MALICIOUS, confidence=0.8
    )

    assessment1 = fusion_engine.fuse(
        detection_result=base_detection, entity_context=ctx, prevalence=prevalence, reputation=ti
    )
    assessment2 = fusion_engine.fuse(
        detection_result=base_detection, entity_context=ctx, prevalence=prevalence, reputation=ti
    )

    categories1 = [e.category for e in assessment1.supporting_evidence]
    categories2 = [e.category for e in assessment2.supporting_evidence]
    assert categories1 == categories2


def test_explanation_generation(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Explanation narrative is derived from actual evidence present."""
    ctx = EntityContext(
        host="srv-01", process_name="powershell.exe", pid=400, dst_ip="203.0.113.50"
    )
    prevalence = PrevalenceResult(dest_host_count=1, is_rare_destination=True)

    assessment = fusion_engine.fuse(
        detection_result=base_detection, entity_context=ctx, prevalence=prevalence
    )

    assert "DET-NET-004-BEACONING" in assessment.explanation
    assert "host='srv-01'" in assessment.explanation
    assert "powershell.exe" in assessment.explanation
    assert "Destination was observed on only 1 host(s)" in assessment.explanation
    assert "No threat-intelligence verdict was available" in assessment.explanation


def test_investigation_pivots(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Actionable investigation pivots are generated and bounded between 2 and 5 items."""
    ctx = EntityContext(
        host="srv-01",
        process_name="powershell.exe",
        pid=400,
        dst_ip="203.0.113.50",
        domain="malicious.example",
    )
    prevalence = PrevalenceResult(dest_host_count=1, is_rare_destination=True)

    assessment = fusion_engine.fuse(
        detection_result=base_detection, entity_context=ctx, prevalence=prevalence
    )

    assert 2 <= len(assessment.investigation_pivots) <= 5
    assert any("PID 400" in p for p in assessment.investigation_pivots)
    assert any("malicious.example" in p for p in assessment.investigation_pivots)


def test_conflicting_evidence_coexistence(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Supporting and contradictory evidence coexist when both signals are present."""
    prevalence = PrevalenceResult(dest_host_count=1, is_rare_destination=True)
    ti = ThreatIntelReputation(
        indicator="203.0.113.5", verdict=ThreatIntelVerdict.BENIGN, confidence=1.0
    )

    assessment = fusion_engine.fuse(
        detection_result=base_detection, prevalence=prevalence, reputation=ti
    )

    assert len(assessment.supporting_evidence) >= 2  # detector + rare
    assert len(assessment.contradictory_evidence) >= 1  # benign ti
    # 0.85 + 0.15 - 0.30 = 0.70 (HIGH)
    assert assessment.final_confidence == 0.70
    assert assessment.severity == Severity.HIGH


def test_input_immutability(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Inputs to fuse() are not mutated."""
    orig_confidence = base_detection.confidence
    ctx = EntityContext(host="host-1", process_name="cmd.exe", pid=10)
    prevalence = PrevalenceResult(dest_host_count=2, is_rare_destination=True)
    ti = ThreatIntelReputation(indicator="10.0.0.1", verdict=ThreatIntelVerdict.UNKNOWN)

    fusion_engine.fuse(
        detection_result=base_detection, entity_context=ctx, prevalence=prevalence, reputation=ti
    )

    assert base_detection.confidence == orig_confidence
    assert ctx.host == "host-1"
    assert prevalence.dest_host_count == 2
    assert ti.verdict == ThreatIntelVerdict.UNKNOWN


def test_non_matched_detection_result(fusion_engine: EvidenceFusionEngine) -> None:
    """Unmatched DetectionResult (matched=False) produces 0.0 confidence and INFO severity."""
    unmatched_det = DetectionResult(
        rule_id="DET-001",
        event_id=uuid4(),
        matched=False,
        confidence=0.0,
    )
    assessment = fusion_engine.fuse(detection_result=unmatched_det)

    assert assessment.final_confidence == 0.0
    assert assessment.severity == Severity.INFO
    assert len(assessment.supporting_evidence) == 0
    assert len(assessment.contradictory_evidence) == 0
    assert "did not match" in assessment.explanation
    assert len(assessment.investigation_pivots) == 0


def test_benign_scenario_reduces_suspicion(
    base_detection: DetectionResult, fusion_engine: EvidenceFusionEngine
) -> None:
    """Strong base beaconing confidence is reduced to INFORMATIONAL when strong contradictory evidence is present."""
    prevalence = PrevalenceResult(dest_host_count=150, is_environment_wide=True)
    ti = ThreatIntelReputation(
        indicator="203.0.113.50", verdict=ThreatIntelVerdict.BENIGN, confidence=1.0
    )

    assessment = fusion_engine.fuse(
        detection_result=base_detection, prevalence=prevalence, reputation=ti
    )

    # 0.85 - 0.40 (env wide) - 0.30 (benign ti) = 0.15
    assert assessment.final_confidence == 0.15
    assert assessment.severity == Severity.INFO


def test_suspicious_scenario_increases_suspicion(fusion_engine: EvidenceFusionEngine) -> None:
    """Multiple supporting contextual signals increase overall confidence."""
    det = DetectionResult(rule_id="DET-BEACON", event_id=uuid4(), matched=True, confidence=0.70)
    ctx = EntityContext(
        host="pc-01", process_name="powershell.exe", pid=2000, dst_ip="203.0.113.99"
    )
    prevalence = PrevalenceResult(dest_host_count=1, is_rare_destination=True)
    ti = ThreatIntelReputation(
        indicator="203.0.113.99", verdict=ThreatIntelVerdict.MALICIOUS, confidence=1.0
    )

    assessment = fusion_engine.fuse(
        detection_result=det, entity_context=ctx, prevalence=prevalence, reputation=ti
    )

    # 0.70 + 0.10 (attribution) + 0.15 (rare) + 0.25 (malicious) + 0.10 (suspicious proc powershell) = 1.30 -> clamp(1.0)
    assert assessment.final_confidence == 1.0
    assert assessment.severity == Severity.CRITICAL
