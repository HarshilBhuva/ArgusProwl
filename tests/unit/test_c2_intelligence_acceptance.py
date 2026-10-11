"""End-to-end acceptance test suite for Phase 4.6D (C2 Intelligence Integration).

Proves the complete C2 / beaconing reasoning path:
telemetry -> normalization -> temporal/beaconing detection -> process/network context
-> environmental prevalence -> threat intelligence -> evidence fusion -> explainable ContextualAssessment.
"""

from datetime import UTC, datetime, timedelta

from argusprowl.constants.severity import Severity
from argusprowl.detection.detectors.beaconing_detector import BeaconingDetector
from argusprowl.intelligence.prevalence import EnvironmentPrevalenceTracker
from argusprowl.intelligence.service import ContextualIntelligenceService
from argusprowl.intelligence.threat_intel import (
    InMemoryThreatIntelProvider,
    ThreatIntelReputation,
    ThreatIntelVerdict,
)
from argusprowl.models.context import EvidenceType
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.temporal.engine import TemporalEngine


def _generate_beacon_events(
    src_ip: str = "192.168.1.105",
    hostname: str = "workstation-23",
    dst_ip: str = "203.0.113.50",
    dst_port: int = 8443,
    process_name: str = "powershell.exe",
    pid: int = 4820,
    username: str = "ACME\\jdoe",
    count: int = 24,
    interval_seconds: float = 60.0,
    start_time: datetime | None = None,
) -> list[NormalizedEvent]:
    """Generate a deterministic sequence of periodic network connection events."""
    if start_time is None:
        start_time = datetime(2026, 8, 31, 10, 0, 0, tzinfo=UTC)

    events: list[NormalizedEvent] = []
    for i in range(count):
        ts = start_time + timedelta(seconds=i * interval_seconds)
        events.append(
            NormalizedEvent(
                source_type="zeek",
                event_type="network_connection",
                timestamp=ts,
                src_ip=src_ip,
                src_port=49152 + i,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                hostname=hostname,
                process_name=process_name,
                pid=pid,
                username=username,
                attributes={
                    "uid": f"C_beacon_{i}",
                    "direction": "outbound",
                },
            )
        )
    return events


def test_scenario_a_suspicious_c2_beacon() -> None:
    """Scenario A: Suspicious C2 beaconing on non-standard port with rare destination and malicious TI."""
    temporal_engine = TemporalEngine(window_duration=timedelta(hours=2))
    detector = BeaconingDetector(
        temporal_engine=temporal_engine,
        min_observations=10,
        min_duration_seconds=300.0,
        periodicity_threshold=0.7,
        confidence_threshold=0.5,
    )

    ti_provider = InMemoryThreatIntelProvider(
        ip_reputations={
            "203.0.113.50": ThreatIntelReputation(
                indicator="203.0.113.50",
                verdict=ThreatIntelVerdict.MALICIOUS,
                confidence=1.0,
                categories=("c2", "botnet"),
                source="AcmeIntel",
            )
        }
    )
    prevalence_tracker = EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3)
    service = ContextualIntelligenceService(
        prevalence_tracker=prevalence_tracker,
        threat_intel_provider=ti_provider,
    )

    events = _generate_beacon_events(
        src_ip="192.168.1.105",
        hostname="workstation-23",
        dst_ip="203.0.113.50",
        dst_port=8443,
        process_name="powershell.exe",
        pid=4820,
        count=24,
        interval_seconds=60.0,
    )

    last_detection = None
    for event in events:
        service.record_event(event)
        temporal_engine.observe(event)
        det = detector.detect(event)
        if det.matched:
            last_detection = det

    assert last_detection is not None
    assert last_detection.matched is True
    assert last_detection.confidence >= 0.80

    # Ensure prevalence tracker has processed the events
    assert service.prevalence_tracker.total_observations >= 24

    # Manually trigger prevalence recording for the last event if needed
    service.record_event(events[-1])

    assessment = service.evaluate(last_detection, events[-1])

    # Assert ContextualAssessment invariants
    assert assessment.final_confidence == 1.0
    assert assessment.final_confidence > last_detection.confidence
    assert assessment.severity == Severity.CRITICAL
    assert assessment.entity_context is not None
    assert assessment.entity_context.host == "workstation-23"
    assert assessment.entity_context.process_name == "powershell.exe"
    assert assessment.entity_context.pid == 4820
    assert assessment.entity_context.dst_ip == "203.0.113.50"
    assert assessment.entity_context.dst_port == 8443

    # Assert Evidence items
    sup_categories = [ev.category for ev in assessment.supporting_evidence]
    assert "temporal" in sup_categories
    assert "attribution" in sup_categories
    assert "prevalence" in sup_categories
    assert "reputation" in sup_categories
    assert "execution_context" in sup_categories
    assert len(assessment.contradictory_evidence) == 0

    # Assert explanation and investigation pivots
    assert "TH-NET-BEACON-001" in assessment.explanation
    assert "powershell.exe" in assessment.explanation
    assert "MALICIOUS" in assessment.explanation
    assert 2 <= len(assessment.investigation_pivots) <= 5
    assert any("PID 4820" in pivot for pivot in assessment.investigation_pivots)

    # Assert original detection result unmutated
    assert last_detection.confidence < 1.0


def test_scenario_b_benign_periodic_traffic() -> None:
    """Scenario B: Benign periodic traffic to an environment-wide CDN with benign TI reputation."""
    temporal_engine = TemporalEngine(window_duration=timedelta(hours=2))
    detector = BeaconingDetector(
        temporal_engine=temporal_engine,
        min_observations=10,
        min_duration_seconds=300.0,
        periodicity_threshold=0.7,
        confidence_threshold=0.3,
    )

    ti_provider = InMemoryThreatIntelProvider(
        ip_reputations={
            "198.51.100.20": ThreatIntelReputation(
                indicator="198.51.100.20",
                verdict=ThreatIntelVerdict.BENIGN,
                confidence=1.0,
                categories=("cdn", "enterprise"),
                source="AcmeIntel",
            )
        }
    )
    prevalence_tracker = EnvironmentPrevalenceTracker(
        min_observations=10, environment_wide_threshold=50
    )
    service = ContextualIntelligenceService(
        prevalence_tracker=prevalence_tracker,
        threat_intel_provider=ti_provider,
    )

    # Simulate environment-wide observations from 60 distinct hosts
    start_ts = datetime(2026, 8, 31, 10, 0, 0, tzinfo=UTC)
    for host_idx in range(60):
        h_ip = f"192.168.1.{10 + host_idx}"
        for i in range(10):
            ev = NormalizedEvent(
                source_type="zeek",
                event_type="network_connection",
                timestamp=start_ts + timedelta(seconds=i * 60),
                src_ip=h_ip,
                dst_ip="198.51.100.20",
                dst_port=443,
                protocol="tcp",
                hostname=f"host-{host_idx}",
                process_name="svchost.exe",
                pid=1024,
                attributes={
                    "uid": f"C_env_{host_idx}_{i}",
                    "direction": "outbound",
                    "is_expected_system_process": True,
                },
            )
            service.record_event(ev)
            if host_idx == 0:
                temporal_engine.observe(ev)

    # Ensure prevalence tracker has processed the events
    assert service.prevalence_tracker.total_observations >= 600

    # Evaluate detection for host-0
    last_event = NormalizedEvent(
        source_type="zeek",
        event_type="network_connection",
        timestamp=start_ts + timedelta(seconds=600),
        src_ip="192.168.1.10",
        dst_ip="198.51.100.20",
        dst_port=443,
        protocol="tcp",
        hostname="host-0",
        process_name="svchost.exe",
        pid=1024,
        attributes={
            "uid": "C_env_0_last",
            "direction": "outbound",
            "is_expected_system_process": True,
        },
    )
    last_event.metadata["is_expected_system_process"] = True
    det = detector.detect(last_event)

    assert det.matched is True

    assessment = service.evaluate(det, last_event)

    # Suspicion must be materially reduced compared to Scenario A (0.0 vs 1.0)
    assert assessment.final_confidence < 0.30
    assert assessment.severity == Severity.INFO
    assert len(assessment.contradictory_evidence) >= 1

    # Check for either prevalence or infrastructure category
    con_categories = [ev.category for ev in assessment.contradictory_evidence]
    assert any(cat in con_categories for cat in ["prevalence", "infrastructure"])

    assert "Contradictory context includes" in assessment.explanation
    assert (
        "environment-wide" in assessment.explanation.lower()
        or "infrastructure" in assessment.explanation.lower()
    )


def test_scenario_c_unknown_intelligence() -> None:
    """Scenario C: Suspicious periodic beaconing to an indicator with UNKNOWN threat intelligence."""
    temporal_engine = TemporalEngine(window_duration=timedelta(hours=2))
    detector = BeaconingDetector(
        temporal_engine=temporal_engine,
        min_observations=10,
        min_duration_seconds=300.0,
        periodicity_threshold=0.7,
        confidence_threshold=0.5,
    )

    # Provider with empty indicator mappings (all lookups return UNKNOWN)
    ti_provider = InMemoryThreatIntelProvider()
    prevalence_tracker = EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3)
    service = ContextualIntelligenceService(
        prevalence_tracker=prevalence_tracker,
        threat_intel_provider=ti_provider,
    )

    events = _generate_beacon_events(
        src_ip="192.168.1.105",
        hostname="workstation-23",
        dst_ip="203.0.113.99",
        dst_port=8443,
        process_name="powershell.exe",
        pid=4820,
        count=24,
    )

    last_detection = None
    for event in events:
        service.record_event(event)
        temporal_engine.observe(event)
        det = detector.detect(event)
        if det.matched:
            last_detection = det

    assert last_detection is not None
    assert last_detection.matched is True

    assessment = service.evaluate(last_detection, events[-1])

    # Absence of TI must NOT change score from TI weight
    # Base (0.85) + Attribution (+0.10) + Rare (+0.15) + Suspicious Proc (+0.10) + TI (0.00) = 1.20 -> clamp(1.0)
    assert assessment.final_confidence == 1.0
    assert "No threat-intelligence verdict was available" in assessment.explanation

    # No TI evidence items added
    ti_ev = [e for e in assessment.supporting_evidence if e.category == "reputation"]
    assert len(ti_ev) == 0


def test_scenario_d_conflicting_evidence() -> None:
    """Scenario D: Strong beaconing + rare destination + BENIGN threat intelligence verdict."""
    temporal_engine = TemporalEngine(window_duration=timedelta(hours=2))
    detector = BeaconingDetector(
        temporal_engine=temporal_engine,
        min_observations=10,
        min_duration_seconds=300.0,
        periodicity_threshold=0.7,
        confidence_threshold=0.5,
    )

    ti_provider = InMemoryThreatIntelProvider(
        ip_reputations={
            "203.0.113.77": ThreatIntelReputation(
                indicator="203.0.113.77",
                verdict=ThreatIntelVerdict.BENIGN,
                confidence=1.0,
                categories=("internal_service",),
                source="AcmeIntel",
            )
        }
    )
    prevalence_tracker = EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3)
    service = ContextualIntelligenceService(
        prevalence_tracker=prevalence_tracker,
        threat_intel_provider=ti_provider,
    )

    events = _generate_beacon_events(
        src_ip="192.168.1.105",
        hostname="workstation-23",
        dst_ip="203.0.113.77",
        dst_port=8443,
        process_name="powershell.exe",
        pid=4820,
        count=24,
    )

    last_detection = None
    for event in events:
        service.record_event(event)
        temporal_engine.observe(event)
        det = detector.detect(event)
        if det.matched:
            last_detection = det

    assert last_detection is not None

    assessment = service.evaluate(last_detection, events[-1])

    # Base (0.92) + Attribution (+0.10) + Rare (+0.15) + Suspicious Proc (+0.10) - Benign TI (-0.30) = 0.97
    assert assessment.final_confidence == 0.97
    assert assessment.severity == Severity.CRITICAL

    # Both supporting and contradictory evidence coexist
    assert len(assessment.supporting_evidence) >= 4
    assert len(assessment.contradictory_evidence) >= 1

    # Evidence polarity verified
    for ev in assessment.supporting_evidence:
        assert ev.evidence_type == EvidenceType.SUPPORTING
    for ev in assessment.contradictory_evidence:
        assert ev.evidence_type == EvidenceType.CONTRADICTORY

    # Explanation contains both supporting and contradictory summaries
    assert "Supporting context includes" in assessment.explanation
    assert "Contradictory context includes" in assessment.explanation


def test_scenario_e_replay_context_parity() -> None:
    """Scenario E: Batch/replay processing yields semantically identical ContextualAssessment."""
    temporal_engine = TemporalEngine(window_duration=timedelta(hours=2))
    detector = BeaconingDetector(
        temporal_engine=temporal_engine,
        min_observations=10,
        min_duration_seconds=300.0,
        periodicity_threshold=0.7,
        confidence_threshold=0.5,
    )
    ti_provider = InMemoryThreatIntelProvider(
        ip_reputations={
            "203.0.113.50": ThreatIntelReputation(
                indicator="203.0.113.50",
                verdict=ThreatIntelVerdict.MALICIOUS,
                confidence=1.0,
                categories=("c2",),
            )
        }
    )
    service = ContextualIntelligenceService(
        prevalence_tracker=EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3),
        threat_intel_provider=ti_provider,
    )

    events = _generate_beacon_events(count=24)

    # Stream execution
    for ev in events:
        service.record_event(ev)
        temporal_engine.observe(ev)

    last_det = detector.detect(events[-1])
    assessment_stream = service.evaluate(last_det, events[-1])

    # Replay batch execution on fresh components
    replay_temporal = TemporalEngine(window_duration=timedelta(hours=2))
    replay_detector = BeaconingDetector(
        temporal_engine=replay_temporal,
        min_observations=10,
        min_duration_seconds=300.0,
        periodicity_threshold=0.7,
        confidence_threshold=0.5,
    )
    replay_service = ContextualIntelligenceService(
        prevalence_tracker=EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3),
        threat_intel_provider=ti_provider,
    )

    for ev in events:
        replay_service.record_event(ev)
        replay_temporal.observe(ev)

    replay_det = replay_detector.detect(events[-1])
    assessment_replay = replay_service.evaluate(replay_det, events[-1])

    # Semantic parity check
    assert last_det.confidence == replay_det.confidence
    assert assessment_stream.final_confidence == assessment_replay.final_confidence
    assert assessment_stream.severity == assessment_replay.severity
    assert len(assessment_stream.supporting_evidence) == len(assessment_replay.supporting_evidence)
    assert len(assessment_stream.contradictory_evidence) == len(
        assessment_replay.contradictory_evidence
    )
    assert assessment_stream.explanation == assessment_replay.explanation
    assert assessment_stream.investigation_pivots == assessment_replay.investigation_pivots
