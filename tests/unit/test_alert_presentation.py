"""Phase 4.7.3 — Analyst Alert Presentation & Contract Cleanup.

Adversarial test matrix covering:
  A. Strong suspicious beacon
  B. Benign periodic traffic
  C. UNKNOWN intelligence
  D. Conflicting evidence
  E. Legacy alert (no contextual assessment)
  F. Fully populated contextual alert round-trip
  G. Empty optional fields
  H. Deterministic output ordering
  I. Replay/live contextual parity
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from argusprowl.alerting.console_provider import ConsoleAlertProvider
from argusprowl.alerting.json_provider import JsonAlertProvider
from argusprowl.constants.severity import Severity
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.detection.detectors.beaconing_detector import BeaconingDetector
from argusprowl.intelligence.fusion import EvidenceFusionEngine
from argusprowl.intelligence.prevalence import EnvironmentPrevalenceTracker
from argusprowl.intelligence.service import ContextualIntelligenceService
from argusprowl.intelligence.threat_intel import (
    InMemoryThreatIntelProvider,
    ThreatIntelReputation,
    ThreatIntelVerdict,
)
from argusprowl.models.alert import Alert
from argusprowl.models.context import (
    ContextualAssessment,
    EntityContext,
    EvidenceType,
    FusionEvidence,
    PrevalenceResult,
)
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.temporal.engine import TemporalEngine

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _beacon_events(
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
                attributes={"uid": f"C_beacon_{i}", "direction": "outbound"},
            )
        )
    return events


def _make_assessment(
    detection_result: DetectionResult,
    *,
    final_confidence: float = 0.92,
    severity: Severity = Severity.CRITICAL,
    entity_context: EntityContext | None = None,
    supporting: tuple[FusionEvidence, ...] = (),
    contradictory: tuple[FusionEvidence, ...] = (),
    explanation: str = "contextual assessment",
    pivots: tuple[str, ...] = ("Inspect destination", "Review process tree"),
) -> ContextualAssessment:
    return ContextualAssessment(
        detection_result=detection_result,
        final_confidence=final_confidence,
        severity=severity,
        entity_context=entity_context,
        supporting_evidence=supporting,
        contradictory_evidence=contradictory,
        explanation=explanation,
        investigation_pivots=pivots,
    )


def _make_result(
    *,
    rule_id: str = "TH-NET-BEACON-001",
    confidence: float = 0.92,
    severity: Severity = Severity.HIGH,
    dst_ip: str = "203.0.113.50",
    dst_port: int = 8443,
    process_name: str = "powershell.exe",
    pid: int = 4820,
    hostname: str = "workstation-23",
    src_ip: str = "192.168.1.105",
) -> DetectionResult:
    evidence: list[dict[str, object]] = [
        {"field": "destination", "observed": dst_ip, "condition": "equals"},
        {"field": "destination_port", "observed": dst_port, "condition": "equals"},
        {"field": "process_name", "observed": process_name, "condition": "equals"},
        {"field": "hostname", "observed": hostname, "condition": "equals"},
    ]
    if pid is not None:
        evidence.append({"field": "process_id", "observed": pid, "condition": "equals"})
    if src_ip:
        evidence.append({"field": "src_ip", "observed": src_ip, "condition": "equals"})
    return DetectionResult(
        rule_id=rule_id,
        event_id=uuid4(),
        matched=True,
        severity=severity,
        confidence=confidence,
        description=f"Beaconing to {dst_ip}:{dst_port}",
        evidence=evidence,
    )


# ===========================================================================
# A. Strong suspicious beacon
# ===========================================================================


class TestStrongSuspiciousBeacon:
    """High detector confidence + rare destination + malicious TI + process attribution."""

    def test_severity_is_critical(self) -> None:
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)
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

        last_det = None
        for ev in events:
            service.record_event(ev)
            temporal_engine.observe(ev)
            det = detector.detect(ev)
            if det.matched:
                last_det = det

        assert last_det is not None
        assessment = service.evaluate(last_det, events[-1])

        assert assessment.severity == Severity.CRITICAL
        assert assessment.final_confidence >= 1.0  # clamped

    def test_supporting_evidence_present(self) -> None:
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)
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
        prevalence_tracker = EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3)
        service = ContextualIntelligenceService(
            prevalence_tracker=prevalence_tracker,
            threat_intel_provider=ti_provider,
        )

        last_det = None
        for ev in events:
            service.record_event(ev)
            temporal_engine.observe(ev)
            det = detector.detect(ev)
            if det.matched:
                last_det = det

        assessment = service.evaluate(last_det, events[-1])
        sup_categories = [ev.category for ev in assessment.supporting_evidence]

        assert "temporal" in sup_categories
        assert "attribution" in sup_categories
        assert "prevalence" in sup_categories
        assert "reputation" in sup_categories
        assert "execution_context" in sup_categories

    def test_contextual_explanation_present(self) -> None:
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)
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
        prevalence_tracker = EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3)
        service = ContextualIntelligenceService(
            prevalence_tracker=prevalence_tracker,
            threat_intel_provider=ti_provider,
        )

        last_det = None
        for ev in events:
            service.record_event(ev)
            temporal_engine.observe(ev)
            det = detector.detect(ev)
            if det.matched:
                last_det = det

        assessment = service.evaluate(last_det, events[-1])
        assert "TH-NET-BEACON-001" in assessment.explanation
        assert "powershell.exe" in assessment.explanation
        assert "MALICIOUS" in assessment.explanation

    def test_investigation_pivots_present(self) -> None:
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)
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
        prevalence_tracker = EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3)
        service = ContextualIntelligenceService(
            prevalence_tracker=prevalence_tracker,
            threat_intel_provider=ti_provider,
        )

        last_det = None
        for ev in events:
            service.record_event(ev)
            temporal_engine.observe(ev)
            det = detector.detect(ev)
            if det.matched:
                last_det = det

        assessment = service.evaluate(last_det, events[-1])
        assert 2 <= len(assessment.investigation_pivots) <= 5
        assert any("PID 4820" in pivot for pivot in assessment.investigation_pivots)

    def test_alert_carries_all_fields(self) -> None:
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)
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
        prevalence_tracker = EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3)
        service = ContextualIntelligenceService(
            prevalence_tracker=prevalence_tracker,
            threat_intel_provider=ti_provider,
        )

        last_det = None
        for ev in events:
            service.record_event(ev)
            temporal_engine.observe(ev)
            det = detector.detect(ev)
            if det.matched:
                last_det = det

        assessment = service.evaluate(last_det, events[-1])
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(last_det, assessment=assessment)

        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert alert.detector_confidence is not None
        assert alert.contextual_confidence is not None
        assert alert.contextual_explanation != ""
        assert len(alert.supporting_evidence) >= 4
        assert len(alert.investigation_pivots) >= 2
        assert alert.entity_context is not None
        assert alert.entity_context.get("host") == "workstation-23"
        assert alert.entity_context.get("process_name") == "powershell.exe"
        assert alert.entity_context.get("pid") == 4820
        assert alert.entity_context.get("dst_ip") == "203.0.113.50"
        assert alert.entity_context.get("dst_port") == 8443


# ===========================================================================
# B. Benign periodic traffic
# ===========================================================================


class TestBenignPeriodicTraffic:
    """High detector confidence but environment-wide destination + benign TI."""

    def test_contextual_reasoning_is_contradictory(self) -> None:
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
        assert assessment.final_confidence < 0.30
        assert assessment.severity == Severity.INFO
        assert len(assessment.contradictory_evidence) >= 1

        con_categories = [ev.category for ev in assessment.contradictory_evidence]
        assert any(cat in con_categories for cat in ["prevalence", "infrastructure"])
        assert "Contradictory context includes" in assessment.explanation

    def test_alert_reflects_benign_severity(self) -> None:
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

        assessment = service.evaluate(det, last_event)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(det, assessment=assessment)

        assert alert is not None
        assert alert.severity == Severity.INFO
        assert alert.contextual_confidence < 0.30
        assert len(alert.contradictory_evidence) >= 1


# ===========================================================================
# C. UNKNOWN intelligence
# ===========================================================================


class TestUnknownIntelligence:
    """UNKNOWN TI must NOT be treated as BENIGN."""

    def test_unknown_ti_does_not_adjust_score(self) -> None:
        events = _beacon_events(dst_ip="203.0.113.99", dst_port=8443)
        temporal_engine = TemporalEngine(window_duration=timedelta(hours=2))
        detector = BeaconingDetector(
            temporal_engine=temporal_engine,
            min_observations=10,
            min_duration_seconds=300.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.5,
        )
        ti_provider = InMemoryThreatIntelProvider()  # empty — all UNKNOWN
        prevalence_tracker = EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3)
        service = ContextualIntelligenceService(
            prevalence_tracker=prevalence_tracker,
            threat_intel_provider=ti_provider,
        )

        last_det = None
        for ev in events:
            service.record_event(ev)
            temporal_engine.observe(ev)
            det = detector.detect(ev)
            if det.matched:
                last_det = det

        assert last_det is not None
        assessment = service.evaluate(last_det, events[-1])

        # Absence of TI must NOT change score from non-TI weights
        # Base (0.92) + Attribution (+0.10) + Rare (+0.15) + Suspicious Proc (+0.10) = 1.27 -> clamp(1.0)
        assert assessment.final_confidence == 1.0
        assert "No threat-intelligence verdict was available" in assessment.explanation

        # No TI evidence items added
        ti_ev = [e for e in assessment.supporting_evidence if e.category == "reputation"]
        assert len(ti_ev) == 0

    def test_unknown_not_treated_as_benign(self) -> None:
        """UNKNOWN must not produce contradictory evidence."""
        events = _beacon_events(dst_ip="203.0.113.99", dst_port=8443)
        temporal_engine = TemporalEngine(window_duration=timedelta(hours=2))
        detector = BeaconingDetector(
            temporal_engine=temporal_engine,
            min_observations=10,
            min_duration_seconds=300.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.5,
        )
        ti_provider = InMemoryThreatIntelProvider()
        prevalence_tracker = EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3)
        service = ContextualIntelligenceService(
            prevalence_tracker=prevalence_tracker,
            threat_intel_provider=ti_provider,
        )

        last_det = None
        for ev in events:
            service.record_event(ev)
            temporal_engine.observe(ev)
            det = detector.detect(ev)
            if det.matched:
                last_det = det

        assessment = service.evaluate(last_det, events[-1])
        con_categories = [ev.category for ev in assessment.contradictory_evidence]
        assert "reputation" not in con_categories


# ===========================================================================
# D. Conflicting evidence
# ===========================================================================


class TestConflictingEvidence:
    """Strong beaconing + rare destination + BENIGN threat intelligence."""

    def test_both_evidence_lists_exist(self) -> None:
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

        events = _beacon_events(dst_ip="203.0.113.77", dst_port=8443)

        last_det = None
        for ev in events:
            service.record_event(ev)
            temporal_engine.observe(ev)
            det = detector.detect(ev)
            if det.matched:
                last_det = det

        assert last_det is not None
        assessment = service.evaluate(last_det, events[-1])

        assert len(assessment.supporting_evidence) >= 4
        assert len(assessment.contradictory_evidence) >= 1

        for ev in assessment.supporting_evidence:
            assert ev.evidence_type == EvidenceType.SUPPORTING
        for ev in assessment.contradictory_evidence:
            assert ev.evidence_type == EvidenceType.CONTRADICTORY

        assert "Supporting context includes" in assessment.explanation
        assert "Contradictory context includes" in assessment.explanation

    def test_confidence_reflects_conflict(self) -> None:
        """Base (0.92) + Attribution (+0.10) + Rare (+0.15) + Suspicious Proc (+0.10) - Benign TI (-0.30) = 0.97."""
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

        events = _beacon_events(dst_ip="203.0.113.77", dst_port=8443)

        last_det = None
        for ev in events:
            service.record_event(ev)
            temporal_engine.observe(ev)
            det = detector.detect(ev)
            if det.matched:
                last_det = det

        assessment = service.evaluate(last_det, events[-1])
        assert assessment.final_confidence == 0.97
        assert assessment.severity == Severity.CRITICAL


# ===========================================================================
# E. Legacy alert (no contextual assessment)
# ===========================================================================


class TestLegacyAlert:
    """Legacy DetectionResult-only alerts must still work."""

    def test_console_output_works(self, capsys: pytest.CaptureFixture[str]) -> None:
        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)
        alert = Alert(
            title="Port Scan Detected",
            description="Port scan from 10.0.0.5",
            severity=Severity.HIGH,
            source="port_scan",
            tags=("port_scan",),
            metadata={
                "confidence": 0.80,
                "evidence": [{"field": "src_ip", "observed": "10.0.0.5", "condition": "equals"}],
            },
        )
        assert provider.send(alert) is True
        output = capsys.readouterr().out
        assert "[HIGH]" in output
        assert "Port Scan Detected" in output
        assert "port_scan" in output

    def test_json_output_works(self, tmp_path: Path) -> None:
        provider = JsonAlertProvider(output_path=tmp_path / "alerts.jsonl")
        alert = Alert(
            title="Port Scan Detected",
            description="Port scan from 10.0.0.5",
            severity=Severity.HIGH,
            source="port_scan",
        )
        assert provider.send(alert) is True
        payload = json.loads((tmp_path / "alerts.jsonl").read_text().splitlines()[0])
        assert payload["title"] == "Port Scan Detected"
        assert payload["severity"] == "HIGH"
        assert payload["assessment_id"] is None
        assert payload["detector_confidence"] is None
        assert payload["contextual_confidence"] is None

    def test_decision_engine_legacy_path(self) -> None:
        result = _make_result(confidence=0.80, severity=Severity.HIGH)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None
        assert alert.assessment_id is None
        assert alert.detector_confidence is None
        assert alert.contextual_confidence is None
        assert alert.contextual_explanation == ""
        assert alert.supporting_evidence == ()
        assert alert.contradictory_evidence == ()
        assert alert.investigation_pivots == ()
        assert alert.entity_context is None


# ===========================================================================
# F. Fully populated contextual alert round-trip
# ===========================================================================


class TestContextualAlertRoundTrip:
    """ContextualAssessment → Alert → JSON → Alert semantic preservation."""

    def test_json_preserves_all_contextual_fields(self) -> None:
        result = _make_result()
        entity = EntityContext(
            host="workstation-23",
            process_name="powershell.exe",
            pid=4820,
            username="ACME\\jdoe",
            src_ip="192.168.1.105",
            dst_ip="203.0.113.50",
            dst_port=8443,
        )
        assessment = _make_assessment(
            result,
            final_confidence=0.97,
            severity=Severity.CRITICAL,
            entity_context=entity,
            supporting=(
                FusionEvidence(
                    evidence_type=EvidenceType.SUPPORTING,
                    category="temporal",
                    description="Base detector matched with confidence 0.92.",
                    weight=0.0,
                ),
                FusionEvidence(
                    evidence_type=EvidenceType.SUPPORTING,
                    category="prevalence",
                    description="Destination was observed on only 1 host(s) in local environment.",
                    weight=0.15,
                ),
                FusionEvidence(
                    evidence_type=EvidenceType.SUPPORTING,
                    category="reputation",
                    description="Threat intelligence classifies indicator '203.0.113.50' as MALICIOUS (confidence: 1.00).",
                    weight=0.25,
                ),
            ),
            contradictory=(),
            explanation="The activity was detected as rule 'TH-NET-BEACON-001' with base detector confidence 0.92.",
            pivots=("Inspect PID 4820", "Search environment for 203.0.113.50"),
        )
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result, assessment=assessment)
        assert alert is not None

        payload = alert.to_dict()
        assert payload["assessment_id"] is not None
        assert payload["detector_confidence"] == 0.92
        assert payload["contextual_confidence"] == 0.97
        assert payload["contextual_explanation"] == assessment.explanation
        assert len(payload["supporting_evidence"]) == 3
        assert len(payload["contradictory_evidence"]) == 0
        assert payload["investigation_pivots"] == list(assessment.investigation_pivots)
        assert payload["entity_context"] == entity.to_dict()
        assert payload["severity"] == "CRITICAL"

    def test_json_roundtrip_preserves_semantics(self) -> None:
        result = _make_result()
        entity = EntityContext(
            host="ws01",
            process_name="cmd.exe",
            pid=1234,
            src_ip="10.0.0.5",
            dst_ip="203.0.113.50",
            dst_port=8443,
        )
        assessment = _make_assessment(
            result,
            final_confidence=0.88,
            severity=Severity.HIGH,
            entity_context=entity,
            supporting=(
                FusionEvidence(
                    evidence_type=EvidenceType.SUPPORTING,
                    category="attribution",
                    description="Network activity was attributed to process 'cmd.exe' (PID 1234).",
                    weight=0.10,
                ),
            ),
            contradictory=(
                FusionEvidence(
                    evidence_type=EvidenceType.CONTRADICTORY,
                    category="reputation",
                    description="Threat intelligence classifies indicator '203.0.113.50' as BENIGN (confidence: 1.00).",
                    weight=-0.30,
                ),
            ),
            explanation="Test explanation",
            pivots=("Inspect command line", "Search environment"),
        )
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result, assessment=assessment)
        assert alert is not None

        payload = alert.to_dict()
        restored = Alert.from_dict(payload)

        assert restored.alert_id == alert.alert_id
        assert restored.title == alert.title
        assert restored.severity == alert.severity
        assert restored.detector_confidence == alert.detector_confidence
        assert restored.contextual_confidence == alert.contextual_confidence
        assert restored.contextual_explanation == alert.contextual_explanation
        assert restored.supporting_evidence == alert.supporting_evidence
        assert restored.contradictory_evidence == alert.contradictory_evidence
        assert restored.investigation_pivots == alert.investigation_pivots
        assert restored.entity_context == alert.entity_context


# ===========================================================================
# G. Empty optional fields
# ===========================================================================


class TestEmptyOptionalFields:
    """Output must not be cluttered with None / [] / 'None'."""

    def test_console_legacy_alert_has_no_clutter(self, capsys: pytest.CaptureFixture[str]) -> None:
        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)
        alert = Alert(
            title="Simple Alert",
            description="No context",
            severity=Severity.INFO,
            source="simple_rule",
        )
        assert provider.send(alert) is True
        output = capsys.readouterr().out
        assert "None" not in output
        assert "[]" not in output
        assert "Detector confidence" not in output
        assert "Contextual confidence" not in output
        assert "WHY:" not in output
        assert "SUPPORTING EVIDENCE:" not in output
        assert "CONTRADICTORY EVIDENCE:" not in output
        assert "INVESTIGATION PIVOTS:" not in output

    def test_json_legacy_alert_has_no_clutter(self, tmp_path: Path) -> None:
        provider = JsonAlertProvider(output_path=tmp_path / "alerts.jsonl")
        alert = Alert(
            title="Simple Alert",
            description="No context",
            severity=Severity.INFO,
            source="simple_rule",
        )
        assert provider.send(alert) is True
        payload = json.loads((tmp_path / "alerts.jsonl").read_text().splitlines()[0])
        assert payload["assessment_id"] is None
        assert payload["detector_confidence"] is None
        assert payload["contextual_confidence"] is None
        assert payload["contextual_explanation"] == ""
        assert payload["supporting_evidence"] == []
        assert payload["contradictory_evidence"] == []
        assert payload["investigation_pivots"] == []
        assert payload["entity_context"] is None


# ===========================================================================
# H. Deterministic output ordering
# ===========================================================================


class TestDeterministicOutput:
    """Same inputs must produce identical output every time."""

    def test_evidence_ordering_is_deterministic(self) -> None:
        """Evidence categories must always appear in the same order."""
        engine = EvidenceFusionEngine()
        result = _make_result()
        entity = EntityContext(
            host="ws01",
            process_name="powershell.exe",
            pid=1234,
            src_ip="10.0.0.5",
            dst_ip="203.0.113.50",
            dst_port=8443,
        )
        prevalence = PrevalenceResult(
            dest_host_count=1, process_dest_count=1, is_rare_destination=True
        )
        reputation = ThreatIntelReputation(
            indicator="203.0.113.50",
            verdict=ThreatIntelVerdict.MALICIOUS,
            confidence=1.0,
            categories=("c2",),
        )

        assessment1 = engine.fuse(result, entity, prevalence, reputation)
        assessment2 = engine.fuse(result, entity, prevalence, reputation)

        sup_cats1 = [ev.category for ev in assessment1.supporting_evidence]
        sup_cats2 = [ev.category for ev in assessment2.supporting_evidence]
        assert sup_cats1 == sup_cats2

        con_cats1 = [ev.category for ev in assessment1.contradictory_evidence]
        con_cats2 = [ev.category for ev in assessment2.contradictory_evidence]
        assert con_cats1 == con_cats2

    def test_explanation_is_deterministic(self) -> None:
        engine = EvidenceFusionEngine()
        result = _make_result()
        entity = EntityContext(
            host="ws01",
            process_name="powershell.exe",
            pid=1234,
            src_ip="10.0.0.5",
            dst_ip="203.0.113.50",
            dst_port=8443,
        )
        prevalence = PrevalenceResult(
            dest_host_count=1, process_dest_count=1, is_rare_destination=True
        )
        reputation = ThreatIntelReputation(
            indicator="203.0.113.50",
            verdict=ThreatIntelVerdict.MALICIOUS,
            confidence=1.0,
            categories=("c2",),
        )

        a1 = engine.fuse(result, entity, prevalence, reputation)
        a2 = engine.fuse(result, entity, prevalence, reputation)
        assert a1.explanation == a2.explanation
        assert a1.investigation_pivots == a2.investigation_pivots
        assert a1.final_confidence == a2.final_confidence

    def test_json_serialization_is_deterministic(self) -> None:
        engine = EvidenceFusionEngine()
        result = _make_result()
        entity = EntityContext(
            host="ws01",
            process_name="powershell.exe",
            pid=1234,
            src_ip="10.0.0.5",
            dst_ip="203.0.113.50",
            dst_port=8443,
        )
        prevalence = PrevalenceResult(
            dest_host_count=1, process_dest_count=1, is_rare_destination=True
        )
        reputation = ThreatIntelReputation(
            indicator="203.0.113.50",
            verdict=ThreatIntelVerdict.MALICIOUS,
            confidence=1.0,
            categories=("c2",),
        )

        a1 = engine.fuse(result, entity, prevalence, reputation)
        a2 = engine.fuse(result, entity, prevalence, reputation)

        d1 = a1.to_dict()
        d2 = a2.to_dict()
        # assessment_id and created_at will differ, so compare the rest
        d1.pop("assessment_id")
        d2.pop("assessment_id")
        d1.pop("created_at")
        d2.pop("created_at")
        assert d1 == d2


# ===========================================================================
# I. Replay/live contextual parity
# ===========================================================================


class TestReplayLiveParity:
    """Same telemetry through live and replay paths must yield equivalent reasoning."""

    def test_live_and_replay_produce_equivalent_assessment(self) -> None:
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)

        # Live path
        live_temporal = TemporalEngine(window_duration=timedelta(hours=2))
        live_detector = BeaconingDetector(
            temporal_engine=live_temporal,
            min_observations=10,
            min_duration_seconds=300.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.5,
        )
        live_service = ContextualIntelligenceService(
            prevalence_tracker=EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3),
            threat_intel_provider=InMemoryThreatIntelProvider(
                ip_reputations={
                    "203.0.113.50": ThreatIntelReputation(
                        indicator="203.0.113.50",
                        verdict=ThreatIntelVerdict.MALICIOUS,
                        confidence=1.0,
                        categories=("c2",),
                    )
                }
            ),
        )
        for ev in events:
            live_service.record_event(ev)
            live_temporal.observe(ev)
        live_det = live_detector.detect(events[-1])
        live_assessment = live_service.evaluate(live_det, events[-1])

        # Replay path (fresh components, same events)
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
            threat_intel_provider=InMemoryThreatIntelProvider(
                ip_reputations={
                    "203.0.113.50": ThreatIntelReputation(
                        indicator="203.0.113.50",
                        verdict=ThreatIntelVerdict.MALICIOUS,
                        confidence=1.0,
                        categories=("c2",),
                    )
                }
            ),
        )
        for ev in events:
            replay_service.record_event(ev)
            replay_temporal.observe(ev)
        replay_det = replay_detector.detect(events[-1])
        replay_assessment = replay_service.evaluate(replay_det, events[-1])

        # Semantic parity
        assert live_det.confidence == replay_det.confidence
        assert live_assessment.final_confidence == replay_assessment.final_confidence
        assert live_assessment.severity == replay_assessment.severity
        assert len(live_assessment.supporting_evidence) == len(
            replay_assessment.supporting_evidence
        )
        assert len(live_assessment.contradictory_evidence) == len(
            replay_assessment.contradictory_evidence
        )
        assert live_assessment.explanation == replay_assessment.explanation
        assert live_assessment.investigation_pivots == replay_assessment.investigation_pivots

    def test_alert_fields_are_equivalent_between_live_and_replay(self) -> None:
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)

        live_temporal = TemporalEngine(window_duration=timedelta(hours=2))
        live_detector = BeaconingDetector(
            temporal_engine=live_temporal,
            min_observations=10,
            min_duration_seconds=300.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.5,
        )
        live_service = ContextualIntelligenceService(
            prevalence_tracker=EnvironmentPrevalenceTracker(min_observations=10, rare_threshold=3),
            threat_intel_provider=InMemoryThreatIntelProvider(
                ip_reputations={
                    "203.0.113.50": ThreatIntelReputation(
                        indicator="203.0.113.50",
                        verdict=ThreatIntelVerdict.MALICIOUS,
                        confidence=1.0,
                        categories=("c2",),
                    )
                }
            ),
        )
        for ev in events:
            live_service.record_event(ev)
            live_temporal.observe(ev)
        live_det = live_detector.detect(events[-1])
        live_assessment = live_service.evaluate(live_det, events[-1])

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
            threat_intel_provider=InMemoryThreatIntelProvider(
                ip_reputations={
                    "203.0.113.50": ThreatIntelReputation(
                        indicator="203.0.113.50",
                        verdict=ThreatIntelVerdict.MALICIOUS,
                        confidence=1.0,
                        categories=("c2",),
                    )
                }
            ),
        )
        for ev in events:
            replay_service.record_event(ev)
            replay_temporal.observe(ev)
        replay_det = replay_detector.detect(events[-1])
        replay_assessment = replay_service.evaluate(replay_det, events[-1])

        engine = DecisionEngine(cooldown_seconds=0)
        live_alert = engine.process_detection_result(live_det, assessment=live_assessment)
        replay_alert = engine.process_detection_result(replay_det, assessment=replay_assessment)

        assert live_alert is not None
        assert replay_alert is not None
        assert live_alert.severity == replay_alert.severity
        assert live_alert.detector_confidence == replay_alert.detector_confidence
        assert live_alert.contextual_confidence == replay_alert.contextual_confidence
        assert live_alert.contextual_explanation == replay_alert.contextual_explanation
        assert live_alert.supporting_evidence == replay_alert.supporting_evidence
        assert live_alert.contradictory_evidence == replay_alert.contradictory_evidence
        assert live_alert.investigation_pivots == replay_alert.investigation_pivots
        assert live_alert.entity_context == replay_alert.entity_context
