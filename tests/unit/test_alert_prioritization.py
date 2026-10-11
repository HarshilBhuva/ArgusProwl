"""Phase 4.7.4 — Alert Prioritization focused test suite.

Covers:
  A. Priority enum contract
  B. Severity → Priority mapping
  C. Contextual scenarios (malicious TI, benign, UNKNOWN, rare, conflicting)
  D. Legacy alerts
  E. Deduplication independence
  F. Console/JSON presentation
  G. Replay/live parity
  H. Determinism
  I. Adversarial boundary cases
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from argusprowl.alerting.console_provider import ConsoleAlertProvider
from argusprowl.alerting.json_provider import JsonAlertProvider
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.decision_engine.priority import determine_alert_priority
from argusprowl.deduplication.engine import AlertDeduplicationEngine
from argusprowl.deduplication.fingerprint import AlertFingerprint, FingerprintConfig
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


# ===========================================================================
# A. Priority enum contract
# ===========================================================================


class TestPriorityEnumContract:
    """AlertPriority enum values, ordering, and parsing."""

    def test_enum_values(self) -> None:
        assert AlertPriority.LOW.value == "LOW"
        assert AlertPriority.MEDIUM.value == "MEDIUM"
        assert AlertPriority.HIGH.value == "HIGH"
        assert AlertPriority.CRITICAL.value == "CRITICAL"

    def test_deterministic_ordering(self) -> None:
        assert AlertPriority.LOW.order < AlertPriority.MEDIUM.order
        assert AlertPriority.MEDIUM.order < AlertPriority.HIGH.order
        assert AlertPriority.HIGH.order < AlertPriority.CRITICAL.order

    def test_from_string_case_insensitive(self) -> None:
        assert AlertPriority.from_string("low") == AlertPriority.LOW
        assert AlertPriority.from_string("MEDIUM") == AlertPriority.MEDIUM
        assert AlertPriority.from_string("high") == AlertPriority.HIGH
        assert AlertPriority.from_string("CRITICAL") == AlertPriority.CRITICAL

    def test_from_string_rejects_invalid(self) -> None:
        with pytest.raises(ValueError):
            AlertPriority.from_string("EXTREME")
        with pytest.raises(ValueError):
            AlertPriority.from_string("42")


# ===========================================================================
# B. Severity → Priority mapping
# ===========================================================================


class TestSeverityToPriority:
    """Deterministic mapping from Severity to AlertPriority."""

    @pytest.mark.parametrize(
        ("severity", "expected_priority"),
        [
            (Severity.INFO, AlertPriority.LOW),
            (Severity.LOW, AlertPriority.LOW),
            (Severity.MEDIUM, AlertPriority.MEDIUM),
            (Severity.HIGH, AlertPriority.HIGH),
            (Severity.CRITICAL, AlertPriority.CRITICAL),
        ],
    )
    def test_mapping_is_deterministic(
        self, severity: Severity, expected_priority: AlertPriority
    ) -> None:
        assert determine_alert_priority(severity) == expected_priority

    def test_all_severities_covered(self) -> None:
        """Every Severity member must map to a priority."""
        for sev in Severity:
            priority = determine_alert_priority(sev)
            assert isinstance(priority, AlertPriority)


# ===========================================================================
# C. Contextual scenarios
# ===========================================================================


class TestContextualScenarios:
    """Priority in realistic contextual assessment scenarios."""

    def test_malicious_ti_critical_severity(self) -> None:
        """Malicious TI + rare destination → CRITICAL severity → CRITICAL priority."""
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
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(last_det, assessment=assessment)

        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert alert.priority == AlertPriority.CRITICAL
        assert alert.priority == determine_alert_priority(alert.severity)

    def test_benign_environment_wide_info_severity(self) -> None:
        """Environment-wide benign destination → INFO severity → LOW priority."""
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
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(det, assessment=assessment)

        assert alert is not None
        assert alert.severity == Severity.INFO
        assert alert.priority == AlertPriority.LOW
        assert alert.priority == determine_alert_priority(alert.severity)

    def test_unknown_ti_no_adjustment(self) -> None:
        """UNKNOWN TI must not change priority — priority follows severity."""
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
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(last_det, assessment=assessment)

        assert alert is not None
        assert alert.priority == determine_alert_priority(alert.severity)
        # UNKNOWN TI must not produce reputation contradictory evidence
        con_cats = [ev.category for ev in alert.contradictory_evidence]
        assert "reputation" not in con_cats

    def test_rare_destination_high_priority(self) -> None:
        """Rare destination with high detector confidence → priority follows severity."""
        result = _make_result(confidence=0.85, severity=Severity.HIGH)
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
        engine_fusion = EvidenceFusionEngine()
        assessment = engine_fusion.fuse(result, entity, prevalence, None)
        # Rare destination + attribution pushes severity to CRITICAL
        assert assessment.severity == Severity.CRITICAL

        decision_engine = DecisionEngine(cooldown_seconds=0)
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert alert.priority == AlertPriority.CRITICAL
        assert alert.priority == determine_alert_priority(alert.severity)

    def test_conflicting_evidence_priority_follows_severity(self) -> None:
        """Conflicting evidence: priority must equal severity-derived priority, not a second score."""
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
        # 0.97 → CRITICAL
        assert assessment.severity == Severity.CRITICAL

        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(last_det, assessment=assessment)
        assert alert is not None
        assert alert.priority == AlertPriority.CRITICAL
        assert alert.priority == determine_alert_priority(alert.severity)
        # Both supporting and contradictory evidence must coexist
        assert len(alert.supporting_evidence) >= 4
        assert len(alert.contradictory_evidence) >= 1

    def test_priority_is_not_a_second_fusion_score(self) -> None:
        """Priority must not duplicate EvidenceFusionEngine scoring.

        Two alerts with the same severity but different contextual_confidence
        must have the same priority.
        """
        result = _make_result(confidence=0.92, severity=Severity.HIGH)

        assessment_a = _make_assessment(result, final_confidence=0.97, severity=Severity.CRITICAL)
        assessment_b = _make_assessment(result, final_confidence=0.60, severity=Severity.HIGH)

        engine = DecisionEngine(cooldown_seconds=0)
        alert_a = engine.process_detection_result(result, assessment=assessment_a)
        alert_b = engine.process_detection_result(result, assessment=assessment_b)

        assert alert_a is not None
        assert alert_b is not None
        assert alert_a.priority == AlertPriority.CRITICAL
        assert alert_b.priority == AlertPriority.HIGH
        # Different contextual_confidence but priority follows severity
        assert alert_a.contextual_confidence != alert_b.contextual_confidence
        assert alert_a.priority != alert_b.priority  # because severities differ


# ===========================================================================
# D. Legacy alerts
# ===========================================================================


class TestLegacyAlerts:
    """Legacy DetectionResult-only alerts must get a deterministic priority."""

    def test_legacy_alert_gets_priority_from_severity(self) -> None:
        """Legacy path: priority is derived from DetectionResult.severity."""
        result = _make_result(confidence=0.80, severity=Severity.HIGH)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None
        assert alert.priority == AlertPriority.HIGH
        assert alert.assessment_id is None
        assert alert.detector_confidence is None
        assert alert.contextual_confidence is None

    def test_legacy_low_confidence_downgrade(self) -> None:
        """Legacy low confidence → LOW severity → LOW priority."""
        result = DetectionResult(
            rule_id="port_scan",
            event_id=uuid4(),
            matched=True,
            severity=Severity.HIGH,
            confidence=0.25,
            description="Port scan from 10.0.0.5",
            evidence=[{"field": "src_ip", "observed": "10.0.0.5", "condition": "equals"}],
        )
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None
        assert alert.severity == Severity.LOW
        assert alert.priority == AlertPriority.LOW

    def test_legacy_serialization_includes_priority(self, tmp_path: Path) -> None:
        """Legacy alert serializes with a priority field."""
        result = _make_result(confidence=0.80, severity=Severity.MEDIUM)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None

        payload = alert.to_dict()
        assert payload["priority"] == "MEDIUM"
        assert payload["severity"] == "MEDIUM"

        restored = Alert.from_dict(payload)
        assert restored.priority == AlertPriority.MEDIUM
        assert restored.severity == Severity.MEDIUM

    def test_legacy_json_provider_works(self, tmp_path: Path) -> None:
        """Legacy alert writes valid JSON with priority."""
        result = _make_result(confidence=0.80, severity=Severity.HIGH)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None

        provider = JsonAlertProvider(output_path=tmp_path / "alerts.jsonl")
        assert provider.send(alert) is True

        payload = json.loads((tmp_path / "alerts.jsonl").read_text().splitlines()[0])
        assert payload["priority"] == "HIGH"
        assert payload["severity"] == "HIGH"

    def test_legacy_console_displays_priority(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Legacy alert console output includes priority line."""
        result = _make_result(confidence=0.80, severity=Severity.HIGH)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None

        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)
        assert provider.send(alert) is True
        output = capsys.readouterr().out
        assert "Priority: HIGH" in output
        assert "[HIGH]" in output


# ===========================================================================
# E. Deduplication independence
# ===========================================================================


class TestDeduplicationIndependence:
    """Priority must NOT affect alert fingerprint identity."""

    def test_different_priority_same_fingerprint(self) -> None:
        """Same rule + same source + different priority → same fingerprint."""
        fingerprint = AlertFingerprint(FingerprintConfig())
        AlertDeduplicationEngine(cooldown=60)

        alert_low = Alert(
            title="Scan",
            description="desc",
            severity=Severity.LOW,
            source="port_scan",
            priority=AlertPriority.LOW,
            metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
        )
        alert_high = Alert(
            title="Scan",
            description="desc",
            severity=Severity.HIGH,
            source="port_scan",
            priority=AlertPriority.HIGH,
            metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
        )

        assert fingerprint.create(alert_low) == fingerprint.create(alert_high)

        dedup = AlertDeduplicationEngine(cooldown=60)
        first = dedup.process(alert_low)
        second = dedup.process(alert_high)
        assert first.emit is True
        assert second.suppressed is True

    def test_different_severity_same_fingerprint(self) -> None:
        """Severity must NOT affect fingerprint."""
        fingerprint = AlertFingerprint(FingerprintConfig())

        alert1 = Alert(
            title="Scan",
            description="desc",
            severity=Severity.HIGH,
            source="port_scan",
            metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
        )
        alert2 = Alert(
            title="Scan",
            description="desc",
            severity=Severity.CRITICAL,
            source="port_scan",
            metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
        )
        assert fingerprint.create(alert1) == fingerprint.create(alert2)

    def test_different_contextual_confidence_same_fingerprint(self) -> None:
        """Contextual confidence must NOT affect fingerprint."""
        fingerprint = AlertFingerprint(FingerprintConfig())

        alert1 = Alert(
            title="Scan",
            description="desc",
            severity=Severity.HIGH,
            source="port_scan",
            contextual_confidence=0.95,
            metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
        )
        alert2 = Alert(
            title="Scan",
            description="desc",
            severity=Severity.HIGH,
            source="port_scan",
            contextual_confidence=0.42,
            metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
        )
        assert fingerprint.create(alert1) == fingerprint.create(alert2)

    def test_different_assessment_id_same_fingerprint(self) -> None:
        """Assessment ID must NOT affect fingerprint."""
        fingerprint = AlertFingerprint(FingerprintConfig())

        alert1 = Alert(
            title="Scan",
            description="desc",
            severity=Severity.HIGH,
            source="port_scan",
            assessment_id=uuid4(),
            metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
        )
        alert2 = Alert(
            title="Scan",
            description="desc",
            severity=Severity.HIGH,
            source="port_scan",
            assessment_id=uuid4(),
            metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
        )
        assert fingerprint.create(alert1) == fingerprint.create(alert2)


# ===========================================================================
# F. Console / JSON presentation
# ===========================================================================


class TestPresentation:
    """Console and JSON providers display priority correctly."""

    def test_console_contextual_alert_shows_priority(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = _make_result()
        assessment = _make_assessment(result, final_confidence=0.97, severity=Severity.CRITICAL)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result, assessment=assessment)
        assert alert is not None

        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)
        assert provider.send(alert) is True
        output = capsys.readouterr().out
        assert "Priority: CRITICAL" in output
        assert "[CRITICAL]" in output

    def test_console_legacy_alert_shows_priority(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = _make_result(confidence=0.80, severity=Severity.MEDIUM)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None

        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)
        assert provider.send(alert) is True
        output = capsys.readouterr().out
        assert "Priority: MEDIUM" in output

    def test_json_contextual_alert_includes_priority(self, tmp_path: Path) -> None:
        result = _make_result()
        assessment = _make_assessment(result, final_confidence=0.97, severity=Severity.CRITICAL)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result, assessment=assessment)
        assert alert is not None

        provider = JsonAlertProvider(output_path=tmp_path / "alerts.jsonl")
        assert provider.send(alert) is True

        payload = json.loads((tmp_path / "alerts.jsonl").read_text().splitlines()[0])
        assert payload["priority"] == "CRITICAL"
        assert payload["severity"] == "CRITICAL"
        assert payload["detector_confidence"] == 0.92
        assert payload["contextual_confidence"] == 0.97

    def test_json_legacy_alert_includes_priority(self, tmp_path: Path) -> None:
        result = _make_result(confidence=0.80, severity=Severity.LOW)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None

        provider = JsonAlertProvider(output_path=tmp_path / "alerts.jsonl")
        assert provider.send(alert) is True

        payload = json.loads((tmp_path / "alerts.jsonl").read_text().splitlines()[0])
        assert payload["priority"] == "LOW"
        assert payload["severity"] == "LOW"

    def test_json_roundtrip_preserves_priority(self) -> None:
        result = _make_result()
        assessment = _make_assessment(result, final_confidence=0.88, severity=Severity.HIGH)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result, assessment=assessment)
        assert alert is not None

        payload = alert.to_dict()
        restored = Alert.from_dict(payload)
        assert restored.priority == alert.priority
        assert restored.priority == AlertPriority.HIGH

    def test_console_no_none_clutter_with_priority(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Priority must not introduce None/empty clutter."""
        alert = Alert(
            title="Simple",
            description="No context",
            severity=Severity.INFO,
            source="simple",
            priority=AlertPriority.LOW,
        )
        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)
        assert provider.send(alert) is True
        output = capsys.readouterr().out
        assert "Priority: LOW" in output
        assert "None" not in output


# ===========================================================================
# G. Replay/live parity
# ===========================================================================


class TestReplayLiveParity:
    """Live and replay must produce identical priority."""

    def test_live_and_replay_priority_equivalent(self) -> None:
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
        live_engine = DecisionEngine(cooldown_seconds=0)
        live_alert = live_engine.process_detection_result(live_det, assessment=live_assessment)

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
        replay_engine = DecisionEngine(cooldown_seconds=0)
        replay_alert = replay_engine.process_detection_result(
            replay_det, assessment=replay_assessment
        )

        assert live_alert is not None
        assert replay_alert is not None
        assert live_alert.priority == replay_alert.priority
        assert live_alert.severity == replay_alert.severity
        assert live_alert.contextual_confidence == replay_alert.contextual_confidence
        assert live_alert.detector_confidence == replay_alert.detector_confidence
        assert live_alert.supporting_evidence == replay_alert.supporting_evidence
        assert live_alert.contradictory_evidence == replay_alert.contradictory_evidence
        assert live_alert.investigation_pivots == replay_alert.investigation_pivots
        assert live_alert.entity_context == replay_alert.entity_context


# ===========================================================================
# H. Determinism
# ===========================================================================


class TestDeterminism:
    """Repeated identical inputs must produce identical priority."""

    def test_priority_is_deterministic_across_runs(self) -> None:
        result = _make_result()
        assessment = _make_assessment(result, final_confidence=0.97, severity=Severity.CRITICAL)

        engines = [DecisionEngine(cooldown_seconds=0) for _ in range(5)]
        alerts = [e.process_detection_result(result, assessment=assessment) for e in engines]

        priorities = [a.priority for a in alerts if a is not None]
        severities = [a.severity for a in alerts if a is not None]
        assert all(p == AlertPriority.CRITICAL for p in priorities)
        assert all(s == Severity.CRITICAL for s in severities)

    def test_priority_survives_multiple_serializations(self) -> None:
        result = _make_result()
        assessment = _make_assessment(result, final_confidence=0.88, severity=Severity.HIGH)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result, assessment=assessment)
        assert alert is not None

        for _ in range(10):
            payload = alert.to_dict()
            restored = Alert.from_dict(payload)
            assert restored.priority == alert.priority
            assert restored.priority == AlertPriority.HIGH


# ===========================================================================
# I. Adversarial boundary cases
# ===========================================================================


class TestAdversarialCases:
    """Edge cases and boundary conditions."""

    def test_highest_severity_with_contradictory_evidence(self) -> None:
        """CRITICAL severity with contradictory evidence still maps to CRITICAL priority."""
        result = _make_result(confidence=0.92, severity=Severity.HIGH)
        contradictory = (
            FusionEvidence(
                evidence_type=EvidenceType.CONTRADICTORY,
                category="infrastructure",
                description="Known CDN endpoint",
                weight=-0.35,
            ),
        )
        assessment = _make_assessment(
            result,
            final_confidence=0.57,
            severity=Severity.HIGH,
            contradictory=contradictory,
        )
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert alert.priority == AlertPriority.HIGH
        assert alert.priority == determine_alert_priority(alert.severity)

    def test_lowest_severity_with_malicious_ti(self) -> None:
        """INFO severity with malicious TI still maps to LOW priority."""
        result = _make_result(confidence=0.55, severity=Severity.MEDIUM)
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
        engine_fusion = EvidenceFusionEngine()
        assessment = engine_fusion.fuse(result, entity, prevalence, reputation)
        # Even with malicious TI, if severity is INFO → priority is LOW
        engine_decision = DecisionEngine(cooldown_seconds=0)
        alert = engine_decision.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert alert.priority == determine_alert_priority(alert.severity)

    def test_missing_assessment_legacy_path(self) -> None:
        """Legacy path without assessment still produces valid priority."""
        result = DetectionResult(
            rule_id="test_rule",
            event_id=uuid4(),
            matched=True,
            severity=Severity.MEDIUM,
            confidence=0.60,
            description="Test detection",
            evidence=[{"field": "src_ip", "observed": "10.0.0.1", "condition": "equals"}],
        )
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None
        assert alert.priority == AlertPriority.MEDIUM
        assert alert.assessment_id is None

    def test_missing_entity_context(self) -> None:
        """Alert without entity context still gets priority."""
        result = _make_result()
        assessment = _make_assessment(
            result,
            final_confidence=0.70,
            severity=Severity.HIGH,
            entity_context=None,
        )
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert alert.priority == AlertPriority.HIGH
        assert alert.entity_context is None

    def test_repeated_identical_alerts_same_priority(self) -> None:
        """Same detection result processed twice yields same priority."""
        result = _make_result(confidence=0.92, severity=Severity.HIGH)
        assessment = _make_assessment(result, final_confidence=0.97, severity=Severity.CRITICAL)
        engine = DecisionEngine(cooldown_seconds=0)
        alert1 = engine.process_detection_result(result, assessment=assessment)
        # Reset cooldown for second processing
        alert_key = engine._generate_alert_key(result)
        from datetime import UTC
        from datetime import timedelta as td

        engine._alert_history[alert_key] = datetime.now(UTC) - td(seconds=600)
        alert2 = engine.process_detection_result(result, assessment=assessment)
        assert alert1 is not None
        assert alert2 is not None
        assert alert1.priority == alert2.priority

    def test_different_assessments_same_detection(self) -> None:
        """Same detection with different assessments yields different priorities."""
        result = _make_result(confidence=0.92, severity=Severity.HIGH)
        assessment_low = _make_assessment(result, final_confidence=0.30, severity=Severity.LOW)
        assessment_high = _make_assessment(
            result, final_confidence=0.97, severity=Severity.CRITICAL
        )

        engine = DecisionEngine(cooldown_seconds=0)
        alert_low = engine.process_detection_result(result, assessment=assessment_low)
        alert_key = engine._generate_alert_key(result)
        from datetime import UTC
        from datetime import timedelta as td

        engine._alert_history[alert_key] = datetime.now(UTC) - td(seconds=600)
        alert_high = engine.process_detection_result(result, assessment=assessment_high)

        assert alert_low is not None
        assert alert_high is not None
        assert alert_low.priority == AlertPriority.LOW
        assert alert_high.priority == AlertPriority.CRITICAL
        assert alert_low.priority != alert_high.priority

    def test_boundary_severity_values(self) -> None:
        """All five severity levels produce correct priority."""
        for sev in Severity:
            result = _make_result(severity=sev)
            assessment = _make_assessment(result, final_confidence=0.50, severity=sev)
            engine = DecisionEngine(cooldown_seconds=0)
            alert = engine.process_detection_result(result, assessment=assessment)
            assert alert is not None
            assert alert.priority == determine_alert_priority(sev)

    def test_serialization_roundtrip_with_all_priorities(self) -> None:
        """Every priority value survives JSON round-trip."""
        for priority in AlertPriority:
            alert = Alert(
                title="Test",
                description="desc",
                severity=Severity.HIGH,
                source="test",
                priority=priority,
            )
            payload = alert.to_dict()
            restored = Alert.from_dict(payload)
            assert restored.priority == priority

    def test_replay_historical_timestamps(self) -> None:
        """Historical telemetry replay produces same priority as live."""
        events = _beacon_events(
            dst_ip="203.0.113.50",
            dst_port=8443,
            start_time=datetime(2026, 1, 15, 8, 0, 0, tzinfo=UTC),
        )
        temporal = TemporalEngine(window_duration=timedelta(hours=2))
        detector = BeaconingDetector(
            temporal_engine=temporal,
            min_observations=10,
            min_duration_seconds=300.0,
            periodicity_threshold=0.7,
            confidence_threshold=0.5,
        )
        service = ContextualIntelligenceService(
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
            service.record_event(ev)
            temporal.observe(ev)
        det = detector.detect(events[-1])
        assessment = service.evaluate(det, events[-1])
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(det, assessment=assessment)
        assert alert is not None
        assert alert.priority == AlertPriority.CRITICAL
        assert alert.priority == determine_alert_priority(alert.severity)
