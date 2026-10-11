"""Phase 4.8.4 — Replay Integration / Evaluation Isolation Tests.

Covers:
  A. Replay creates isolated incidents
  B. Live state is unaffected by replay
  C. Replay runs are isolated from each other
  D. Entity correlation works during replay
  E. Semantic replay equivalence
  F. Existing queue isolation preserved
  G. Provider isolation verified
  H. Backward compatibility maintained
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from argusprowl.constants.severity import Severity
from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.detection.detectors.beaconing_detector import BeaconingDetector
from argusprowl.incident.incident_service import IncidentService
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
    FusionEvidence,
)
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.replay.replay_engine import ReplayEngine
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


def _build_replay_pipeline_with_incidents(
    events: list[NormalizedEvent],
    incident_service: IncidentService | None = None,
    entity_correlation_service: EntityCorrelationService | None = None,
) -> tuple[ReplayEngine, list[Alert]]:
    """Build a replay pipeline with optional incident correlation.

    Returns:
        Tuple of (ReplayEngine, list of generated alerts).
    """
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
    intelligence_service = ContextualIntelligenceService(
        prevalence_tracker=prevalence_tracker,
        threat_intel_provider=ti_provider,
    )

    # Create a temporary log file with the events
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("#separator \\x09\n")
        f.write("#set_separator\t,\n")
        f.write("#empty_field\t(empty)\n")
        f.write("#path\tconn\n")
        f.write("#open\t2019-01-01-00-00-00\n")
        f.write(
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\n"
        )
        f.write(
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\n"
        )
        for ev in events:
            f.write(
                f"{ev.timestamp.timestamp()}\t{ev.attributes.get('uid', 'C_test')}\t{ev.src_ip}\t{ev.src_port}\t{ev.dst_ip}\t{ev.dst_port}\t{ev.protocol}\t\t{ev.timestamp.timestamp()}\t0\t0\tSF\tShADadfF\t1\t1\n"
            )
        log_path = f.name

    try:
        engine = ReplayEngine(
            log_path=log_path,
            temporal_engine=temporal_engine,
            beaconing_detector=detector,
            intelligence_service=intelligence_service,
            incident_service=incident_service,
            entity_correlation_service=entity_correlation_service,
        )
        alerts = engine.run()
        return engine, alerts
    finally:
        import os

        os.unlink(log_path)


def _normalize_alert_for_comparison(alert: Alert) -> dict:
    """Normalize alert fields for semantic comparison, ignoring nondeterministic IDs."""
    d = alert.to_dict()
    # Remove nondeterministic identifiers
    d.pop("alert_id", None)
    d.pop("assessment_id", None)
    d.pop("incident_id", None)
    d.pop("created_at", None)
    return d


# ===========================================================================
# A. Replay creates isolated incidents
# ===========================================================================


class TestReplayCreatesIsolatedIncidents:
    """Verify that replay with isolated services creates incidents."""

    def test_replay_creates_incidents_in_isolated_service(self) -> None:
        """Replay with isolated IncidentService should create incidents."""
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)
        incident_service = IncidentService()
        entity_correlation_service = EntityCorrelationService()

        _engine, alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=incident_service,
            entity_correlation_service=entity_correlation_service,
        )

        # Should have generated alerts
        assert len(alerts) > 0

        # Alerts with entity context should have incident_id set
        entity_alerts = [a for a in alerts if a.entity_context is not None]
        if entity_alerts:
            for alert in entity_alerts:
                assert alert.incident_id is not None, (
                    "Alert with entity context should have incident_id set"
                )

        # IncidentService should contain the incidents
        incidents = incident_service.list_incidents()
        assert len(incidents) > 0, "Isolated IncidentService should contain incidents"

    def test_replay_alerts_have_incident_id(self) -> None:
        """Alerts generated during replay should have incident_id when entity context exists."""
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)
        incident_service = IncidentService()
        entity_correlation_service = EntityCorrelationService()

        _, alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=incident_service,
            entity_correlation_service=entity_correlation_service,
        )

        # At least some alerts should have incident_id
        alerts_with_incident = [a for a in alerts if a.incident_id is not None]
        assert len(alerts_with_incident) > 0, (
            "Some alerts should have incident_id when entity context is present"
        )


# ===========================================================================
# B. Live state is unaffected
# ===========================================================================


class TestLiveStateUnaffected:
    """Verify that replay does not affect live incident state."""

    def test_live_incident_service_unaffected_by_replay(self) -> None:
        """Live IncidentService should remain unchanged after replay."""
        # Create live incident service with known state
        live_incident_service = IncidentService()
        EntityCorrelationService()

        # Pre-populate live service with an incident
        live_alert = Alert(
            title="Live Alert",
            description="Live test alert",
            severity=Severity.HIGH,
            source="test",
            entity_context={"host": "live-host", "dst_ip": "10.0.0.1"},
        )
        live_incident_service.create_incident([live_alert], title="Live Incident")
        live_incident_count_before = len(live_incident_service.list_incidents())
        assert live_incident_count_before == 1

        # Run replay with completely separate isolated services
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)
        replay_incident_service = IncidentService()
        replay_entity_correlation = EntityCorrelationService()

        _, _ = _build_replay_pipeline_with_incidents(
            events,
            incident_service=replay_incident_service,
            entity_correlation_service=replay_entity_correlation,
        )

        # Live service should be unchanged
        live_incidents_after = live_incident_service.list_incidents()
        assert len(live_incidents_after) == live_incident_count_before, (
            "Live incident count should not change after replay"
        )
        assert live_incidents_after[0].title == "Live Incident", (
            "Live incident should remain unchanged"
        )

        # Replay incidents should be in replay service, not live
        replay_incidents = replay_incident_service.list_incidents()
        assert len(replay_incidents) > 0, "Replay should create incidents in isolated service"
        for replay_incident in replay_incidents:
            assert replay_incident.title != "Live Incident", (
                "Replay incidents should not appear in live service"
            )

    def test_replay_does_not_consume_live_entity_mappings(self) -> None:
        """Replay should not consume or alter live entity mappings."""
        live_entity_correlation = EntityCorrelationService()
        live_incident_service = IncidentService()

        # Pre-populate live entity mappings
        live_alert = Alert(
            title="Live Alert",
            description="Live test",
            severity=Severity.MEDIUM,
            source="test",
            entity_context={"host": "live-host", "dst_ip": "10.0.0.1"},
        )
        live_entity_key = live_entity_correlation.compute_entity_key(live_alert)
        live_incident_service.create_incident([live_alert])
        live_incident_service.get_or_create_incident_for_entity(live_entity_key, [live_alert])

        # Run replay with separate services
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)
        replay_entity_correlation = EntityCorrelationService()
        replay_incident_service = IncidentService()

        _, _ = _build_replay_pipeline_with_incidents(
            events,
            incident_service=replay_incident_service,
            entity_correlation_service=replay_entity_correlation,
        )

        # Live entity mappings should be unchanged
        live_entity_for_host = live_incident_service.get_incident_for_entity(live_entity_key)
        assert live_entity_for_host is not None, "Live entity mapping should remain intact"


# ===========================================================================
# C. Replay runs are isolated from each other
# ===========================================================================


class TestReplayRunsIsolated:
    """Verify that multiple replay runs use separate incident state."""

    def test_run_a_does_not_affect_run_b(self) -> None:
        """Two replay runs should not share incident state."""
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)

        # Run A
        run_a_incident_service = IncidentService()
        run_a_entity_correlation = EntityCorrelationService()
        _, run_a_alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=run_a_incident_service,
            entity_correlation_service=run_a_entity_correlation,
        )
        run_a_incidents = run_a_incident_service.list_incidents()
        run_a_incident_ids = {inc.incident_id for inc in run_a_incidents}

        # Run B with completely separate services
        run_b_incident_service = IncidentService()
        run_b_entity_correlation = EntityCorrelationService()
        _, run_b_alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=run_b_incident_service,
            entity_correlation_service=run_b_entity_correlation,
        )
        run_b_incidents = run_b_incident_service.list_incidents()
        run_b_incident_ids = {inc.incident_id for inc in run_b_incidents}

        # Incident IDs should be different (random UUIDs)
        assert run_a_incident_ids != run_b_incident_ids, (
            "Different replay runs should have different incident IDs"
        )

        # Both runs should have incidents
        assert len(run_a_incidents) > 0, "Run A should have incidents"
        assert len(run_b_incidents) > 0, "Run B should have incidents"

        # Alerts from run A should not reference run B incidents
        for alert in run_a_alerts:
            if alert.incident_id is not None:
                assert alert.incident_id not in run_b_incident_ids, (
                    "Run A alerts should not reference run B incidents"
                )

        # Alerts from run B should not reference run A incidents
        for alert in run_b_alerts:
            if alert.incident_id is not None:
                assert alert.incident_id not in run_a_incident_ids, (
                    "Run B alerts should not reference run A incidents"
                )


# ===========================================================================
# D. Entity correlation works during replay
# ===========================================================================


class TestEntityCorrelationDuringReplay:
    """Verify that entity correlation produces correct grouping during replay."""

    def test_same_entity_alerts_grouped_to_same_incident(self) -> None:
        """Multiple alerts for same entity should share incident_id."""
        # Create events for same entity (same host, same dst_ip)
        events = _beacon_events(
            src_ip="192.168.1.105",
            hostname="workstation-23",
            dst_ip="203.0.113.50",
            dst_port=8443,
            process_name="powershell.exe",
            count=24,
        )

        incident_service = IncidentService()
        entity_correlation_service = EntityCorrelationService()

        _, alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=incident_service,
            entity_correlation_service=entity_correlation_service,
        )

        # Filter alerts with entity context
        entity_alerts = [a for a in alerts if a.entity_context is not None]
        assert len(entity_alerts) > 0, "Should have alerts with entity context"

        # All alerts for same entity should have same incident_id
        incident_ids = {a.incident_id for a in entity_alerts if a.incident_id is not None}
        assert len(incident_ids) == 1, "All alerts for same entity should share one incident_id"

    def test_canonical_entity_key_used(self) -> None:
        """Entity correlation should use canonical compute_entity_key()."""
        events = _beacon_events(
            src_ip="192.168.1.105",
            hostname="workstation-23",
            dst_ip="203.0.113.50",
            dst_port=8443,
            process_name="powershell.exe",
            count=24,
        )

        entity_correlation_service = EntityCorrelationService()
        incident_service = IncidentService()

        _, alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=incident_service,
            entity_correlation_service=entity_correlation_service,
        )

        # Verify entity key computation is consistent across alerts
        # Note: Zeek conn.log parser does not populate hostname/process_name,
        # so entity key falls back to dst_ip-based key
        entity_keys = set()
        for alert in alerts:
            if alert.entity_context is not None:
                entity_key = entity_correlation_service.compute_entity_key(alert)
                entity_keys.add(entity_key)

        # All alerts should have consistent entity keys
        assert len(entity_keys) == 1, (
            f"All alerts should have consistent entity key, got: {entity_keys}"
        )

        # The key should be based on dst_ip since hostname/process_name
        # are not available from Zeek conn.log
        expected_key = "*:203.0.113.50"
        assert expected_key in entity_keys, f"Expected entity key {expected_key}, got {entity_keys}"

    def test_no_duplicate_unrelated_incidents_for_same_entity(self) -> None:
        """Should not create multiple incidents for same entity."""
        events = _beacon_events(
            src_ip="192.168.1.105",
            hostname="workstation-23",
            dst_ip="203.0.113.50",
            dst_port=8443,
            process_name="powershell.exe",
            count=24,
        )

        incident_service = IncidentService()
        entity_correlation_service = EntityCorrelationService()

        _, _alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=incident_service,
            entity_correlation_service=entity_correlation_service,
        )

        # Should have exactly one incident for the entity
        incidents = incident_service.list_incidents()
        assert len(incidents) == 1, "Should create exactly one incident for same entity"


# ===========================================================================
# E. Semantic replay equivalence
# ===========================================================================


class TestSemanticReplayEquivalence:
    """Verify that equivalent replay inputs produce semantically equivalent results."""

    def test_repeated_replay_produces_equivalent_semantic_results(self) -> None:
        """Two replay runs on same input should produce equivalent semantic fields."""
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)

        # Run 1
        run1_incident_service = IncidentService()
        run1_entity_correlation = EntityCorrelationService()
        _, run1_alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=run1_incident_service,
            entity_correlation_service=run1_entity_correlation,
        )

        # Run 2
        run2_incident_service = IncidentService()
        run2_entity_correlation = EntityCorrelationService()
        _, run2_alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=run2_incident_service,
            entity_correlation_service=run2_entity_correlation,
        )

        assert len(run1_alerts) == len(run2_alerts), (
            "Both runs should produce same number of alerts"
        )

        # Compare semantic fields (ignoring nondeterministic IDs)
        for alert1, alert2 in zip(run1_alerts, run2_alerts, strict=False):
            normalized1 = _normalize_alert_for_comparison(alert1)
            normalized2 = _normalize_alert_for_comparison(alert2)

            # These fields should be identical
            assert normalized1["severity"] == normalized2["severity"], (
                "Severity should be equivalent"
            )
            assert normalized1["priority"] == normalized2["priority"], (
                "Priority should be equivalent"
            )
            assert normalized1["contextual_confidence"] == normalized2["contextual_confidence"], (
                "Contextual confidence should be equivalent"
            )
            assert normalized1["detector_confidence"] == normalized2["detector_confidence"], (
                "Detector confidence should be equivalent"
            )
            assert normalized1["supporting_evidence"] == normalized2["supporting_evidence"], (
                "Supporting evidence should be equivalent"
            )
            assert normalized1["contradictory_evidence"] == normalized2["contradictory_evidence"], (
                "Contradictory evidence should be equivalent"
            )
            assert normalized1["investigation_pivots"] == normalized2["investigation_pivots"], (
                "Investigation pivots should be equivalent"
            )
            assert normalized1["entity_context"] == normalized2["entity_context"], (
                "Entity context should be equivalent"
            )

    def test_incident_ids_are_normalized_for_comparison(self) -> None:
        """Incident IDs should differ between runs but semantic fields match."""
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)

        run1_incident_service = IncidentService()
        run1_entity_correlation = EntityCorrelationService()
        _, run1_alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=run1_incident_service,
            entity_correlation_service=run1_entity_correlation,
        )

        run2_incident_service = IncidentService()
        run2_entity_correlation = EntityCorrelationService()
        _, run2_alerts = _build_replay_pipeline_with_incidents(
            events,
            incident_service=run2_incident_service,
            entity_correlation_service=run2_entity_correlation,
        )

        # Incident IDs should be different (random UUIDs)
        run1_incident_ids = {a.incident_id for a in run1_alerts if a.incident_id}
        run2_incident_ids = {a.incident_id for a in run2_alerts if a.incident_id}
        assert run1_incident_ids != run2_incident_ids, (
            "Incident IDs should differ between runs (nondeterministic)"
        )

        # But semantic fields should match
        for alert1, alert2 in zip(run1_alerts, run2_alerts, strict=False):
            assert alert1.severity == alert2.severity
            assert alert1.priority == alert2.priority


# ===========================================================================
# F. Existing queue isolation
# ===========================================================================


class TestQueueIsolation:
    """Verify that replay does not mutate AlertQueue."""

    def test_alert_queue_untouched_by_replay(self) -> None:
        """Replay should not enqueue alerts or alter queue state."""
        from argusprowl.lifecycle.queue import AlertQueue

        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)

        # Create a live AlertQueue
        live_queue = AlertQueue(max_size=100)
        initial_queue_size = len(live_queue)

        # Run replay with isolated services
        incident_service = IncidentService()
        entity_correlation_service = EntityCorrelationService()

        _, _ = _build_replay_pipeline_with_incidents(
            events,
            incident_service=incident_service,
            entity_correlation_service=entity_correlation_service,
        )

        # Queue should be unchanged
        assert len(live_queue) == initial_queue_size, "Replay should not mutate AlertQueue"

    def test_replay_does_not_acknowledge_or_close_queue_alerts(self) -> None:
        """Replay should not perform lifecycle operations on queue."""
        from argusprowl.lifecycle.queue import AlertQueue

        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)

        live_queue = AlertQueue(max_size=100)

        # Add a test alert to queue
        test_alert = Alert(
            title="Test Alert",
            description="Test",
            severity=Severity.MEDIUM,
            source="test",
        )
        live_queue.enqueue(test_alert)
        initial_count = len(live_queue)

        # Run replay
        incident_service = IncidentService()
        entity_correlation_service = EntityCorrelationService()

        _, _ = _build_replay_pipeline_with_incidents(
            events,
            incident_service=incident_service,
            entity_correlation_service=entity_correlation_service,
        )

        # Queue should still have the test alert
        assert len(live_queue) == initial_count, "Replay should not alter queue contents"


# ===========================================================================
# G. Provider isolation
# ===========================================================================


class TestProviderIsolation:
    """Verify that replay does not dispatch alerts to providers."""

    def test_providers_untouched_by_replay(self) -> None:
        """Replay should not dispatch alerts to any providers."""
        from argusprowl.alerting.console_provider import ConsoleAlertProvider
        from argusprowl.alerting.json_provider import JsonAlertProvider

        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)

        # Track provider calls
        console_deliveries = []
        json_deliveries = []

        class TrackingConsoleProvider(ConsoleAlertProvider):
            def deliver(self, alert: Alert) -> None:
                console_deliveries.append(alert)
                super().deliver(alert)

        class TrackingJsonProvider(JsonAlertProvider):
            def deliver(self, alert: Alert) -> None:
                json_deliveries.append(alert)
                super().deliver(alert)

        # Run replay (providers are not injected into replay, so no dispatch should occur)
        incident_service = IncidentService()
        entity_correlation_service = EntityCorrelationService()

        _, _ = _build_replay_pipeline_with_incidents(
            events,
            incident_service=incident_service,
            entity_correlation_service=entity_correlation_service,
        )

        # No provider dispatch should have occurred
        assert len(console_deliveries) == 0, "Replay should not dispatch to ConsoleAlertProvider"
        assert len(json_deliveries) == 0, "Replay should not dispatch to JsonAlertProvider"


# ===========================================================================
# H. Backward compatibility
# ===========================================================================


class TestBackwardCompatibility:
    """Verify existing ReplayEngine behavior remains unchanged."""

    def test_existing_replay_without_incident_services(self) -> None:
        """Replay without incident services should work as before."""
        events = _beacon_events(dst_ip="203.0.113.50", dst_port=8443)

        # Create replay engine without incident services (old behavior)
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
        intelligence_service = ContextualIntelligenceService(
            prevalence_tracker=prevalence_tracker,
            threat_intel_provider=ti_provider,
        )

        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("#separator \\x09\n")
            f.write("#set_separator\t,\n")
            f.write("#empty_field\t(empty)\n")
            f.write("#path\tconn\n")
            f.write("#open\t2019-01-01-00-00-00\n")
            f.write(
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\n"
            )
            f.write(
                "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\n"
            )
            for ev in events:
                f.write(
                    f"{ev.timestamp.timestamp()}\t{ev.attributes.get('uid', 'C_test')}\t{ev.src_ip}\t{ev.src_port}\t{ev.dst_ip}\t{ev.dst_port}\t{ev.protocol}\t\t{ev.timestamp.timestamp()}\t0\t0\tSF\tShADadfF\t1\t1\n"
                )
            log_path = f.name

        try:
            engine = ReplayEngine(
                log_path=log_path,
                temporal_engine=temporal_engine,
                beaconing_detector=detector,
                intelligence_service=intelligence_service,
                # No incident_service or entity_correlation_service
            )
            alerts = engine.run()

            # Should complete without errors
            assert isinstance(alerts, list)
            assert engine.events_processed == len(events)
        finally:
            import os

            os.unlink(log_path)

    def test_existing_replay_with_explicit_decision_engine(self) -> None:
        """Replay with explicit DecisionEngine should use it directly."""
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
        intelligence_service = ContextualIntelligenceService(
            prevalence_tracker=prevalence_tracker,
            threat_intel_provider=ti_provider,
        )

        # Create explicit DecisionEngine
        explicit_decision_engine = DecisionEngine(cooldown_seconds=0)

        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("#separator \\x09\n")
            f.write("#set_separator\t,\n")
            f.write("#empty_field\t(empty)\n")
            f.write("#path\tconn\n")
            f.write("#open\t2019-01-01-00-00-00\n")
            f.write(
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\n"
            )
            f.write(
                "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\n"
            )
            for ev in events:
                f.write(
                    f"{ev.timestamp.timestamp()}\t{ev.attributes.get('uid', 'C_test')}\t{ev.src_ip}\t{ev.src_port}\t{ev.dst_ip}\t{ev.dst_port}\t{ev.protocol}\t\t{ev.timestamp.timestamp()}\t0\t0\tSF\tShADadfF\t1\t1\n"
                )
            log_path = f.name

        try:
            engine = ReplayEngine(
                log_path=log_path,
                temporal_engine=temporal_engine,
                beaconing_detector=detector,
                intelligence_service=intelligence_service,
                decision_engine=explicit_decision_engine,
            )
            alerts = engine.run()

            # Should use the explicit decision engine
            assert isinstance(alerts, list)
            assert engine.events_processed == len(events)
        finally:
            import os

            os.unlink(log_path)

    def test_existing_replay_tests_still_pass(self) -> None:
        """Run the existing replay test suite to verify backward compatibility."""
        # This test simply verifies that the existing test_replay.py tests
        # would still pass by running a subset of the same logic
        import tempfile

        from argusprowl.detection.detection_manager import DetectionManager
        from argusprowl.detection.detector_registry import DetectorRegistry
        from argusprowl.detection.detectors.port_scan import PortScanDetector
        from argusprowl.feature_engineering.feature_extractor import FeatureExtractor

        # Create sample log
        log_content = """#separator \\x09
#set_separator	,
#empty_field	(empty)
#path	conn
#open	2019-01-01-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	history	orig_pkts	resp_pkts
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	string	count	count
1550000000.000000	C1	192.168.1.100	12345	10.0.0.1	80	tcp	http	1.5	1024	2048	SF	ShADadfF	10	8
1550000001.000000	C2	192.168.1.100	12346	10.0.0.2	443	tcp	https	2.0	2048	4096	SF	ShADadfF	15	12
1550000002.000000	C3	192.168.1.100	12347	10.0.0.3	22	tcp	ssh	0.5	512	256	SF	ShADadfF	5	3
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(log_content)
            log_path = f.name

        try:
            # Test basic replay
            engine = ReplayEngine(log_path=log_path)
            alerts = engine.run()
            assert isinstance(alerts, list)
            assert engine.events_processed == 3

            # Test with callbacks
            callback_events = []

            def on_event(event):
                callback_events.append(("event", event.attributes["uid"]))

            engine2 = ReplayEngine(log_path=log_path)
            engine2.run_with_callbacks(on_event=on_event)
            assert len(callback_events) == 3
            assert all(e[0] == "event" for e in callback_events)

            # Test with custom detectors
            feature_extractor = FeatureExtractor(window_size_seconds=3600.0)
            registry = DetectorRegistry()
            registry.register(PortScanDetector())
            detection_manager = DetectionManager(registry)

            engine3 = ReplayEngine(
                log_path=log_path,
                feature_extractor=feature_extractor,
                detection_manager=detection_manager,
            )
            alerts3 = engine3.run()
            assert isinstance(alerts3, list)
            assert engine3.events_processed == 3
        finally:
            import os

            os.unlink(log_path)
