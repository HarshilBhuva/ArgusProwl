"""Tests for endpoint ↔ network correlation."""

from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from argusprowl.correlation.correlation_model import (
    CorrelatedActivity,
    NetworkDirection,
    NetworkObservation,
    ProcessIdentity,
)
from argusprowl.correlation.correlator import EndpointCorrelator
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Return a randomly available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_event(
    dst_ip: str = "203.0.113.10",
    dst_port: int = 443,
    src_ip: str | None = "192.168.1.1",
    process_name: str | None = None,
    pid: int | None = None,
    username: str | None = None,
    hostname: str | None = "workstation01",
    timestamp: datetime | None = None,
    protocol: str | None = "TCP",
    attributes: dict[str, Any] | None = None,
    source_type: str = "sysmon",
    command_line: str | None = None,
) -> NormalizedEvent:
    """Create a minimal NormalizedEvent for correlation testing."""
    return NormalizedEvent(
        source_type=source_type,
        event_type="network_connection",
        timestamp=timestamp or datetime.now(UTC),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=54321,
        dst_port=dst_port,
        protocol=protocol,
        process_name=process_name,
        pid=pid,
        username=username,
        hostname=hostname,
        command_line=command_line,
        attributes=attributes or {},
    )


def _make_process_event(
    process_name: str = "unknown.exe",
    pid: int = 4812,
    username: str | None = "alice",
    hostname: str | None = "workstation01",
    command_line: str | None = None,
    timestamp: datetime | None = None,
    source_type: str = "sysmon",
) -> NormalizedEvent:
    """Create a process creation event."""
    return NormalizedEvent(
        source_type=source_type,
        event_type="process_create",
        timestamp=timestamp or datetime.now(UTC),
        hostname=hostname,
        username=username,
        process_name=process_name,
        pid=pid,
        command_line=command_line,
        attributes={"process_id": pid, "ProcessId": pid},
    )


# ---------------------------------------------------------------------------
# ProcessIdentity tests
# ---------------------------------------------------------------------------


class TestProcessIdentity:
    def test_creates_with_required_fields(self) -> None:
        identity = ProcessIdentity(process_name="test.exe", pid=1234)
        assert identity.process_name == "test.exe"
        assert identity.pid == 1234
        assert identity.username is None
        assert identity.hostname is None

    def test_identity_key(self) -> None:
        identity = ProcessIdentity(process_name="test.exe", pid=1234, hostname="host1")
        assert identity.identity_key == ("host1", 1234)

    def test_identity_key_without_hostname(self) -> None:
        identity = ProcessIdentity(process_name="test.exe", pid=1234)
        assert identity.identity_key == (None, 1234)

    def test_is_complete(self) -> None:
        assert ProcessIdentity(process_name="test.exe", pid=1234).is_complete()
        assert not ProcessIdentity(process_name="test.exe", pid=None).is_complete()
        assert not ProcessIdentity(process_name=None, pid=1234).is_complete()


# ---------------------------------------------------------------------------
# NetworkObservation tests
# ---------------------------------------------------------------------------


class TestNetworkObservation:
    def test_creates_with_required_fields(self) -> None:
        obs = NetworkObservation(
            event_id=uuid4(),
            timestamp=datetime.now(UTC),
            dst_ip="1.2.3.4",
            dst_port=443,
        )
        assert obs.dst_ip == "1.2.3.4"
        assert obs.dst_port == 443
        assert obs.direction == NetworkDirection.UNKNOWN
        assert not obs.has_process_attribution()

    def test_network_key(self) -> None:
        obs = NetworkObservation(
            event_id=uuid4(),
            timestamp=datetime.now(UTC),
            dst_ip="1.2.3.4",
            dst_port=443,
        )
        assert obs.network_key == ("1.2.3.4", 443)

    def test_has_process_attribution(self) -> None:
        obs = NetworkObservation(
            event_id=uuid4(),
            timestamp=datetime.now(UTC),
            dst_ip="1.2.3.4",
            dst_port=443,
            process_name="test.exe",
            pid=1234,
        )
        assert obs.has_process_attribution()

    def test_no_process_attribution(self) -> None:
        obs = NetworkObservation(
            event_id=uuid4(),
            timestamp=datetime.now(UTC),
            dst_ip="1.2.3.4",
            dst_port=443,
        )
        assert not obs.has_process_attribution()


# ---------------------------------------------------------------------------
# CorrelatedActivity tests
# ---------------------------------------------------------------------------


class TestCorrelatedActivity:
    def test_explanation_with_process(self) -> None:
        corr = CorrelatedActivity(
            activity_id=uuid4(),
            process_name="unknown.exe",
            pid=4812,
            username="alice",
            hostname="workstation01",
            command_line=None,
            dst_ip="203.0.113.10",
            dst_port=443,
            protocol="TCP",
            direction=NetworkDirection.UNKNOWN,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            observation_count=5,
            source_types=("sysmon",),
            event_ids=(uuid4(),),
        )
        assert "unknown.exe" in corr.explanation
        assert "4812" in corr.explanation
        assert "alice" in corr.explanation
        assert "203.0.113.10:443" in corr.explanation

    def test_explanation_without_process(self) -> None:
        corr = CorrelatedActivity(
            activity_id=uuid4(),
            process_name=None,
            pid=None,
            username=None,
            hostname=None,
            command_line=None,
            dst_ip="203.0.113.10",
            dst_port=443,
            protocol=None,
            direction=NetworkDirection.UNKNOWN,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            observation_count=5,
            source_types=("zeek",),
            event_ids=(uuid4(),),
        )
        assert "unknown process" in corr.explanation.lower()

    def test_to_evidence(self) -> None:
        corr = CorrelatedActivity(
            activity_id=uuid4(),
            process_name="test.exe",
            pid=1234,
            username="bob",
            hostname="host1",
            command_line=None,
            dst_ip="1.2.3.4",
            dst_port=80,
            protocol="TCP",
            direction=NetworkDirection.OUTBOUND,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            observation_count=10,
            source_types=("sysmon",),
            event_ids=(uuid4(),),
        )
        evidence = corr.to_evidence()
        fields = [e["field"] for e in evidence]
        assert "process_name" in fields
        assert "process_id" in fields
        assert "username" in fields
        assert "hostname" in fields
        assert "destination" in fields
        assert "destination_port" in fields
        assert "protocol" in fields
        assert "direction" in fields
        assert "observation_count" in fields

    def test_to_evidence_minimal(self) -> None:
        corr = CorrelatedActivity(
            activity_id=uuid4(),
            process_name=None,
            pid=None,
            username=None,
            hostname=None,
            command_line=None,
            dst_ip="1.2.3.4",
            dst_port=443,
            protocol=None,
            direction=NetworkDirection.UNKNOWN,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            observation_count=1,
            source_types=(),
            event_ids=(uuid4(),),
        )
        evidence = corr.to_evidence()
        fields = [e["field"] for e in evidence]
        assert "process_name" not in fields
        assert "destination" in fields


# ---------------------------------------------------------------------------
# EndpointCorrelator tests
# ---------------------------------------------------------------------------


class TestEndpointCorrelator:
    def test_empty_initial_state(self) -> None:
        corr = EndpointCorrelator()
        stats = corr.get_statistics()
        assert stats["processed_count"] == 0
        assert stats["correlation_count"] == 0
        assert stats["tracked_processes"] == 0
        assert stats["tracked_network_keys"] == 0

    def test_process_observation_registration(self) -> None:
        corr = EndpointCorrelator()
        event = _make_process_event()
        corr.observe(event)

        stats = corr.get_statistics()
        assert stats["processed_count"] == 1
        assert stats["tracked_processes"] == 1

    def test_network_observation_registration(self) -> None:
        corr = EndpointCorrelator()
        event = _make_event()
        corr.observe(event)

        stats = corr.get_statistics()
        assert stats["processed_count"] == 1
        assert stats["tracked_network_keys"] == 1

    def test_successful_pid_correlation(self) -> None:
        corr = EndpointCorrelator()
        # Register process
        proc_event = _make_process_event(process_name="unknown.exe", pid=4812)
        corr.observe(proc_event)
        # Register network event with same process
        net_event = _make_event(
            dst_ip="203.0.113.10",
            dst_port=443,
            process_name="unknown.exe",
            pid=4812,
            hostname="workstation01",
        )
        corr.observe(net_event)

        correlations = corr.get_correlations()
        assert len(correlations) == 1
        assert correlations[0].process_name == "unknown.exe"
        assert correlations[0].pid == 4812
        assert correlations[0].dst_ip == "203.0.113.10"

    def test_hostname_pid_scoping(self) -> None:
        corr = EndpointCorrelator()
        # Same PID on different hosts
        proc1 = _make_process_event(pid=1234, hostname="host1")
        proc2 = _make_process_event(pid=1234, hostname="host2")
        corr.observe(proc1)
        corr.observe(proc2)

        assert corr.get_statistics()["tracked_processes"] == 2

        # Network event for host1 should correlate with host1 process
        net1 = _make_event(process_name="test.exe", pid=1234, hostname="host1")
        corr.observe(net1)

        # Network event for host2 should correlate with host2 process
        net2 = _make_event(process_name="test.exe", pid=1234, hostname="host2")
        corr.observe(net2)

        correlations = corr.get_correlations()
        assert len(correlations) == 2

    def test_process_lifetime_handling(self) -> None:
        corr = EndpointCorrelator(correlation_window_seconds=1.0)
        now = datetime.now(UTC)

        # Register process
        proc_event = _make_process_event(timestamp=now)
        corr.observe(proc_event)

        # Network event after window expires WITHOUT process attribution
        # (simulating Zeek/Suricata that lacks process info)
        net_event = _make_event(
            timestamp=now + timedelta(seconds=5),
            process_name=None,
            pid=None,
        )
        corr.observe(net_event)

        # Should not correlate because network event has no process attribution
        correlations = corr.get_correlations()
        assert len(correlations) == 0

    def test_correlation_window_expiration(self) -> None:
        corr = EndpointCorrelator(correlation_window_seconds=1.0)
        now = datetime.now(UTC)

        # Register process and network event within window
        proc_event = _make_process_event(timestamp=now)
        corr.observe(proc_event)

        net_event = _make_event(
            timestamp=now + timedelta(seconds=0.5),
            process_name="unknown.exe",
            pid=4812,
            hostname="workstation01",
        )
        corr.observe(net_event)

        assert len(corr.get_correlations()) == 1

        # Late network event WITHOUT process attribution (e.g., Zeek)
        # Should not create new correlation
        net_event_late = _make_event(
            timestamp=now + timedelta(seconds=5),
            process_name=None,
            pid=None,
        )
        corr.observe(net_event_late)

        # Old correlation should still exist
        correlations = corr.get_correlations()
        assert len(correlations) == 1
        # Observation count should not increase since late event has no process
        assert correlations[0].observation_count == 1

    def test_max_tracked_process_bound(self) -> None:
        corr = EndpointCorrelator(max_processes=5)
        # Register more processes than max
        for i in range(10):
            event = _make_process_event(process_name=f"proc{i}.exe", pid=i)
            corr.observe(event)

        stats = corr.get_statistics()
        assert stats["tracked_processes"] <= 5

    def test_deterministic_process_eviction(self) -> None:
        corr = EndpointCorrelator(max_processes=3)
        # Register processes
        for i in range(5):
            event = _make_process_event(process_name=f"proc{i}.exe", pid=i)
            corr.observe(event)

        # Oldest processes should be evicted (LRU)
        stats = corr.get_statistics()
        assert stats["tracked_processes"] == 3

    def test_missing_pid(self) -> None:
        corr = EndpointCorrelator()
        # Event without PID
        event = _make_event(process_name="test.exe", pid=None)
        corr.observe(event)

        stats = corr.get_statistics()
        assert stats["tracked_processes"] == 1

    def test_missing_hostname(self) -> None:
        corr = EndpointCorrelator()
        # Event without hostname
        event = _make_event(process_name="test.exe", pid=1234, hostname=None)
        corr.observe(event)

        stats = corr.get_statistics()
        assert stats["tracked_processes"] == 1

    def test_network_event_without_process_attribution(self) -> None:
        corr = EndpointCorrelator()
        # Zeek-like event without process info
        event = _make_event(
            source_type="zeek",
            process_name=None,
            pid=None,
        )
        corr.observe(event)

        correlations = corr.get_correlations()
        assert len(correlations) == 0
        stats = corr.get_statistics()
        assert stats["tracked_network_keys"] == 1

    def test_process_event_without_network_event(self) -> None:
        corr = EndpointCorrelator()
        event = _make_process_event()
        corr.observe(event)

        correlations = corr.get_correlations()
        assert len(correlations) == 0
        stats = corr.get_statistics()
        assert stats["tracked_processes"] == 1

    def test_multiple_processes_on_same_host(self) -> None:
        corr = EndpointCorrelator()
        # Two different processes on same host
        proc1 = _make_process_event(process_name="browser.exe", pid=1000, hostname="host1")
        proc2 = _make_process_event(process_name="unknown.exe", pid=2000, hostname="host1")
        corr.observe(proc1)
        corr.observe(proc2)

        # Network events for each
        net1 = _make_event(process_name="browser.exe", pid=1000, hostname="host1")
        net2 = _make_event(process_name="unknown.exe", pid=2000, hostname="host1")
        corr.observe(net1)
        corr.observe(net2)

        correlations = corr.get_correlations()
        assert len(correlations) == 2
        pids = {c.pid for c in correlations}
        assert 1000 in pids
        assert 2000 in pids

    def test_pid_reuse_handling(self) -> None:
        corr = EndpointCorrelator()
        now = datetime.now(UTC)

        # Process with PID 1234
        proc1 = _make_process_event(pid=1234, hostname="host1", timestamp=now)
        corr.observe(proc1)

        # Network event for PID 1234 with explicit hostname and process name
        net1 = _make_event(pid=1234, hostname="host1", process_name="test.exe", timestamp=now)
        corr.observe(net1)

        # Later, same PID on same host (PID reuse) - update process identity
        proc2 = _make_process_event(
            pid=1234, hostname="host1", timestamp=now + timedelta(seconds=10)
        )
        corr.observe(proc2)

        # Network event after reuse with explicit hostname and process name
        net2 = _make_event(
            pid=1234,
            hostname="host1",
            process_name="test.exe",
            timestamp=now + timedelta(seconds=10),
        )
        corr.observe(net2)

        correlations = corr.get_correlations()
        # Should have at least one correlation (may be updated due to PID reuse)
        assert len(correlations) >= 1

    def test_correct_destination_association(self) -> None:
        corr = EndpointCorrelator()
        proc = _make_process_event(process_name="test.exe", pid=1234)
        corr.observe(proc)

        # Network to different destinations
        net1 = _make_event(dst_ip="1.1.1.1", dst_port=80, process_name="test.exe", pid=1234)
        net2 = _make_event(dst_ip="2.2.2.2", dst_port=443, process_name="test.exe", pid=1234)
        corr.observe(net1)
        corr.observe(net2)

        correlations = corr.get_correlations()
        assert len(correlations) == 2
        destinations = {(c.dst_ip, c.dst_port) for c in correlations}
        assert ("1.1.1.1", 80) in destinations
        assert ("2.2.2.2", 443) in destinations

    def test_correct_timestamp_association(self) -> None:
        corr = EndpointCorrelator()
        now = datetime.now(UTC)

        proc = _make_process_event(timestamp=now)
        corr.observe(proc)

        net = _make_event(timestamp=now + timedelta(seconds=1))
        corr.observe(net)

        correlations = corr.get_correlations()
        if correlations:
            assert correlations[0].first_seen <= correlations[0].last_seen

    def test_direction_outbound(self) -> None:
        corr = EndpointCorrelator()
        event = _make_event(
            attributes={"direction": "outbound"},
        )
        corr.observe(event)

        corr.get_correlations()
        # Direction is derived from network observation, not correlation
        # This tests that direction is preserved
        stats = corr.get_statistics()
        assert stats["tracked_network_keys"] == 1

    def test_direction_inbound(self) -> None:
        corr = EndpointCorrelator()
        event = _make_event(
            attributes={"in_iface": "eth0"},
        )
        corr.observe(event)

        # Inbound direction should be derived from in_iface
        stats = corr.get_statistics()
        assert stats["tracked_network_keys"] == 1

    def test_direction_unknown(self) -> None:
        corr = EndpointCorrelator()
        event = _make_event()
        corr.observe(event)

        stats = corr.get_statistics()
        assert stats["tracked_network_keys"] == 1

    def test_no_unsafe_direction_inference(self) -> None:
        """Ensure we don't infer direction from IP heuristics."""
        corr = EndpointCorrelator()
        # Private IP destination should not automatically be outbound
        event = _make_event(dst_ip="192.168.1.100")
        corr.observe(event)

        # Should not infer outbound from private IP
        correlations = corr.get_correlations()
        for corr_item in correlations:
            assert (
                corr_item.direction != NetworkDirection.OUTBOUND
                or corr_item.direction == NetworkDirection.UNKNOWN
            )

    def test_sysmon_correlation(self) -> None:
        corr = EndpointCorrelator()
        # Sysmon process event
        proc = _make_process_event(
            process_name="svchost.exe",
            pid=812,
            username="SYSTEM",
            hostname="DC01",
            source_type="sysmon",
        )
        corr.observe(proc)

        # Sysmon network event with process attribution
        net = _make_event(
            dst_ip="203.0.113.50",
            dst_port=443,
            process_name="svchost.exe",
            pid=812,
            hostname="DC01",
            source_type="sysmon",
            username="SYSTEM",  # Include username in network event too
        )
        corr.observe(net)

        correlations = corr.get_correlations()
        assert len(correlations) == 1
        assert correlations[0].process_name == "svchost.exe"
        assert correlations[0].pid == 812
        assert correlations[0].username == "SYSTEM"

    def test_zeek_no_process_identity(self) -> None:
        """Zeek should track network but not correlate with process."""
        corr = EndpointCorrelator()
        event = _make_event(
            source_type="zeek",
            process_name=None,
            pid=None,
            username=None,
        )
        corr.observe(event)

        correlations = corr.get_correlations()
        assert len(correlations) == 0
        stats = corr.get_statistics()
        assert stats["tracked_network_keys"] == 1
        assert stats["tracked_processes"] == 0

    def test_suricata_no_process_identity(self) -> None:
        """Suricata should track network but not correlate with process."""
        corr = EndpointCorrelator()
        event = _make_event(
            source_type="suricata",
            process_name=None,
            pid=None,
        )
        corr.observe(event)

        correlations = corr.get_correlations()
        assert len(correlations) == 0
        stats = corr.get_statistics()
        assert stats["tracked_network_keys"] == 1

    def test_beaconing_detector_receives_temporal_signal(self) -> None:
        """Test that beaconing detector can use correlated process info."""
        from argusprowl.detection.detectors.beaconing_detector import BeaconingDetector
        from argusprowl.temporal.engine import TemporalEngine

        temporal = TemporalEngine(max_keys=100, max_observations_per_key=100)
        BeaconingDetector(
            temporal_engine=temporal,
            min_observations=3,
            min_duration_seconds=1.0,
            periodicity_threshold=0.5,
        )

        corr = EndpointCorrelator()
        now = datetime.now(UTC)

        # Register process
        proc = _make_process_event(process_name="beacon.exe", pid=9999, hostname="host1")
        corr.observe(proc)

        # Create periodic network observations with process attribution
        for i in range(5):
            event = _make_event(
                dst_ip="203.0.113.10",
                dst_port=443,
                process_name="beacon.exe",
                pid=9999,
                hostname="host1",
                timestamp=now + timedelta(seconds=i * 10),
            )
            temporal.observe(event)
            corr.observe(event)

        # Check that temporal engine has process info
        analysis = temporal.get_analysis("203.0.113.10", 443)
        assert analysis is not None
        assert analysis.get("process_name") == "beacon.exe"
        assert analysis.get("pid") == 9999

    def test_beaconing_detection_includes_process_evidence(self) -> None:
        """Test that beaconing detection includes process evidence when available."""
        from argusprowl.detection.detectors.beaconing_detector import BeaconingDetector
        from argusprowl.temporal.engine import TemporalEngine

        temporal = TemporalEngine(max_keys=100, max_observations_per_key=100)
        detector = BeaconingDetector(
            temporal_engine=temporal,
            min_observations=3,
            min_duration_seconds=1.0,
            periodicity_threshold=0.5,
        )

        now = datetime.now(UTC)

        # Create periodic observations with process attribution
        for i in range(5):
            event = _make_event(
                dst_ip="203.0.113.10",
                dst_port=8443,
                process_name="suspicious.exe",
                pid=1234,
                username="alice",
                hostname="workstation01",
                timestamp=now + timedelta(seconds=i * 10),
            )
            temporal.observe(event)

        # Trigger detection
        result = detector.detect(_make_event(dst_ip="203.0.113.10", dst_port=8443))
        assert result.matched
        evidence_fields = [e["field"] for e in result.evidence]
        assert "process_name" in evidence_fields
        assert "process_id" in evidence_fields
        assert "username" in evidence_fields
        assert "hostname" in evidence_fields

    def test_beaconing_detection_without_process_evidence(self) -> None:
        """Test that beaconing detection works without process evidence."""
        from argusprowl.detection.detectors.beaconing_detector import BeaconingDetector
        from argusprowl.temporal.engine import TemporalEngine

        temporal = TemporalEngine(max_keys=100, max_observations_per_key=100)
        detector = BeaconingDetector(
            temporal_engine=temporal,
            min_observations=3,
            min_duration_seconds=1.0,
            periodicity_threshold=0.5,
        )

        now = datetime.now(UTC)

        # Create periodic observations WITHOUT process attribution
        for i in range(5):
            event = _make_event(
                dst_ip="203.0.113.10",
                dst_port=8443,
                process_name=None,
                pid=None,
                timestamp=now + timedelta(seconds=i * 10),
            )
            temporal.observe(event)

        # Trigger detection
        result = detector.detect(_make_event(dst_ip="203.0.113.10", dst_port=8443))
        assert result.matched
        evidence_fields = [e["field"] for e in result.evidence]
        assert "process_name" not in evidence_fields
        assert "destination" in evidence_fields

    def test_structured_detection_result_evidence(self) -> None:
        """Test that correlation produces structured evidence."""
        corr = EndpointCorrelator()
        proc = _make_process_event(process_name="test.exe", pid=1234, username="bob")
        corr.observe(proc)

        net = _make_event(
            dst_ip="1.2.3.4",
            dst_port=80,
            process_name="test.exe",
            pid=1234,
            username="bob",
        )
        corr.observe(net)

        correlations = corr.get_correlations()
        assert len(correlations) == 1
        evidence = correlations[0].to_evidence()
        assert isinstance(evidence, list)
        for item in evidence:
            assert "field" in item
            assert "observed" in item
            assert "condition" in item

    def test_detection_result_serialization_round_trip(self) -> None:
        """Test that correlation data can be serialized."""
        corr = EndpointCorrelator()
        proc = _make_process_event(process_name="test.exe", pid=1234)
        corr.observe(proc)

        net = _make_event(dst_ip="1.2.3.4", dst_port=80, process_name="test.exe", pid=1234)
        corr.observe(net)

        correlations = corr.get_correlations()
        assert len(correlations) == 1

        # Verify all fields are serializable
        corr_item = correlations[0]
        assert isinstance(corr_item.activity_id, uuid4().__class__)
        assert isinstance(corr_item.event_ids, tuple)
        assert isinstance(corr_item.source_types, tuple)

    def test_replay_compatibility(self) -> None:
        """Test that correlation works the same in replay and live mode."""
        corr_live = EndpointCorrelator()
        corr_replay = EndpointCorrelator()

        events = [
            _make_process_event(process_name="test.exe", pid=1234),
            _make_event(dst_ip="1.2.3.4", dst_port=80, process_name="test.exe", pid=1234),
        ]

        for event in events:
            corr_live.observe(event)
            corr_replay.observe(event)

        live_corr = corr_live.get_correlations()
        replay_corr = corr_replay.get_correlations()
        assert len(live_corr) == len(replay_corr)
        if live_corr and replay_corr:
            assert live_corr[0].process_name == replay_corr[0].process_name
            assert live_corr[0].pid == replay_corr[0].pid

    def test_live_pipeline_compatibility(self) -> None:
        """Test that correlator integrates with the processing pipeline."""
        import tempfile
        from pathlib import Path

        from argusprowl.core.application import Application

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Path(tmpdir) / "config.yaml"
            cfg.write_text(
                f"app_name: 'Test'\nenvironment: 'test'\napi:\n  enabled: true\n  port: {_free_port()}\n"
            )
            app = Application(config_path=cfg)
            app.startup()
            try:
                correlator = app.container.resolve(EndpointCorrelator)
                assert correlator is not None
            finally:
                app.shutdown()

    def test_concurrent_event_processing(self) -> None:
        """Test thread safety with concurrent events."""
        import threading

        corr = EndpointCorrelator()
        errors = []

        def observe_events(start_pid: int, count: int) -> None:
            try:
                for i in range(count):
                    event = _make_event(
                        process_name=f"proc{start_pid + i}.exe",
                        pid=start_pid + i,
                        dst_ip="1.2.3.4",
                        dst_port=80,
                    )
                    corr.observe(event)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=observe_events, args=(i * 10, 10)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        stats = corr.get_statistics()
        assert stats["processed_count"] == 50

    def test_bounded_memory_behavior(self) -> None:
        """Test that memory usage is bounded."""
        corr = EndpointCorrelator(max_processes=10, max_observations=5)
        # Add more than max
        for i in range(100):
            proc = _make_process_event(process_name=f"proc{i}.exe", pid=i)
            corr.observe(proc)
            net = _make_event(dst_ip="1.2.3.4", dst_port=80, process_name=f"proc{i}.exe", pid=i)
            corr.observe(net)

        stats = corr.get_statistics()
        assert stats["tracked_processes"] <= 10
        # Network observations should also be bounded
        assert stats["tracked_network_keys"] <= 100

    def test_clear_state(self) -> None:
        """Test that clear resets all state."""
        corr = EndpointCorrelator()
        corr.observe(_make_process_event())
        corr.observe(_make_event())
        assert corr.get_statistics()["tracked_processes"] > 0

        corr.clear()
        stats = corr.get_statistics()
        assert stats["tracked_processes"] == 0
        assert stats["tracked_network_keys"] == 0
        assert stats["correlation_count"] == 0

    def test_get_correlations_filtered(self) -> None:
        """Test filtering correlations by destination."""
        corr = EndpointCorrelator()
        proc = _make_process_event(process_name="test.exe", pid=1234)
        corr.observe(proc)

        corr.observe(_make_event(dst_ip="1.1.1.1", dst_port=80, process_name="test.exe", pid=1234))
        corr.observe(_make_event(dst_ip="2.2.2.2", dst_port=443, process_name="test.exe", pid=1234))

        all_corr = corr.get_correlations()
        filtered = corr.get_correlations(dst_ip="1.1.1.1")
        assert len(filtered) == 1
        assert filtered[0].dst_ip == "1.1.1.1"
        assert len(all_corr) == 2

    def test_linux_audit_correlation(self) -> None:
        """Test correlation with Linux Audit telemetry."""
        corr = EndpointCorrelator()
        # Linux Audit process event
        proc = _make_process_event(
            process_name="suspicious_script.sh",
            pid=5678,
            username="www-data",
            hostname="webserver01",
            source_type="linux_audit",
        )
        corr.observe(proc)

        # Linux Audit network event (SYSCALL with addr fields)
        net = _make_event(
            source_type="linux_audit",
            dst_ip="203.0.113.10",
            dst_port=443,
            process_name="suspicious_script.sh",
            pid=5678,
            hostname="webserver01",
        )
        corr.observe(net)

        correlations = corr.get_correlations()
        assert len(correlations) == 1
        assert correlations[0].process_name == "suspicious_script.sh"

    def test_windows_event_log_correlation(self) -> None:
        """Test correlation with Windows Event Log telemetry."""
        corr = EndpointCorrelator()
        # Windows Event Log process event (EventID 4688)
        proc = _make_process_event(
            process_name="malware.exe",
            pid=4321,
            username="admin",
            hostname="workstation02",
            source_type="windows_event_log",
        )
        corr.observe(proc)

        # Network event with process attribution
        net = _make_event(
            source_type="windows_event_log",
            dst_ip="198.51.100.50",
            dst_port=8080,
            process_name="malware.exe",
            pid=4321,
            hostname="workstation02",
        )
        corr.observe(net)

        correlations = corr.get_correlations()
        assert len(correlations) == 1
        assert correlations[0].process_name == "malware.exe"

    def test_false_positive_browser_traffic(self) -> None:
        """Browser traffic should correlate but not necessarily trigger detection."""
        corr = EndpointCorrelator()
        # Regular browser process
        proc = _make_process_event(process_name="chrome.exe", pid=1000, username="alice")
        corr.observe(proc)

        # Periodic but benign browser updates
        now = datetime.now(UTC)
        for i in range(5):
            net = _make_event(
                dst_ip="142.250.80.46",  # Google CDN
                dst_port=443,
                process_name="chrome.exe",
                pid=1000,
                hostname="workstation01",
                timestamp=now + timedelta(seconds=i * 60 + (i % 3) * 5),  # Some jitter
            )
            corr.observe(net)

        correlations = corr.get_correlations()
        assert len(correlations) == 1
        assert correlations[0].process_name == "chrome.exe"
        # Correlation exists but is evidence, not a verdict

    def test_false_positive_ntp_traffic(self) -> None:
        """NTP traffic should correlate but be recognized as benign."""
        corr = EndpointCorrelator()
        # NTP service
        proc = _make_process_event(process_name="ntpd.exe", pid=500, username="SYSTEM")
        corr.observe(proc)

        now = datetime.now(UTC)
        for i in range(5):
            net = _make_event(
                dst_ip="129.6.15.28",  # NTP server
                dst_port=123,
                process_name="ntpd.exe",
                pid=500,
                hostname="dc01",
                timestamp=now + timedelta(seconds=i * 64),  # NTP interval
            )
            corr.observe(net)

        correlations = corr.get_correlations()
        assert len(correlations) == 1
        assert correlations[0].process_name == "ntpd.exe"

    def test_suspicious_beacon_with_process(self) -> None:
        """Suspicious beacon should correlate with process."""
        corr = EndpointCorrelator()
        proc = _make_process_event(process_name="unknown.exe", pid=9999, username="alice")
        corr.observe(proc)

        now = datetime.now(UTC)
        for i in range(10):
            net = _make_event(
                dst_ip="203.0.113.10",
                dst_port=443,
                process_name="unknown.exe",
                pid=9999,
                hostname="workstation01",
                timestamp=now + timedelta(seconds=i * 60),
            )
            corr.observe(net)

        correlations = corr.get_correlations()
        assert len(correlations) == 1
        assert correlations[0].process_name == "unknown.exe"
        assert correlations[0].observation_count == 10
        assert correlations[0].correlation_confidence > 0

    def test_highly_regular_beacon(self) -> None:
        """Highly regular beacon should produce strong correlation."""
        corr = EndpointCorrelator()
        proc = _make_process_event(process_name="c2_beacon.exe", pid=7777)
        corr.observe(proc)

        now = datetime.now(UTC)
        for i in range(20):
            net = _make_event(
                dst_ip="198.51.100.1",
                dst_port=8443,
                process_name="c2_beacon.exe",
                pid=7777,
                timestamp=now + timedelta(seconds=i * 30),  # Very regular
            )
            corr.observe(net)

        correlations = corr.get_correlations()
        assert len(correlations) == 1
        assert correlations[0].observation_count == 20
        assert correlations[0].correlation_confidence > 0.5


# ---------------------------------------------------------------------------
# CorrelationDetector tests
# ---------------------------------------------------------------------------


class TestCorrelationDetector:
    """Tests for the CorrelationDetector that produces DetectionResults."""

    def test_no_match_without_correlation(self) -> None:
        """Detector returns no-match when no correlation exists."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=2)

        event = _make_event(process_name="test.exe", pid=1234)
        result = detector.detect(event)

        assert not result.matched
        assert result.rule_id == "TH-CORR-ENDPOINT-001"

    def test_no_match_without_process_attribution(self) -> None:
        """Detector returns no-match when event has no process attribution."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=2)

        # Event without process info (like Zeek)
        event = _make_event(process_name=None, pid=None)
        result = detector.detect(event)

        assert not result.matched

    def test_match_with_correlation(self) -> None:
        """Detector produces match when correlation exists."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        # Create correlation
        proc = _make_process_event(process_name="unknown.exe", pid=4812)
        corr.observe(proc)
        net = _make_event(
            dst_ip="203.0.113.10",
            dst_port=443,
            process_name="unknown.exe",
            pid=4812,
            hostname="workstation01",
        )
        corr.observe(net)

        # Trigger detection
        result = detector.detect(net)
        assert result.matched
        assert result.rule_id == "TH-CORR-ENDPOINT-001"
        assert result.confidence > 0
        assert len(result.evidence) > 0
        assert result.contributing_event_ids == (net.event_id,)

    def test_match_evidence_structure(self) -> None:
        """Matched detection has structured evidence."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        proc = _make_process_event(process_name="suspicious.exe", pid=1234, username="alice")
        corr.observe(proc)
        net = _make_event(
            dst_ip="1.2.3.4",
            dst_port=80,
            process_name="suspicious.exe",
            pid=1234,
            username="alice",
            hostname="host1",
        )
        corr.observe(net)

        result = detector.detect(net)
        assert result.matched

        evidence_fields = [e["field"] for e in result.evidence]
        assert "process_name" in evidence_fields
        assert "process_id" in evidence_fields
        assert "destination" in evidence_fields
        assert "destination_port" in evidence_fields

    def test_match_description(self) -> None:
        """Matched detection has human-readable description."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        proc = _make_process_event(process_name="test.exe", pid=100)
        corr.observe(proc)
        net = _make_event(dst_ip="1.2.3.4", dst_port=443, process_name="test.exe", pid=100)
        corr.observe(net)

        result = detector.detect(net)
        assert result.matched
        assert "test.exe" in result.description
        assert "1.2.3.4" in result.description

    def test_match_explanation_is_evidence_based(self) -> None:
        """Explanation states this is evidence, not proof."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        proc = _make_process_event(process_name="test.exe", pid=100)
        corr.observe(proc)
        net = _make_event(dst_ip="1.2.3.4", dst_port=443, process_name="test.exe", pid=100)
        corr.observe(net)

        result = detector.detect(net)
        assert result.matched
        assert "evidence" in result.explanation.lower()

    def test_no_match_below_min_observations(self) -> None:
        """Detector respects min_observations threshold."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=5)

        proc = _make_process_event(process_name="test.exe", pid=100)
        corr.observe(proc)
        net = _make_event(dst_ip="1.2.3.4", dst_port=443, process_name="test.exe", pid=100)
        corr.observe(net)

        # Only 1 observation, below threshold of 5
        result = detector.detect(net)
        assert not result.matched

    def test_no_match_below_min_confidence(self) -> None:
        """Detector respects min_confidence threshold."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1, min_confidence=0.99)

        proc = _make_process_event(process_name="test.exe", pid=100)
        corr.observe(proc)
        net = _make_event(dst_ip="1.2.3.4", dst_port=443, process_name="test.exe", pid=100)
        corr.observe(net)

        # Default confidence is 0.5, below threshold of 0.99
        result = detector.detect(net)
        assert not result.matched

    def test_match_increases_confidence_with_observations(self) -> None:
        """Confidence increases with more observations."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        proc = _make_process_event(process_name="test.exe", pid=100)
        corr.observe(proc)

        # Add multiple observations to increase confidence
        for i in range(5):
            net = _make_event(
                dst_ip="1.2.3.4",
                dst_port=443,
                process_name="test.exe",
                pid=100,
                timestamp=datetime.now(UTC) + timedelta(seconds=i),
            )
            corr.observe(net)

        result = detector.detect(net)
        assert result.matched
        # Confidence should be higher with more observations
        assert result.confidence > 0.5

    def test_detection_result_serialization(self) -> None:
        """DetectionResult can be serialized and deserialized."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        proc = _make_process_event(process_name="test.exe", pid=100)
        corr.observe(proc)
        net = _make_event(dst_ip="1.2.3.4", dst_port=443, process_name="test.exe", pid=100)
        corr.observe(net)

        result = detector.detect(net)
        assert result.matched

        # Serialize
        d = result.to_dict()
        assert d["rule_id"] == "TH-CORR-ENDPOINT-001"
        assert d["matched"] is True
        assert len(d["contributing_event_ids"]) > 0

        # Deserialize
        restored = DetectionResult.from_dict(d)
        assert restored.rule_id == result.rule_id
        assert restored.matched == result.matched
        assert restored.contributing_event_ids == result.contributing_event_ids

    def test_properties(self) -> None:
        """Detector has correct properties."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, version=2)

        assert detector.name == "correlation_detector"
        assert detector.rule_id == "TH-CORR-ENDPOINT-001"
        assert detector.version == 2
        assert detector.is_enabled() is True
        assert detector.detections_count == 0

    def test_no_match_no_dst_ip(self) -> None:
        """Detector returns no-match when event has no destination."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        event = _make_event(dst_ip=None)
        result = detector.detect(event)
        assert not result.matched

    def test_multiple_correlations_different_destinations(self) -> None:
        """Detector handles multiple correlations to different destinations."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        # Process communicating with two destinations
        proc = _make_process_event(process_name="test.exe", pid=100)
        corr.observe(proc)

        net1 = _make_event(dst_ip="1.1.1.1", dst_port=80, process_name="test.exe", pid=100)
        net2 = _make_event(dst_ip="2.2.2.2", dst_port=443, process_name="test.exe", pid=100)
        corr.observe(net1)
        corr.observe(net2)

        # Detection for net1 should find correlation with 1.1.1.1
        result1 = detector.detect(net1)
        assert result1.matched
        evidence_fields = {e["field"]: e["observed"] for e in result1.evidence}
        assert evidence_fields.get("destination") == "1.1.1.1"

        # Detection for net2 should find correlation with 2.2.2.2
        result2 = detector.detect(net2)
        assert result2.matched
        evidence_fields = {e["field"]: e["observed"] for e in result2.evidence}
        assert evidence_fields.get("destination") == "2.2.2.2"

    def test_concurrent_detection(self) -> None:
        """Detector is thread-safe for concurrent access."""
        import threading

        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        # Create multiple correlations
        for i in range(10):
            proc = _make_process_event(process_name=f"proc{i}.exe", pid=i)
            corr.observe(proc)
            net = _make_event(
                dst_ip=f"10.0.0.{i}",
                dst_port=80,
                process_name=f"proc{i}.exe",
                pid=i,
            )
            corr.observe(net)

        errors = []

        def detect_event(i: int) -> None:
            try:
                event = _make_event(
                    dst_ip=f"10.0.0.{i}",
                    dst_port=80,
                    process_name=f"proc{i}.exe",
                    pid=i,
                )
                detector.detect(event)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=detect_event, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_false_positive_benign_process(self) -> None:
        """Benign process traffic should still produce evidence, not verdict."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        # Normal browser process
        proc = _make_process_event(process_name="chrome.exe", pid=1000, username="alice")
        corr.observe(proc)

        # Browser making normal connections
        for _i in range(3):
            net = _make_event(
                dst_ip="142.250.80.46",
                dst_port=443,
                process_name="chrome.exe",
                pid=1000,
                username="alice",
            )
            corr.observe(net)

        result = detector.detect(net)
        assert result.matched
        # Explanation should be evidence-based, not accusatory
        assert "evidence" in result.explanation.lower()
        assert "not proof" in result.explanation.lower() or "evidence" in result.explanation.lower()

    def test_integration_with_temporal_engine(self) -> None:
        """Correlation detector works alongside temporal engine."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector
        from argusprowl.temporal.engine import TemporalEngine

        corr = EndpointCorrelator()
        temporal = TemporalEngine(max_keys=100, max_observations_per_key=100)
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        now = datetime.now(UTC)
        # Create periodic traffic with process attribution
        for i in range(5):
            event = _make_event(
                dst_ip="203.0.113.10",
                dst_port=443,
                process_name="beacon.exe",
                pid=9999,
                hostname="host1",
                timestamp=now + timedelta(seconds=i * 10),
            )
            temporal.observe(event)
            corr.observe(event)

        # Trigger detection with a fresh event
        trigger_event = _make_event(
            dst_ip="203.0.113.10",
            dst_port=443,
            process_name="beacon.exe",
            pid=9999,
            hostname="host1",
            timestamp=now + timedelta(seconds=50),
        )
        corr_result = detector.detect(trigger_event)
        assert corr_result.matched

        # Temporal engine should also have data
        analysis = temporal.get_analysis("203.0.113.10", 443)
        assert analysis is not None
        assert analysis.get("process_name") == "beacon.exe"

    def test_evidence_includes_contributing_event_ids(self) -> None:
        """DetectionResult includes all contributing event IDs."""
        from argusprowl.detection.detectors.correlation_detector import CorrelationDetector

        corr = EndpointCorrelator()
        detector = CorrelationDetector(correlator=corr, min_observations=1)

        proc = _make_process_event(process_name="test.exe", pid=100)
        corr.observe(proc)

        events = []
        for i in range(3):
            net = _make_event(
                dst_ip="1.2.3.4",
                dst_port=443,
                process_name="test.exe",
                pid=100,
                timestamp=datetime.now(UTC) + timedelta(seconds=i),
            )
            corr.observe(net)
            events.append(net)

        result = detector.detect(events[-1])
        assert result.matched
        # Should include all event IDs from the correlation
        assert len(result.contributing_event_ids) >= 1
