"""Unit tests for Environmental Prevalence Tracker (Phase 4.6B)."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from argusprowl.intelligence.prevalence import EnvironmentPrevalenceTracker
from argusprowl.models.normalized_event import NormalizedEvent


def test_basic_counting() -> None:
    """Verify unique host counting for destinations."""
    tracker = EnvironmentPrevalenceTracker(min_observations=0, rare_threshold=3)

    tracker.record_connection(hostname="HostA", dst_ip="203.0.113.10", dst_port=8443)
    tracker.record_connection(hostname="HostB", dst_ip="203.0.113.10", dst_port=8443)

    res = tracker.get_prevalence(dst_ip="203.0.113.10", dst_port=8443)
    assert res.dest_host_count == 2
    assert res.is_rare_destination is True
    assert res.is_environment_wide is False


def test_repeated_host() -> None:
    """Verify repeated connections from the same host do not inflate host count."""
    tracker = EnvironmentPrevalenceTracker(min_observations=0)

    for _ in range(5):
        tracker.record_connection(hostname="HostA", dst_ip="203.0.113.10", dst_port=8443)

    res = tracker.get_prevalence(dst_ip="203.0.113.10", dst_port=8443)
    assert res.dest_host_count == 1


def test_multiple_processes() -> None:
    """Verify process+destination host counting."""
    tracker = EnvironmentPrevalenceTracker(min_observations=0)

    tracker.record_connection(
        hostname="HostA", dst_ip="203.0.113.10", dst_port=8443, process_name="powershell.exe"
    )
    tracker.record_connection(
        hostname="HostB", dst_ip="203.0.113.10", dst_port=8443, process_name="powershell.exe"
    )
    tracker.record_connection(
        hostname="HostC", dst_ip="203.0.113.10", dst_port=8443, process_name="cmd.exe"
    )

    res_ps = tracker.get_prevalence(
        dst_ip="203.0.113.10", dst_port=8443, process_name="powershell.exe"
    )
    assert res_ps.dest_host_count == 3
    assert res_ps.process_dest_count == 2

    res_cmd = tracker.get_prevalence(dst_ip="203.0.113.10", dst_port=8443, process_name="cmd.exe")
    assert res_cmd.dest_host_count == 3
    assert res_cmd.process_dest_count == 1


def test_rare_destination_boundaries() -> None:
    """Verify rare destination threshold logic."""
    tracker = EnvironmentPrevalenceTracker(min_observations=0, rare_threshold=3)

    # 2 hosts: threshold - 1 => rare
    tracker.record_connection(hostname="HostA", dst_ip="198.51.100.1")
    tracker.record_connection(hostname="HostB", dst_ip="198.51.100.1")
    assert tracker.get_prevalence(dst_ip="198.51.100.1").is_rare_destination is True

    # Add 3rd host: threshold => not rare
    tracker.record_connection(hostname="HostC", dst_ip="198.51.100.1")
    assert tracker.get_prevalence(dst_ip="198.51.100.1").is_rare_destination is False


def test_environment_wide_boundaries() -> None:
    """Verify environment-wide threshold logic."""
    tracker = EnvironmentPrevalenceTracker(min_observations=0, environment_wide_threshold=5)

    for i in range(4):
        tracker.record_connection(hostname=f"Host{i}", dst_ip="10.0.0.1", dst_port=443)
    assert tracker.get_prevalence(dst_ip="10.0.0.1", dst_port=443).is_environment_wide is False

    tracker.record_connection(hostname="Host4", dst_ip="10.0.0.1", dst_port=443)
    assert tracker.get_prevalence(dst_ip="10.0.0.1", dst_port=443).is_environment_wide is True


def test_multiple_destinations_isolation() -> None:
    """Ensure distinct destinations do not cross-contaminate."""
    tracker = EnvironmentPrevalenceTracker(min_observations=0)

    tracker.record_connection(hostname="HostA", dst_ip="192.0.2.1")
    tracker.record_connection(hostname="HostB", dst_ip="192.0.2.2")

    assert tracker.get_prevalence(dst_ip="192.0.2.1").dest_host_count == 1
    assert tracker.get_prevalence(dst_ip="192.0.2.2").dest_host_count == 1


def test_duplicate_delivery() -> None:
    """Verify duplicate telemetry events with same event_id or source_record_id are ignored."""
    tracker = EnvironmentPrevalenceTracker(min_observations=0)
    eid = uuid4()
    now = datetime.now(UTC)

    tracker.record_connection(
        hostname="HostA",
        dst_ip="203.0.113.5",
        event_id=eid,
        source_record_id="zeek-uid-123",
        timestamp=now,
    )
    # Duplicate delivery
    tracker.record_connection(
        hostname="HostA",
        dst_ip="203.0.113.5",
        event_id=eid,
        source_record_id="zeek-uid-123",
        timestamp=now,
    )

    res = tracker.get_prevalence(dst_ip="203.0.113.5")
    assert res.dest_host_count == 1


def test_expiration() -> None:
    """Verify old observations expire after window_duration."""
    tracker = EnvironmentPrevalenceTracker(
        min_observations=0,
        window_duration=timedelta(minutes=10),
    )
    base_time = datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC)

    tracker.record_connection(hostname="HostA", dst_ip="203.0.113.10", timestamp=base_time)
    tracker.record_connection(
        hostname="HostB", dst_ip="203.0.113.10", timestamp=base_time + timedelta(minutes=5)
    )

    # Query at T+5m -> both active
    res1 = tracker.get_prevalence(dst_ip="203.0.113.10", timestamp=base_time + timedelta(minutes=5))
    assert res1.dest_host_count == 2

    # Query at T+11m -> HostA (T+0m) expired
    res2 = tracker.get_prevalence(
        dst_ip="203.0.113.10", timestamp=base_time + timedelta(minutes=11)
    )
    assert res2.dest_host_count == 1


def test_capacity_eviction() -> None:
    """Verify LRU capacity eviction for destinations and host limit bounding."""
    tracker = EnvironmentPrevalenceTracker(
        max_destinations=2,
        max_hosts_per_key=2,
        min_observations=0,
    )

    tracker.record_connection(hostname="HostA", dst_ip="10.0.0.1")
    tracker.record_connection(hostname="HostA", dst_ip="10.0.0.2")

    # Add 3rd destination -> 10.0.0.1 evicted
    tracker.record_connection(hostname="HostA", dst_ip="10.0.0.3")

    assert len(tracker) == 2
    assert tracker.get_prevalence(dst_ip="10.0.0.1").dest_host_count == 0
    assert tracker.get_prevalence(dst_ip="10.0.0.2").dest_host_count == 1
    assert tracker.get_prevalence(dst_ip="10.0.0.3").dest_host_count == 1


def test_cold_start_protection() -> None:
    """Verify cold start protection prevents premature rarity flags."""
    tracker = EnvironmentPrevalenceTracker(min_observations=5, rare_threshold=3)

    # 2 observations total (below min_observations = 5)
    tracker.record_connection(hostname="HostA", dst_ip="203.0.113.99")
    tracker.record_connection(hostname="HostB", dst_ip="203.0.113.99")

    res_cold = tracker.get_prevalence(dst_ip="203.0.113.99")
    assert res_cold.dest_host_count == 2
    assert res_cold.is_rare_destination is False  # Warmup protected

    # Record 3 more connections to cross min_observations = 5
    for i in range(3):
        tracker.record_connection(hostname=f"OtherHost{i}", dst_ip="10.0.0.100")

    res_warm = tracker.get_prevalence(dst_ip="203.0.113.99")
    assert res_warm.dest_host_count == 2
    assert res_warm.is_rare_destination is True  # Now rare after warmup


def test_record_event_integration() -> None:
    """Verify record_event with NormalizedEvent."""
    tracker = EnvironmentPrevalenceTracker(min_observations=0)
    event = NormalizedEvent(
        source_type="zeek",
        event_type="conn",
        hostname="workstation-01",
        src_ip="192.168.1.50",
        dst_ip="203.0.113.50",
        dst_port=8443,
        process_name="svchost.exe",
        attributes={"domain": "c2.example.com"},
    )

    tracker.record_event(event)

    res_ip = tracker.get_prevalence(
        dst_ip="203.0.113.50", dst_port=8443, process_name="svchost.exe"
    )
    assert res_ip.dest_host_count == 1
    assert res_ip.process_dest_count == 1

    res_dom = tracker.get_prevalence(domain="c2.example.com", dst_port=8443)
    assert res_dom.dest_host_count == 1


def test_port_separation() -> None:
    """Verify dst_port differentiates services on the same IP."""
    tracker = EnvironmentPrevalenceTracker(min_observations=0)

    tracker.record_connection(hostname="HostA", dst_ip="203.0.113.10", dst_port=443)
    tracker.record_connection(hostname="HostB", dst_ip="203.0.113.10", dst_port=8443)

    assert tracker.get_prevalence(dst_ip="203.0.113.10", dst_port=443).dest_host_count == 1
    assert tracker.get_prevalence(dst_ip="203.0.113.10", dst_port=8443).dest_host_count == 1


def test_clear_and_validation() -> None:
    """Verify clear() resets state and init validates arguments."""
    tracker = EnvironmentPrevalenceTracker()
    tracker.record_connection(src_ip="192.168.1.1", dst_ip="1.1.1.1")
    assert tracker.total_observations == 1
    assert len(tracker) == 1

    tracker.clear()
    assert tracker.total_observations == 0
    assert len(tracker) == 0

    with pytest.raises(ValueError, match="Capacity limits"):
        EnvironmentPrevalenceTracker(max_destinations=0)

    with pytest.raises(ValueError, match="Thresholds"):
        EnvironmentPrevalenceTracker(rare_threshold=0)

    with pytest.raises(ValueError, match="min_observations"):
        EnvironmentPrevalenceTracker(min_observations=-1)
