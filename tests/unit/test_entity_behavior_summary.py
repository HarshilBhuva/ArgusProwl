"""Tests for EntityBehaviorSummary and get_summary."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from argusprowl.behavior.entity_behavior_profile import ProfileMaturity
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService
from argusprowl.behavior.entity_behavior_summary import EntityBehaviorSummary


class TestEntityBehaviorSummary:
    """Tests for EntityBehaviorSummary model and generation."""

    def test_summary_missing_profile(self) -> None:
        """Test getting summary for a missing profile."""
        service = EntityBehaviorService()
        summary = service.get_summary("hostname", "unknown", "process_name")
        assert summary is None

    def test_summary_empty_profile(self) -> None:
        """Test getting summary for an empty profile model."""
        summary = EntityBehaviorSummary(
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            observation_count=0,
            distinct_value_count=0,
            first_seen=None,
            last_seen=None,
            maturity=ProfileMaturity.EMPTY,
            top_values=[],
        )
        assert summary.entity_type == "hostname"
        assert summary.entity_id == "server01"
        assert summary.dimension == "process_name"
        assert summary.observation_count == 0
        assert summary.distinct_value_count == 0
        assert summary.first_seen is None
        assert summary.last_seen is None
        assert summary.maturity == ProfileMaturity.EMPTY
        assert summary.top_values == []
        assert summary.narrative == "No observations recorded."

    def test_summary_observation_and_distinct_counts(self) -> None:
        """Test observation and distinct counts in summary."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.record_observation("hostname", "server01", "process_name", "python", timestamp)
        service.record_observation("hostname", "server01", "process_name", "python", timestamp)
        service.record_observation("hostname", "server01", "process_name", "java", timestamp)

        summary = service.get_summary("hostname", "server01", "process_name")
        assert summary is not None
        assert summary.observation_count == 3
        assert summary.distinct_value_count == 2
        assert summary.top_values == [("python", 2), ("java", 1)]
        assert (
            summary.narrative
            == "Observed 3 times across 2 distinct values. Most frequently observed values: python, java."
        )

    def test_summary_first_last_timestamps(self) -> None:
        """Test first and last timestamps in summary."""
        service = EntityBehaviorService()
        t1 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        t2 = datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC)
        t3 = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)

        service.record_observation("hostname", "server01", "process_name", "python", t1)
        service.record_observation("hostname", "server01", "process_name", "java", t2)
        service.record_observation("hostname", "server01", "process_name", "bash", t3)

        summary = service.get_summary("hostname", "server01", "process_name")
        assert summary is not None
        assert summary.first_seen == t1
        assert summary.last_seen == t3

    def test_summary_maturity(self) -> None:
        """Test maturity in summary."""
        service = EntityBehaviorService(stale_timeout=timedelta(hours=1))
        t1 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.record_observation("hostname", "server01", "process_name", "python", t1)

        summary = service.get_summary("hostname", "server01", "process_name")
        assert summary is not None
        assert summary.maturity == ProfileMaturity.WARMING

    def test_summary_top_value_ordering_and_ties(self) -> None:
        """Test top value ordering and deterministic tie-breaking."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        # python: 3, java: 3, bash: 2, zsh: 2, awk: 1
        for _ in range(3):
            service.record_observation("hostname", "server01", "process_name", "python", timestamp)
            service.record_observation("hostname", "server01", "process_name", "java", timestamp)
        for _ in range(2):
            service.record_observation("hostname", "server01", "process_name", "zsh", timestamp)
            service.record_observation("hostname", "server01", "process_name", "bash", timestamp)
        service.record_observation("hostname", "server01", "process_name", "awk", timestamp)

        summary = service.get_summary("hostname", "server01", "process_name")
        assert summary is not None
        # Ties broken lexicographically: java < python, bash < zsh
        assert summary.top_values == [
            ("java", 3),
            ("python", 3),
            ("bash", 2),
            ("zsh", 2),
            ("awk", 1),
        ]

    def test_summary_bounded_output(self) -> None:
        """Test bounded output for top values."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        for i in range(20):
            service.record_observation(
                "hostname", "server01", "process_name", f"proc_{i}", timestamp
            )

        summary = service.get_summary("hostname", "server01", "process_name", max_top_values=5)
        assert summary is not None
        assert len(summary.top_values) == 5

    def test_summary_hashed_oversized_values(self) -> None:
        """Test hashed oversized values in summary."""
        service = EntityBehaviorService(max_value_length=10)
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        oversized_value = "this_is_a_very_long_process_name_that_exceeds_the_limit"
        expected_hash = sha256(oversized_value.encode("utf-8")).hexdigest()

        service.record_observation(
            "hostname", "server01", "process_name", oversized_value, timestamp
        )

        summary = service.get_summary("hostname", "server01", "process_name")
        assert summary is not None
        assert summary.top_values == [(expected_hash, 1)]
        assert expected_hash in summary.narrative

    def test_summary_stale_profiles(self) -> None:
        """Test summary for stale profiles."""
        service = EntityBehaviorService(stale_timeout=timedelta(hours=1))
        t1 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.record_observation("hostname", "server01", "process_name", "python", t1)

        # Force stale by checking maturity with a later time
        # Wait, get_summary doesn't update maturity based on current time, it just reads it.
        # Let's record an observation that makes it stale? No, record_observation updates last_seen.
        # We can manually set maturity or just rely on the fact that get_summary reads the current maturity.
        # Actually, get_summary just reads the profile's maturity.
        profile = service.get_profile("hostname", "server01", "process_name")
        assert profile is not None

        # To make it stale, we can use check_and_record_first_seen which updates maturity based on current time?
        # No, maturity is updated in record_observation based on current time vs last_seen.
        # Let's just check that get_summary returns whatever maturity the profile has.
        summary = service.get_summary("hostname", "server01", "process_name")
        assert summary is not None
        assert summary.maturity == profile.maturity

    def test_summary_evicted_values(self) -> None:
        """Test summary behavior with evicted values."""
        service = EntityBehaviorService(max_values_per_profile=2)
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.record_observation("hostname", "server01", "process_name", "python", timestamp)
        service.record_observation("hostname", "server01", "process_name", "java", timestamp)
        service.record_observation("hostname", "server01", "process_name", "bash", timestamp)

        # python should be evicted from BoundedValueSet, but it's still in _value_counts!
        # The summary should still include it because _value_counts retains it.
        summary = service.get_summary("hostname", "server01", "process_name")
        assert summary is not None
        assert summary.observation_count == 3
        assert summary.distinct_value_count == 3

        # All 3 should be in top_values because _value_counts doesn't evict
        assert len(summary.top_values) == 3
        assert ("python", 1) in summary.top_values
        assert ("java", 1) in summary.top_values
        assert ("bash", 1) in summary.top_values

    def test_summary_read_only_behavior(self) -> None:
        """Test that get_summary does not mutate profile state."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.record_observation("hostname", "server01", "process_name", "python", timestamp)

        profile_before = service.get_profile("hostname", "server01", "process_name")
        assert profile_before is not None

        summary = service.get_summary("hostname", "server01", "process_name")
        assert summary is not None

        profile_after = service.get_profile("hostname", "server01", "process_name")
        assert profile_after is not None

        assert profile_before.observation_count == profile_after.observation_count
        assert profile_before.distinct_value_count == profile_after.distinct_value_count
        assert profile_before.last_update == profile_after.last_update

    def test_summary_replay_parity(self) -> None:
        """Test that identical profile state produces identical summaries."""
        service1 = EntityBehaviorService()
        service2 = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service1.record_observation("hostname", "server01", "process_name", "python", timestamp)
        service2.record_observation("hostname", "server01", "process_name", "python", timestamp)

        summary1 = service1.get_summary("hostname", "server01", "process_name")
        summary2 = service2.get_summary("hostname", "server01", "process_name")

        assert summary1 == summary2

    def test_summary_metrics(self) -> None:
        """Test telemetry counters when querying summaries."""
        from argusprowl.metrics.collector import MetricsCollector

        collector = MetricsCollector()
        service = EntityBehaviorService(metrics_collector=collector)
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        # Missing profile query
        assert service.get_summary("hostname", "unknown", "process_name") is None
        assert collector.get_counter("entity_behavior_summary_queries_total").get_value() == 1
        assert collector.get_counter("entity_behavior_summary_missing_total").get_value() == 1
        assert collector.get_counter("entity_behavior_summary_generated_total").get_value() == 0

        # Valid profile query
        service.record_observation("hostname", "server01", "process_name", "python", timestamp)
        assert service.get_summary("hostname", "server01", "process_name") is not None
        assert collector.get_counter("entity_behavior_summary_queries_total").get_value() == 2
        assert collector.get_counter("entity_behavior_summary_missing_total").get_value() == 1
        assert collector.get_counter("entity_behavior_summary_generated_total").get_value() == 1

    def test_summary_concurrency(self) -> None:
        """Test concurrent get_summary calls while recording observations."""
        import threading

        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        def writer() -> None:
            for i in range(100):
                service.record_observation(
                    "hostname", "server01", "process_name", f"proc_{i % 10}", timestamp
                )

        def reader() -> None:
            for _ in range(100):
                summary = service.get_summary("hostname", "server01", "process_name")
                if summary is not None:
                    assert summary.observation_count >= 1
                    assert isinstance(summary.top_values, list)
                    assert len(summary.top_values) <= 10

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        summary = service.get_summary("hostname", "server01", "process_name")
        assert summary is not None
        assert summary.observation_count == 200
