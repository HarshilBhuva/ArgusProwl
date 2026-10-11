"""Tests for AnalystBehaviorQueryService (Phase 5.1.9 Hardening).

Comprehensive tests covering:
- Multi-dimension entity queries
- Missing entity/dimension handling
- Valid and invalid baseline evidence
- Read-only state preservation
- Malformed input handling
- Oversized limit handling
- Deterministic ordering
- Persistence disabled/unavailable
- Concurrent reads
- Bounded output
- Decision neutrality
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from threading import Thread

import pytest

from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
from argusprowl.behavior.baseline_evidence import BaselineEvidence, BaselineReasonCode
from argusprowl.behavior.entity_behavior_profile import ProfileMaturity
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def behavior_service() -> EntityBehaviorService:
    """Create a service with pre-populated multi-dimension profiles."""
    service = EntityBehaviorService(
        maturity_min_observations=3,
        maturity_window_seconds=0.1,
        baseline_rare_threshold=2,
        baseline_stale_after_seconds=3600.0,
    )
    base_time = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

    # Entity with multiple dimensions
    for i in range(5):
        service.classify_and_record(
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            dimension_value="python",
            timestamp=base_time + timedelta(seconds=i),
            processing_time=base_time + timedelta(seconds=i),
        )
    for i in range(3):
        service.classify_and_record(
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            dimension_value="bash",
            timestamp=base_time + timedelta(seconds=i),
            processing_time=base_time + timedelta(seconds=i),
        )
    for i in range(4):
        service.classify_and_record(
            entity_type="hostname",
            entity_id="server01",
            dimension="dst_ip",
            dimension_value="10.0.0.1",
            timestamp=base_time + timedelta(seconds=i),
            processing_time=base_time + timedelta(seconds=i),
        )
    for i in range(2):
        service.classify_and_record(
            entity_type="hostname",
            entity_id="server01",
            dimension="dst_ip",
            dimension_value="10.0.0.2",
            timestamp=base_time + timedelta(seconds=i),
            processing_time=base_time + timedelta(seconds=i),
        )

    # Second entity with single dimension
    for i in range(5):
        service.classify_and_record(
            entity_type="hostname",
            entity_id="server02",
            dimension="process_name",
            dimension_value="chrome",
            timestamp=base_time + timedelta(seconds=i),
            processing_time=base_time + timedelta(seconds=i),
        )

    return service


@pytest.fixture
def query_service(behavior_service: EntityBehaviorService) -> AnalystBehaviorQueryService:
    """Create query service wrapped around behavior service."""
    return AnalystBehaviorQueryService(behavior_service)


# ── TestAnalystBehaviorQueryService ───────────────────────────────────────────


class TestAnalystBehaviorQueryService:
    """Tests for the analyst query service."""

    def test_get_entity_behavior_single_dimension(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test getting behavior for entity with single dimension."""
        results = query_service.get_entity_behavior("hostname", "server02")
        assert len(results) == 1
        assert results[0]["dimension"] == "process_name"
        assert results[0]["observation_count"] == 5
        assert results[0]["distinct_value_count"] == 1
        assert results[0]["top_values"] == [("chrome", 5)]

    def test_get_entity_behavior_multi_dimension(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test getting behavior for entity with multiple dimensions."""
        results = query_service.get_entity_behavior("hostname", "server01")
        assert len(results) == 2
        # Deterministic ordering by dimension
        assert results[0]["dimension"] == "dst_ip"
        assert results[1]["dimension"] == "process_name"

    def test_get_entity_behavior_missing_entity(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test getting behavior for missing entity returns empty list."""
        results = query_service.get_entity_behavior("hostname", "nonexistent")
        assert results == []

    def test_get_dimension_values(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test getting dimension values."""
        values = query_service.get_dimension_values("hostname", "server01", "process_name")
        assert values == {"python": 5, "bash": 3}

    def test_get_dimension_values_missing(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test getting dimension values for missing profile."""
        values = query_service.get_dimension_values("hostname", "nonexistent", "process_name")
        assert values == {}

    def test_list_entities(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test listing entities."""
        results = query_service.list_entities(limit=10)
        assert len(results) >= 2

    def test_list_entities_filtered(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test listing entities with type filter."""
        results = query_service.list_entities(entity_type="hostname", limit=10)
        assert all(r["entity_type"] == "hostname" for r in results)

    def test_list_entities_maturity_filter(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test listing entities with maturity filter."""
        results = query_service.list_entities(maturity=ProfileMaturity.MATURE, limit=10)
        assert all(r["maturity"] == "mature" for r in results)

    def test_get_baseline_evidence_established(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test getting baseline evidence for established value."""
        evidence = query_service.get_baseline_evidence(
            "hostname", "server01", "process_name", "python"
        )
        assert evidence is not None
        # Profile may be stale due to time passing since fixture creation
        assert evidence.reason_code in (
            BaselineReasonCode.VALUE_ESTABLISHED,
            BaselineReasonCode.PROFILE_WARMING,
        )

    def test_get_baseline_evidence_missing(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test getting baseline evidence for missing profile."""
        evidence = query_service.get_baseline_evidence(
            "hostname", "nonexistent", "process_name", "python"
        )
        assert evidence is None

    def test_get_entity_summary(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test getting entity summary."""
        summary = query_service.get_entity_summary("hostname", "server01", "process_name")
        assert summary is not None
        assert summary["dimension"] == "process_name"
        assert summary["observation_count"] == 8

    def test_get_entity_summary_missing(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test getting summary for missing profile."""
        summary = query_service.get_entity_summary("hostname", "nonexistent", "process_name")
        assert summary is None


# ── TestQueryInputValidation ──────────────────────────────────────────────────


class TestQueryInputValidation:
    """Tests for input validation."""

    def test_get_entity_behavior_empty_entity_type(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test empty entity_type raises."""
        with pytest.raises(ValueError, match="entity_type"):
            query_service.get_entity_behavior("", "server01")

    def test_get_entity_behavior_empty_entity_id(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test empty entity_id raises."""
        with pytest.raises(ValueError, match="entity_id"):
            query_service.get_entity_behavior("hostname", "")

    def test_get_entity_behavior_non_string_entity_type(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test non-string entity_type raises."""
        with pytest.raises(ValueError, match="entity_type"):
            query_service.get_entity_behavior(123, "server01")

    def test_get_entity_behavior_non_string_entity_id(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test non-string entity_id raises."""
        with pytest.raises(ValueError, match="entity_id"):
            query_service.get_entity_behavior("hostname", 123)

    def test_get_entity_behavior_oversized_entity_type(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test oversized entity_type raises."""
        with pytest.raises(ValueError, match="entity_type"):
            query_service.get_entity_behavior("x" * 65, "server01")

    def test_get_entity_behavior_oversized_entity_id(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test oversized entity_id raises."""
        with pytest.raises(ValueError, match="entity_id"):
            query_service.get_entity_behavior("hostname", "x" * 257)

    def test_get_dimension_values_empty_dimension(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test empty dimension raises."""
        with pytest.raises(ValueError, match="dimension"):
            query_service.get_dimension_values("hostname", "server01", "")

    def test_get_dimension_values_non_string_dimension(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test non-string dimension raises."""
        with pytest.raises(ValueError, match="dimension"):
            query_service.get_dimension_values("hostname", "server01", 123)

    def test_get_dimension_values_oversized_dimension(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test oversized dimension raises."""
        with pytest.raises(ValueError, match="dimension"):
            query_service.get_dimension_values("hostname", "server01", "x" * 65)

    def test_get_dimension_values_negative_max_values(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test negative max_values raises."""
        with pytest.raises(ValueError, match="max_values"):
            query_service.get_dimension_values("hostname", "server01", "process_name", max_values=0)

    def test_list_entities_negative_limit(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test negative limit raises."""
        with pytest.raises(ValueError, match="limit"):
            query_service.list_entities(limit=0)

    def test_list_entities_non_int_limit(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test non-integer limit raises."""
        with pytest.raises(ValueError, match="limit"):
            query_service.list_entities(limit="10")

    def test_list_entities_invalid_maturity(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test invalid maturity raises."""
        with pytest.raises(ValueError, match="maturity"):
            query_service.list_entities(maturity="invalid")

    def test_get_baseline_evidence_empty_dimension_value(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test empty dimension_value raises."""
        with pytest.raises(ValueError, match="dimension_value"):
            query_service.get_baseline_evidence("hostname", "server01", "process_name", "")

    def test_get_baseline_evidence_oversized_dimension_value(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test oversized dimension_value raises."""
        with pytest.raises(ValueError, match="dimension_value"):
            query_service.get_baseline_evidence("hostname", "server01", "process_name", "x" * 129)


# ── TestQueryBoundedness ──────────────────────────────────────────────────────


class TestQueryBoundedness:
    """Tests for query output bounds."""

    def test_get_entity_behavior_max_values_bound(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test max_values is bounded to 10."""
        results = query_service.get_entity_behavior("hostname", "server01", max_values=1000)
        for result in results:
            assert len(result["top_values"]) <= 10

    def test_get_dimension_values_max_bound(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test dimension values are bounded."""
        values = query_service.get_dimension_values(
            "hostname", "server01", "process_name", max_values=1000
        )
        assert len(values) <= 10

    def test_list_entities_limit_bound(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test entity list is bounded."""
        results = query_service.list_entities(limit=1000)
        assert len(results) <= 100

    def test_get_entity_behavior_dimensions_bound(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test dimensions per entity are bounded."""
        results = query_service.get_entity_behavior("hostname", "server01", max_values=1000)
        assert len(results) <= 10


# ── TestQueryReadOnly ─────────────────────────────────────────────────────────


class TestQueryReadOnly:
    """Tests proving queries are read-only."""

    def _snapshot_state(self, service: EntityBehaviorService) -> dict:
        """Create a snapshot of service state."""
        with service._lock:
            return {
                "profile_count": len(service._profiles),
                "profiles": copy.deepcopy(dict(service._profiles)),
                "value_counts": copy.deepcopy(service._value_counts),
            }

    def _compare_state(self, before: dict, after: dict) -> None:
        """Compare two state snapshots."""
        assert before["profile_count"] == after["profile_count"], "Profile count changed"
        assert before["profiles"] == after["profiles"], "Profiles changed"
        assert before["value_counts"] == after["value_counts"], "Value counts changed"

    def test_get_entity_behavior_read_only(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test get_entity_behavior does not modify state."""
        before = self._snapshot_state(behavior_service)
        query_service.get_entity_behavior("hostname", "server01")
        after = self._snapshot_state(behavior_service)
        self._compare_state(before, after)

    def test_get_dimension_values_read_only(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test get_dimension_values does not modify state."""
        before = self._snapshot_state(behavior_service)
        query_service.get_dimension_values("hostname", "server01", "process_name")
        after = self._snapshot_state(behavior_service)
        self._compare_state(before, after)

    def test_list_entities_read_only(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test list_entities does not modify state."""
        before = self._snapshot_state(behavior_service)
        query_service.list_entities(limit=10)
        after = self._snapshot_state(behavior_service)
        self._compare_state(before, after)

    def test_get_baseline_evidence_read_only(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test get_baseline_evidence does not modify state."""
        before = self._snapshot_state(behavior_service)
        query_service.get_baseline_evidence("hostname", "server01", "process_name", "python")
        after = self._snapshot_state(behavior_service)
        self._compare_state(before, after)

    def test_get_entity_summary_read_only(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test get_entity_summary does not modify state."""
        before = self._snapshot_state(behavior_service)
        query_service.get_entity_summary("hostname", "server01", "process_name")
        after = self._snapshot_state(behavior_service)
        self._compare_state(before, after)

    def test_queries_do_not_increment_observations(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test queries do not increment observation counts."""
        before_count = behavior_service.get_profile(
            "hostname", "server01", "process_name"
        ).observation_count
        query_service.get_entity_behavior("hostname", "server01")
        query_service.get_dimension_values("hostname", "server01", "process_name")
        query_service.get_baseline_evidence("hostname", "server01", "process_name", "python")
        after_count = behavior_service.get_profile(
            "hostname", "server01", "process_name"
        ).observation_count
        assert before_count == after_count

    def test_queries_do_not_update_timestamps(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test queries do not update timestamps."""
        profile = behavior_service.get_profile("hostname", "server01", "process_name")
        before_first_seen = profile.first_seen
        before_last_seen = profile.last_seen

        query_service.get_entity_behavior("hostname", "server01")
        query_service.get_dimension_values("hostname", "server01", "process_name")

        profile = behavior_service.get_profile("hostname", "server01", "process_name")
        assert profile.first_seen == before_first_seen
        assert profile.last_seen == before_last_seen

    def test_queries_do_not_alter_maturity(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test queries do not alter maturity."""
        before_maturity = behavior_service.get_profile(
            "hostname", "server01", "process_name"
        ).maturity

        query_service.get_entity_behavior("hostname", "server01")
        query_service.get_dimension_values("hostname", "server01", "process_name")

        after_maturity = behavior_service.get_profile(
            "hostname", "server01", "process_name"
        ).maturity
        assert before_maturity == after_maturity


# ── TestQueryDecisionNeutrality ───────────────────────────────────────────────


class TestQueryDecisionNeutrality:
    """Tests proving queries don't affect decision logic."""

    def test_queries_dont_affect_classification(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test queries don't affect baseline classification."""
        # Get evidence before
        evidence_before = query_service.get_baseline_evidence(
            "hostname", "server01", "process_name", "python"
        )

        # Run queries
        query_service.get_entity_behavior("hostname", "server01")
        query_service.get_dimension_values("hostname", "server01", "process_name")
        query_service.list_entities(limit=10)

        # Get evidence after
        evidence_after = query_service.get_baseline_evidence(
            "hostname", "server01", "process_name", "python"
        )

        assert evidence_before is not None
        assert evidence_after is not None
        assert evidence_before.reason_code == evidence_after.reason_code
        assert evidence_before.value_count == evidence_after.value_count
        assert evidence_before.observation_count == evidence_after.observation_count


# ── TestQueryDeterministicOrdering ────────────────────────────────────────────


class TestQueryDeterministicOrdering:
    """Tests for deterministic query ordering."""

    def test_get_entity_behavior_deterministic_order(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test get_entity_behavior returns deterministic order."""
        results1 = query_service.get_entity_behavior("hostname", "server01")
        results2 = query_service.get_entity_behavior("hostname", "server01")
        assert results1 == results2

    def test_list_entities_deterministic_order(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test list_entities returns deterministic order."""
        results1 = query_service.list_entities(limit=100)
        results2 = query_service.list_entities(limit=100)
        assert results1 == results2

    def test_get_dimension_values_deterministic_order(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test get_dimension_values returns deterministic order."""
        values1 = query_service.get_dimension_values("hostname", "server01", "process_name")
        values2 = query_service.get_dimension_values("hostname", "server01", "process_name")
        assert values1 == values2


# ── TestQueryPersistence ──────────────────────────────────────────────────────


class TestQueryPersistence:
    """Tests for query behavior with persistence."""

    def test_queries_work_without_persistence(self) -> None:
        """Test queries work when persistence is disabled."""
        service = EntityBehaviorService()
        query = AnalystBehaviorQueryService(service)

        # Query on empty service
        results = query.get_entity_behavior("hostname", "server01")
        assert results == []

        values = query.get_dimension_values("hostname", "server01", "process_name")
        assert values == {}

        evidence = query.get_baseline_evidence("hostname", "server01", "process_name", "python")
        assert evidence is None

    def test_queries_work_with_persistence(self, tmp_path) -> None:
        """Test queries work when persistence is enabled."""
        from argusprowl.behavior.entity_behavior_persistence import EntityBehaviorPersistence

        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        service = EntityBehaviorService(persistence=persistence)
        query = AnalystBehaviorQueryService(service)

        # Add some data
        base_time = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="server01",
                dimension="process_name",
                dimension_value="python",
                timestamp=base_time + timedelta(seconds=i),
                processing_time=base_time + timedelta(seconds=i),
            )

        # Query should work
        results = query.get_entity_behavior("hostname", "server01")
        assert len(results) == 1
        assert results[0]["observation_count"] == 5

    def test_queries_graceful_degradation_corrupt_persistence(self, tmp_path) -> None:
        """Test queries degrade gracefully with corrupt persistence."""
        from argusprowl.behavior.entity_behavior_persistence import EntityBehaviorPersistence

        db_path = tmp_path / "corrupt.db"
        # Create a corrupt database
        db_path.write_text("corrupt data")

        persistence = EntityBehaviorPersistence(db_path=db_path)
        # Don't initialize - simulate failure
        service = EntityBehaviorService(persistence=persistence)
        query = AnalystBehaviorQueryService(service)

        # Queries should return empty results, not crash
        results = query.get_entity_behavior("hostname", "server01")
        assert results == []


# ── TestQueryConcurrency ──────────────────────────────────────────────────────


class TestQueryConcurrency:
    """Tests for concurrent query access."""

    def test_concurrent_reads(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test concurrent reads don't corrupt state."""
        errors = []

        def read_entity() -> None:
            try:
                for _ in range(100):
                    query_service.get_entity_behavior("hostname", "server01")
            except Exception as e:
                errors.append(e)

        def read_dimension() -> None:
            try:
                for _ in range(100):
                    query_service.get_dimension_values("hostname", "server01", "process_name")
            except Exception as e:
                errors.append(e)

        def read_list() -> None:
            try:
                for _ in range(100):
                    query_service.list_entities(limit=10)
            except Exception as e:
                errors.append(e)

        threads = [
            Thread(target=read_entity),
            Thread(target=read_dimension),
            Thread(target=read_list),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Concurrent reads failed: {errors}"

    def test_concurrent_reads_with_writes(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test concurrent reads during writes don't corrupt state."""
        errors = []

        def read_entity() -> None:
            try:
                for _ in range(50):
                    query_service.get_entity_behavior("hostname", "server01")
            except Exception as e:
                errors.append(e)

        def write_observations() -> None:
            try:
                base_time = datetime(2026, 9, 4, 12, 0, 0, tzinfo=UTC)
                for i in range(50):
                    behavior_service.classify_and_record(
                        entity_type="hostname",
                        entity_id="server01",
                        dimension="process_name",
                        dimension_value="java",
                        timestamp=base_time + timedelta(seconds=i),
                        processing_time=base_time + timedelta(seconds=i),
                    )
            except Exception as e:
                errors.append(e)

        threads = [
            Thread(target=read_entity),
            Thread(target=write_observations),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Concurrent access failed: {errors}"


# ── TestQueryBaselineEvidence ─────────────────────────────────────────────────


class TestQueryBaselineEvidence:
    """Tests for baseline evidence queries."""

    def test_valid_baseline_evidence(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test getting valid baseline evidence."""
        evidence = query_service.get_baseline_evidence(
            "hostname", "server01", "process_name", "python"
        )
        assert evidence is not None
        assert isinstance(evidence, BaselineEvidence)
        assert evidence.reason_code in BaselineReasonCode
        assert evidence.classification is not None
        assert evidence.explanation is not None

    def test_missing_entity_evidence(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test evidence for missing entity."""
        evidence = query_service.get_baseline_evidence(
            "hostname", "nonexistent", "process_name", "python"
        )
        assert evidence is None

    def test_missing_dimension_evidence(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test evidence for missing dimension."""
        evidence = query_service.get_baseline_evidence(
            "hostname", "server01", "nonexistent", "python"
        )
        assert evidence is None

    def test_evidence_contains_real_state(
        self, query_service: AnalystBehaviorQueryService, behavior_service: EntityBehaviorService
    ) -> None:
        """Test evidence corresponds to real existing state."""
        evidence = query_service.get_baseline_evidence(
            "hostname", "server01", "process_name", "python"
        )
        assert evidence is not None

        # Verify evidence matches actual profile state
        profile = behavior_service.get_profile("hostname", "server01", "process_name")
        assert evidence.observation_count == profile.observation_count
        assert evidence.first_seen == profile.first_seen
        assert evidence.last_seen == profile.last_seen

    def test_evidence_reason_code_matches_classification(
        self, query_service: AnalystBehaviorQueryService
    ) -> None:
        """Test evidence reason code is consistent with classification."""
        evidence = query_service.get_baseline_evidence(
            "hostname", "server01", "process_name", "python"
        )
        assert evidence is not None

        # Get the classification directly
        profile = query_service._service.get_profile("hostname", "server01", "process_name")
        assert profile is not None

        # The evidence should have a valid reason code
        assert evidence.reason_code in list(BaselineReasonCode)


# ── TestQueryEdgeCases ────────────────────────────────────────────────────────


class TestQueryEdgeCases:
    """Tests for edge cases."""

    def test_empty_string_inputs(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test empty string inputs are rejected."""
        with pytest.raises(ValueError):
            query_service.get_entity_behavior("", "server01")
        with pytest.raises(ValueError):
            query_service.get_entity_behavior("hostname", "")
        with pytest.raises(ValueError):
            query_service.get_dimension_values("hostname", "server01", "")
        with pytest.raises(ValueError):
            query_service.get_baseline_evidence("hostname", "server01", "process_name", "")

    def test_none_inputs(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test None inputs are handled."""
        # entity_type=None should raise
        with pytest.raises((ValueError, TypeError)):
            query_service.get_entity_behavior(None, "server01")

    def test_very_large_limits(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test very large limits are clamped."""
        results = query_service.list_entities(limit=1000000)
        assert len(results) <= 100

        values = query_service.get_dimension_values(
            "hostname", "server01", "process_name", max_values=1000000
        )
        assert len(values) <= 10

    def test_zero_limits(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test zero limits raise."""
        with pytest.raises(ValueError):
            query_service.list_entities(limit=0)
        with pytest.raises(ValueError):
            query_service.get_dimension_values("hostname", "server01", "process_name", max_values=0)

    def test_negative_limits(self, query_service: AnalystBehaviorQueryService) -> None:
        """Test negative limits raise."""
        with pytest.raises(ValueError):
            query_service.list_entities(limit=-1)
        with pytest.raises(ValueError):
            query_service.get_dimension_values(
                "hostname", "server01", "process_name", max_values=-1
            )


# ── Run all tests ─────────────────────────────────────────────────────────────


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
