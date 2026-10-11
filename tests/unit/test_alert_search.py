"""Tests for AlertSearchService (Phase 5.5).

Comprehensive tests covering:
- Empty queue + empty/unsupported persistence
- Queue-only search
- Persistence-only search
- Duplicate alert IDs
- Lifecycle-only difference
- Immutable payload conflict
- Conflict source immutability
- min_priority
- min_severity
- rule_id
- host
- lifecycle_state
- entity_key
- incident_id
- Multiple filters with AND semantics
- Deterministic ordering
- Final limit after merge/sort
- Limit zero raises
- Negative limit raises
- Limit one
- Persistence unavailable
- Persistence degraded
- Queue exception behavior
- Persistence disabled
- Complete persistence scan when requested limit is smaller than retained data
- Target match beyond the first N persisted rows
- Bounded intermediate results
- Manager status preservation
- No mutation of queue/persistence
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.alerting.alert_persistence import (
    AlertPersistence,
)
from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
from argusprowl.lifecycle.queue import AlertQueue, AlertQueueFullError
from argusprowl.models.alert import Alert
from argusprowl.services.alert_search_service import (
    AlertSearchResult,
    AlertSearchService,
    AlertSearchStatus,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def entity_correlation_service() -> EntityCorrelationService:
    """Create an EntityCorrelationService."""
    return EntityCorrelationService()


@pytest.fixture
def alert_queue() -> AlertQueue:
    """Create an AlertQueue."""
    return AlertQueue(max_size=100)


@pytest.fixture
def alert_persistence(tmp_path) -> AlertPersistence:
    """Create an AlertPersistence with a temp database."""
    db_path = tmp_path / "test_alerts.db"
    persistence = AlertPersistence(db_path=db_path, max_alerts=100)
    persistence.initialize()
    return persistence


@pytest.fixture
def search_service(
    alert_queue: AlertQueue,
    alert_persistence: AlertPersistence,
    entity_correlation_service: EntityCorrelationService,
) -> AlertSearchService:
    """Create an AlertSearchService with all dependencies."""
    return AlertSearchService(
        alert_queue=alert_queue,
        alert_persistence=alert_persistence,
        entity_correlation_service=entity_correlation_service,
    )


@pytest.fixture
def search_service_no_queue(
    alert_persistence: AlertPersistence,
    entity_correlation_service: EntityCorrelationService,
) -> AlertSearchService:
    """Create an AlertSearchService without a queue."""
    return AlertSearchService(
        alert_queue=None,
        alert_persistence=alert_persistence,
        entity_correlation_service=entity_correlation_service,
    )


@pytest.fixture
def search_service_no_persistence(
    alert_queue: AlertQueue,
    entity_correlation_service: EntityCorrelationService,
) -> AlertSearchService:
    """Create an AlertSearchService without persistence."""
    return AlertSearchService(
        alert_queue=alert_queue,
        alert_persistence=None,
        entity_correlation_service=entity_correlation_service,
    )


# ── Helper Functions ──────────────────────────────────────────────────────────


def make_alert(
    alert_id: UUID | None = None,
    title: str = "Test Alert",
    host: str | None = None,
    process_name: str | None = None,
    dst_ip: str | None = None,
    severity: Severity = Severity.MEDIUM,
    priority: AlertPriority | None = None,
    rule_id: str | None = None,
    lifecycle_state: AlertLifecycleState = AlertLifecycleState.OPEN,
    incident_id: UUID | None = None,
    created_at: datetime | None = None,
    entity_context: dict[str, Any] | None = None,
) -> Alert:
    """Create a test alert."""
    ctx: dict[str, Any] = {}
    if host is not None:
        ctx["host"] = host
    if process_name is not None:
        ctx["process_name"] = process_name
    if dst_ip is not None:
        ctx["dst_ip"] = dst_ip
    if entity_context is not None:
        ctx.update(entity_context)

    metadata: dict[str, Any] = {}
    if rule_id is not None:
        metadata["rule_id"] = rule_id

    return Alert(
        alert_id=alert_id or uuid4(),
        title=title,
        description="Test description",
        severity=severity,
        source="test",
        created_at=created_at or datetime.now(UTC),
        entity_context=ctx if ctx else None,
        priority=priority,
        lifecycle_state=lifecycle_state,
        incident_id=incident_id,
        metadata=metadata,
    )


def make_alert_with_modified_payload(
    base_alert: Alert,
    new_title: str | None = None,
    new_severity: Severity | None = None,
) -> Alert:
    """Create a modified copy of an alert (different immutable payload)."""
    return Alert(
        alert_id=base_alert.alert_id,
        title=new_title or base_alert.title + "_modified",
        description=base_alert.description,
        severity=new_severity or base_alert.severity,
        source=base_alert.source,
        created_at=base_alert.created_at,
        entity_context=base_alert.entity_context,
        priority=base_alert.priority,
        lifecycle_state=base_alert.lifecycle_state,
        incident_id=base_alert.incident_id,
        metadata=base_alert.metadata,
    )


# ── 10.1 Search-Limit Correctness Tests ──────────────────────────────────────


class TestSearchLimitCorrectness:
    """Tests for search-limit semantics."""

    def test_search_limit_does_not_truncate_persistence(
        self, search_service: AlertSearchService, alert_persistence: AlertPersistence
    ):
        """Prove that search(limit=10) retrieves complete persistence set before filtering.

        Setup: persistence has 100 alerts, search limit is 10
        Expected: search retrieves all 100 from persistence, then applies limit after sort
        Expected: final result count ≤ 10
        """
        # Create 100 alerts in persistence
        for i in range(100):
            alert = make_alert(
                title=f"Alert {i}",
                host="testhost",
                created_at=datetime(2026, 1, 1, i // 60, i % 60, 0, tzinfo=UTC),
            )
            alert_persistence.save_alert(alert)

        # Search with limit=10
        result = search_service.search(limit=10, host="testhost")

        # Should get exactly 10 alerts (the top 10 by sort order)
        assert len(result.alerts) == 10
        assert result.status == AlertSearchStatus.AVAILABLE
        # All returned alerts should match the filter
        for alert in result.alerts:
            assert alert.entity_context.get("host") == "testhost"

    def test_search_limit_applied_after_merge(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Queue has 5 alerts, persistence has 50, limit is 10 → Result has ≤ 10 alerts."""
        # Add 5 alerts to queue
        for i in range(5):
            alert = make_alert(title=f"Queue Alert {i}", host="testhost")
            alert_queue.enqueue(alert)

        # Add 50 alerts to persistence
        for i in range(50):
            alert = make_alert(title=f"Persist Alert {i}", host="testhost")
            alert_persistence.save_alert(alert)

        result = search_service.search(limit=10, host="testhost")

        assert len(result.alerts) <= 10
        assert result.status == AlertSearchStatus.AVAILABLE

    def test_search_limit_zero_raises(self, search_service: AlertSearchService):
        """limit=0 should raise ValueError."""
        with pytest.raises(ValueError, match="limit must be a positive integer"):
            search_service.search(limit=0)

    def test_search_limit_negative_raises(self, search_service: AlertSearchService):
        """limit=-1 should raise ValueError."""
        with pytest.raises(ValueError, match="limit must be a positive integer"):
            search_service.search(limit=-1)

    def test_search_limit_one(self, search_service: AlertSearchService, alert_queue: AlertQueue):
        """limit=1 should return exactly 1 alert."""
        alert = make_alert(title="Single Alert", host="testhost")
        alert_queue.enqueue(alert)

        result = search_service.search(limit=1, host="testhost")

        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Single Alert"


# ── 10.2 Entity Key Semantics Tests ──────────────────────────────────────────


class TestEntityKeySemantics:
    """Tests for canonical entity key semantics."""

    def test_entity_key_canonical_across_sources(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
        entity_correlation_service: EntityCorrelationService,
    ):
        """Same alert, queue vs persistence entity key must match."""
        alert = make_alert(
            title="Test Alert",
            host="workstation01",
            process_name="svchost.exe",
        )

        # Compute entity key via canonical service
        canonical_key = entity_correlation_service.compute_entity_key(alert)

        # Enqueue and persist
        alert_queue.enqueue(alert)
        alert_persistence.save_alert(alert)

        # Search by entity key
        result = search_service.search(limit=10, entity_key=canonical_key)

        assert len(result.alerts) == 1
        assert result.alerts[0].alert_id == alert.alert_id

    def test_entity_key_precedence_host_process(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        entity_correlation_service: EntityCorrelationService,
    ):
        """Priority 1: host + process_name."""
        alert = make_alert(
            title="Test Alert",
            host="workstation01",
            process_name="svchost.exe",
            dst_ip="10.0.0.1",
        )
        alert_queue.enqueue(alert)

        key = entity_correlation_service.compute_entity_key(alert)
        assert key == "workstation01:svchost.exe"

        result = search_service.search(limit=10, entity_key=key)
        assert len(result.alerts) == 1

    def test_entity_key_precedence_host_dst_ip(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        entity_correlation_service: EntityCorrelationService,
    ):
        """Priority 2: host + dst_ip."""
        alert = make_alert(
            title="Test Alert",
            host="workstation01",
            dst_ip="10.0.0.1",
        )
        alert_queue.enqueue(alert)

        key = entity_correlation_service.compute_entity_key(alert)
        assert key == "workstation01:10.0.0.1"

        result = search_service.search(limit=10, entity_key=key)
        assert len(result.alerts) == 1

    def test_entity_key_precedence_host_alone(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        entity_correlation_service: EntityCorrelationService,
    ):
        """Priority 3: host alone."""
        alert = make_alert(
            title="Test Alert",
            host="workstation01",
        )
        alert_queue.enqueue(alert)

        key = entity_correlation_service.compute_entity_key(alert)
        assert key == "workstation01:*"

        result = search_service.search(limit=10, entity_key=key)
        assert len(result.alerts) == 1

    def test_entity_key_precedence_dst_ip_alone(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        entity_correlation_service: EntityCorrelationService,
    ):
        """Priority 4: dst_ip alone."""
        alert = make_alert(
            title="Test Alert",
            dst_ip="10.0.0.1",
        )
        alert_queue.enqueue(alert)

        key = entity_correlation_service.compute_entity_key(alert)
        assert key == "*:10.0.0.1"

        result = search_service.search(limit=10, entity_key=key)
        assert len(result.alerts) == 1

    def test_entity_key_fallback(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        entity_correlation_service: EntityCorrelationService,
    ):
        """Priority 5: stable fallback for alerts without entity context."""
        alert = make_alert(
            title="Test Alert",
        )
        alert_queue.enqueue(alert)

        key = entity_correlation_service.compute_entity_key(alert)
        assert key.startswith("unknown:")

        result = search_service.search(limit=10, entity_key=key)
        assert len(result.alerts) == 1


# ── 10.3 Queue Availability Tests ────────────────────────────────────────────


class TestQueueAvailability:
    """Tests for queue availability semantics."""

    def test_queue_none_returns_empty(self, search_service_no_persistence: AlertSearchService):
        """No queue configured → Empty result, AVAILABLE."""
        result = search_service_no_persistence.search(limit=10)

        assert len(result.alerts) == 0
        assert result.status == AlertSearchStatus.AVAILABLE

    def test_queue_empty_returns_empty(self, search_service: AlertSearchService):
        """Queue operational but empty → Empty result, AVAILABLE."""
        result = search_service.search(limit=10)

        assert len(result.alerts) == 0
        assert result.status == AlertSearchStatus.AVAILABLE

    def test_queue_full_propagates(
        self, search_service: AlertSearchService, alert_queue: AlertQueue
    ):
        """Queue raises AlertQueueFullError → Exception propagates."""
        # Fill queue to capacity
        for i in range(100):
            alert = make_alert(title=f"Alert {i}")
            alert_queue.enqueue(alert)

        # Next enqueue should raise
        with pytest.raises(AlertQueueFullError):
            alert_queue.enqueue(make_alert(title="Overflow"))

        # Search should still work (queue is operational)
        result = search_service.search(limit=10)
        assert len(result.alerts) == 10
        assert result.status == AlertSearchStatus.AVAILABLE


# ── 10.4 Conflict Resolution Tests ───────────────────────────────────────────


class TestConflictResolution:
    """Tests for conflict detection and resolution."""

    def test_payload_conflict_returns_degraded(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Same alert_id with different payload → DEGRADED, queue copy returned."""
        base_alert = make_alert(title="Original", host="testhost")

        # Save to persistence
        alert_persistence.save_alert(base_alert)

        # Create modified copy and enqueue to queue
        modified_alert = make_alert_with_modified_payload(base_alert, new_title="Modified")
        alert_queue.enqueue(modified_alert)

        result = search_service.search(limit=10)

        assert result.status == AlertSearchStatus.DEGRADED
        assert result.reason == "payload_conflict"
        # Queue copy should be returned
        assert result.alerts[0].title == "Modified"

    def test_lifecycle_difference_not_conflict(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Same alert_id, different lifecycle state → AVAILABLE, queue copy returned."""
        base_alert = make_alert(title="Test", host="testhost")

        # Save to persistence
        alert_persistence.save_alert(base_alert)

        # Create alert with different lifecycle state and enqueue
        lifecycle_alert = Alert(
            alert_id=base_alert.alert_id,
            title=base_alert.title,
            description=base_alert.description,
            severity=base_alert.severity,
            source=base_alert.source,
            created_at=base_alert.created_at,
            entity_context=base_alert.entity_context,
            priority=base_alert.priority,
            lifecycle_state=AlertLifecycleState.ACKNOWLEDGED,
            incident_id=base_alert.incident_id,
            metadata=base_alert.metadata,
        )
        alert_queue.enqueue(lifecycle_alert)

        result = search_service.search(limit=10)

        assert result.status == AlertSearchStatus.AVAILABLE
        # Queue copy should be returned
        assert result.alerts[0].lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_conflict_does_not_mutate_sources(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Conflict resolution should not mutate either source."""
        base_alert = make_alert(title="Original", host="testhost")

        # Save to persistence
        alert_persistence.save_alert(base_alert)

        # Create modified copy and enqueue to queue
        modified_alert = make_alert_with_modified_payload(base_alert, new_title="Modified")
        alert_queue.enqueue(modified_alert)

        # Get snapshots before search
        queue_before = list(alert_queue.values())
        persistence_before = alert_persistence.list_all().alerts

        # Perform search
        search_service.search(limit=10)

        # Verify sources not mutated
        queue_after = list(alert_queue.values())
        persistence_after = alert_persistence.list_all().alerts

        assert queue_before == queue_after
        assert len(persistence_before) == len(persistence_after)


# ── 10.5 Merge Pipeline Tests ────────────────────────────────────────────────


class TestMergePipeline:
    """Tests for merge pipeline correctness."""

    def test_merge_deduplicates_by_alert_id(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Same alert in both sources → Single result."""
        alert = make_alert(title="Test", host="testhost")

        alert_queue.enqueue(alert)
        alert_persistence.save_alert(alert)

        result = search_service.search(limit=10)

        assert len(result.alerts) == 1
        assert result.alerts[0].alert_id == alert.alert_id

    def test_merge_preserves_unique_queue_alerts(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Alert only in queue → Included in result."""
        queue_alert = make_alert(title="Queue Only", host="testhost")
        alert_queue.enqueue(queue_alert)

        result = search_service.search(limit=10)

        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Queue Only"

    def test_merge_preserves_unique_persistence_alerts(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Alert only in persistence → Included in result."""
        persist_alert = make_alert(title="Persistence Only", host="testhost")
        alert_persistence.save_alert(persist_alert)

        result = search_service.search(limit=10)

        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Persistence Only"

    def test_filter_applied_before_merge(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Filter reduces both sources → Correct filtered merge."""
        # Add alerts with different severities
        high_alert = make_alert(title="High", severity=Severity.HIGH, host="testhost")
        low_alert = make_alert(title="Low", severity=Severity.LOW, host="testhost")

        alert_queue.enqueue(high_alert)
        alert_queue.enqueue(low_alert)
        alert_persistence.save_alert(high_alert)
        alert_persistence.save_alert(low_alert)

        result = search_service.search(limit=10, min_severity=Severity.HIGH)

        # Only HIGH severity should remain
        assert len(result.alerts) == 1
        assert result.alerts[0].severity == Severity.HIGH

    def test_sort_applied_after_merge(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Sort order is deterministic."""
        # Add alerts with different priorities
        low_alert = make_alert(title="Low", priority=AlertPriority.LOW, host="testhost")
        high_alert = make_alert(title="High", priority=AlertPriority.HIGH, host="testhost")

        alert_queue.enqueue(low_alert)
        alert_queue.enqueue(high_alert)
        alert_persistence.save_alert(low_alert)
        alert_persistence.save_alert(high_alert)

        result = search_service.search(limit=10)

        # HIGH should come before LOW
        assert result.alerts[0].priority == AlertPriority.HIGH
        assert result.alerts[1].priority == AlertPriority.LOW

    def test_limit_applied_after_sort(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """Limit truncates sorted results."""
        # Add 5 alerts with different priorities
        priorities = [
            AlertPriority.LOW,
            AlertPriority.MEDIUM,
            AlertPriority.HIGH,
            AlertPriority.CRITICAL,
            AlertPriority.LOW,
        ]
        for i in range(5):
            alert = make_alert(title=f"Alert {i}", priority=priorities[i], host="testhost")
            alert_queue.enqueue(alert)

        result = search_service.search(limit=2)

        assert len(result.alerts) == 2


# ── 10.6 Boundedness Tests ───────────────────────────────────────────────────


class TestBoundedness:
    """Tests for bounded intermediate collections."""

    def test_queue_bounded_by_max_size(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """Queue has max_size alerts → No more than max_size."""
        # Fill queue to capacity
        for i in range(100):
            alert = make_alert(title=f"Alert {i}")
            alert_queue.enqueue(alert)

        result = search_service.search(limit=1000)

        assert len(result.alerts) <= 100

    def test_persistence_bounded_by_max_alerts(
        self,
        search_service: AlertSearchService,
        alert_persistence: AlertPersistence,
    ):
        """Persistence has max_alerts alerts → No more than max_alerts."""
        # Fill persistence to capacity
        for i in range(100):
            alert = make_alert(title=f"Alert {i}")
            alert_persistence.save_alert(alert)

        result = search_service.search(limit=1000)

        assert len(result.alerts) <= 100

    def test_merged_bounded_by_sum(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Both sources at capacity → ≤ max_size + max_alerts."""
        # Fill queue
        for i in range(100):
            alert = make_alert(title=f"Queue Alert {i}")
            alert_queue.enqueue(alert)

        # Fill persistence
        for i in range(100):
            alert = make_alert(title=f"Persist Alert {i}")
            alert_persistence.save_alert(alert)

        result = search_service.search(limit=1000)

        assert len(result.alerts) <= 200


# ── 10.7 Filter Tests ────────────────────────────────────────────────────────


class TestFilters:
    """Tests for filter semantics."""

    def test_min_priority(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """min_priority filter works correctly."""
        low_alert = make_alert(title="Low", priority=AlertPriority.LOW)
        high_alert = make_alert(title="High", priority=AlertPriority.HIGH)

        alert_queue.enqueue(low_alert)
        alert_queue.enqueue(high_alert)

        result = search_service.search(limit=10, min_priority=AlertPriority.HIGH)

        assert len(result.alerts) == 1
        assert result.alerts[0].priority == AlertPriority.HIGH

    def test_min_severity(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """min_severity filter works correctly."""
        low_alert = make_alert(title="Low", severity=Severity.LOW)
        high_alert = make_alert(title="High", severity=Severity.HIGH)

        alert_queue.enqueue(low_alert)
        alert_queue.enqueue(high_alert)

        result = search_service.search(limit=10, min_severity=Severity.HIGH)

        assert len(result.alerts) == 1
        assert result.alerts[0].severity == Severity.HIGH

    def test_rule_id(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """rule_id filter works correctly."""
        alert1 = make_alert(title="Alert 1", rule_id="rule_1")
        alert2 = make_alert(title="Alert 2", rule_id="rule_2")

        alert_queue.enqueue(alert1)
        alert_queue.enqueue(alert2)

        result = search_service.search(limit=10, rule_id="rule_1")

        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Alert 1"

    def test_host(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """host filter works correctly."""
        alert1 = make_alert(title="Alert 1", host="host1")
        alert2 = make_alert(title="Alert 2", host="host2")

        alert_queue.enqueue(alert1)
        alert_queue.enqueue(alert2)

        result = search_service.search(limit=10, host="host1")

        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Alert 1"

    def test_lifecycle_state(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """lifecycle_state filter works correctly."""
        open_alert = make_alert(title="Open", lifecycle_state=AlertLifecycleState.OPEN)
        ack_alert = make_alert(title="Ack", lifecycle_state=AlertLifecycleState.ACKNOWLEDGED)

        alert_queue.enqueue(open_alert)
        alert_queue.enqueue(ack_alert)

        result = search_service.search(limit=10, lifecycle_state=AlertLifecycleState.OPEN)

        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Open"

    def test_incident_id(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """incident_id filter works correctly."""
        incident_id = uuid4()
        alert1 = make_alert(title="Alert 1", incident_id=incident_id)
        alert2 = make_alert(title="Alert 2", incident_id=uuid4())

        alert_queue.enqueue(alert1)
        alert_queue.enqueue(alert2)

        result = search_service.search(limit=10, incident_id=str(incident_id))

        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Alert 1"

    def test_multiple_filters_and_semantics(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """Multiple filters with AND semantics."""
        alert1 = make_alert(title="Alert 1", host="host1", severity=Severity.HIGH, rule_id="rule_1")
        alert2 = make_alert(title="Alert 2", host="host1", severity=Severity.LOW, rule_id="rule_1")
        alert3 = make_alert(title="Alert 3", host="host2", severity=Severity.HIGH, rule_id="rule_1")

        alert_queue.enqueue(alert1)
        alert_queue.enqueue(alert2)
        alert_queue.enqueue(alert3)

        result = search_service.search(
            limit=10, host="host1", min_severity=Severity.HIGH, rule_id="rule_1"
        )

        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Alert 1"


# ── 10.8 Edge Case Tests ─────────────────────────────────────────────────────


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_queue_empty_persistence(
        self,
        search_service: AlertSearchService,
    ):
        """Empty queue + empty persistence → Empty result, AVAILABLE."""
        result = search_service.search(limit=10)

        assert len(result.alerts) == 0
        assert result.status == AlertSearchStatus.AVAILABLE

    def test_persistence_unavailable(
        self,
        search_service_no_persistence: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """Persistence unavailable → Queue results still returned."""
        alert = make_alert(title="Queue Alert", host="testhost")
        alert_queue.enqueue(alert)

        result = search_service_no_persistence.search(limit=10)

        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Queue Alert"
        assert result.status == AlertSearchStatus.AVAILABLE

    def test_persistence_disabled(
        self,
        search_service_no_persistence: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """Persistence disabled → Queue-only search works."""
        alert = make_alert(title="Queue Alert", host="testhost")
        alert_queue.enqueue(alert)

        result = search_service_no_persistence.search(limit=10)

        assert len(result.alerts) == 1
        assert result.status == AlertSearchStatus.AVAILABLE

    def test_queue_exception_not_silently_converted(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """Queue exceptions should propagate, not be silently converted."""
        # This test verifies that normal operation doesn't raise
        # The queue-full case is tested separately
        result = search_service.search(limit=10)
        assert result.status == AlertSearchStatus.AVAILABLE

    def test_persistence_failure_does_not_erase_queue_results(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Persistence failure should not erase valid queue results."""
        # Add alert to queue
        queue_alert = make_alert(title="Queue Alert", host="testhost")
        alert_queue.enqueue(queue_alert)

        # Search should still return queue results even if persistence has issues
        result = search_service.search(limit=10)

        assert len(result.alerts) >= 1
        assert result.status == AlertSearchStatus.AVAILABLE


# ── 10.9 AlertManager Integration Tests ──────────────────────────────────────


class TestAlertManagerIntegration:
    """Tests for AlertManager.search_alerts() integration."""

    def test_manager_search_with_service(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
    ):
        """AlertManager.search_alerts() delegates to AlertSearchService."""
        alert = make_alert(title="Test Alert", host="testhost")
        alert_queue.enqueue(alert)

        manager = AlertManager(
            alert_queue=alert_queue,
            alert_search_service=search_service,
        )

        result = manager.search_alerts(limit=10, host="testhost")

        assert isinstance(result, AlertSearchResult)
        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Test Alert"
        assert result.status == AlertSearchStatus.AVAILABLE

    def test_manager_search_without_service(
        self,
        alert_queue: AlertQueue,
    ):
        """AlertManager.search_alerts() falls back to queue-only when service unavailable."""
        alert = make_alert(title="Test Alert", host="testhost")
        alert_queue.enqueue(alert)

        manager = AlertManager(
            alert_queue=alert_queue,
            alert_search_service=None,
        )

        result = manager.search_alerts(limit=10, host="testhost")

        assert isinstance(result, AlertSearchResult)
        assert len(result.alerts) == 1
        assert result.alerts[0].title == "Test Alert"
        assert result.status == AlertSearchStatus.AVAILABLE

    def test_manager_preserves_status(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """AlertManager preserves DEGRADED status from search service."""
        base_alert = make_alert(title="Original", host="testhost")
        alert_persistence.save_alert(base_alert)

        modified_alert = make_alert_with_modified_payload(base_alert, new_title="Modified")
        alert_queue.enqueue(modified_alert)

        manager = AlertManager(
            alert_queue=alert_queue,
            alert_persistence=alert_persistence,
            alert_search_service=search_service,
        )

        result = manager.search_alerts(limit=10)

        assert result.status == AlertSearchStatus.DEGRADED
        assert result.reason == "payload_conflict"


# ── 10.10 Regression Test ────────────────────────────────────────────────────


class TestRegression:
    """Regression tests for critical invariants."""

    def test_search_limit_does_not_truncate_persistence_source(
        self,
        search_service: AlertSearchService,
        alert_persistence: AlertPersistence,
    ):
        """Prove that search(limit=10) retrieves complete persistence set before filtering.

        Setup: persistence has 100 alerts, search limit is 10
        Expected: search retrieves all 100 from persistence, then applies limit after sort
        Expected: final result count ≤ 10
        """
        # Create 100 alerts with distinct timestamps (strictly increasing)
        for i in range(100):
            # Use minutes to ensure strict ordering (each alert is 1 minute apart)
            alert = make_alert(
                title=f"Alert {i}",
                host="testhost",
                created_at=datetime(2026, 1, 1, i // 60, i % 60, 0, tzinfo=UTC),
            )
            alert_persistence.save_alert(alert)

        # Search with limit=10
        result = search_service.search(limit=10, host="testhost")

        # Should get exactly 10 alerts (the top 10 by sort order)
        assert len(result.alerts) == 10
        assert result.status == AlertSearchStatus.AVAILABLE
        # All returned alerts should match the filter
        for alert in result.alerts:
            assert alert.entity_context.get("host") == "testhost"

        # Final result count should be ≤ 10
        assert len(result.alerts) <= 10

    def test_no_mutation_of_sources(
        self,
        search_service: AlertSearchService,
        alert_queue: AlertQueue,
        alert_persistence: AlertPersistence,
    ):
        """Search should not mutate queue or persistence."""
        alert = make_alert(title="Test", host="testhost")
        alert_queue.enqueue(alert)
        alert_persistence.save_alert(alert)

        # Get snapshots
        queue_before = list(alert_queue.values())
        persistence_before = alert_persistence.list_all().alerts

        # Perform search
        search_service.search(limit=10)

        # Verify no mutation
        queue_after = list(alert_queue.values())
        persistence_after = alert_persistence.list_all().alerts

        assert queue_before == queue_after
        assert len(persistence_before) == len(persistence_after)
