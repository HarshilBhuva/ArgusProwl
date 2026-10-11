"""Tests for Phase 4.7.5C — Alert Queue & Minimal Analyst Workflow.

Covers:
- AlertQueue basic operations (enqueue, get, list, acknowledge, close)
- Lifecycle workflow transitions
- Filtering and sorting integration with 4.7.5B
- Immutability invariants
- Deduplication invariance
- Backward compatibility with legacy alerts
- Capacity bounds and duplicate semantics
"""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.deduplication import AlertFingerprint, FingerprintConfig
from argusprowl.lifecycle import (
    AlertQueue,
    AlertQueueFullError,
)
from argusprowl.models.alert import Alert

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_alert(
    *,
    title: str = "Test Alert",
    severity: Severity = Severity.HIGH,
    priority: AlertPriority = AlertPriority.HIGH,
    lifecycle_state: AlertLifecycleState = AlertLifecycleState.OPEN,
    contextual_confidence: float | None = 0.85,
    host: str | None = "workstation-23",
    rule_id: str | None = "test_rule",
    created_at: datetime | None = None,
    alert_id: UUID | None = None,
) -> Alert:
    """Helper to create a test alert with sensible defaults."""
    return Alert(
        title=title,
        description=f"Test alert: {title}",
        severity=severity,
        source="test_source",
        alert_id=alert_id or uuid4(),
        created_at=created_at or datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
        metadata={"rule_id": rule_id} if rule_id else {},
        entity_context={"host": host} if host else None,
        priority=priority,
        contextual_confidence=contextual_confidence,
        lifecycle_state=lifecycle_state,
    )


@pytest.fixture
def queue() -> AlertQueue:
    return AlertQueue(max_size=100)


@pytest.fixture
def alert_collection() -> list[Alert]:
    """Create a collection of alerts with varying properties."""
    return [
        make_alert(
            title="Critical Alert",
            severity=Severity.CRITICAL,
            priority=AlertPriority.CRITICAL,
            host="server-01",
            rule_id="rule_critical",
            contextual_confidence=0.95,
            created_at=datetime(2026, 8, 31, 14, 0, 0, tzinfo=UTC),
        ),
        make_alert(
            title="High Alert",
            severity=Severity.HIGH,
            priority=AlertPriority.HIGH,
            host="workstation-23",
            rule_id="rule_high",
            contextual_confidence=0.85,
            created_at=datetime(2026, 8, 31, 13, 0, 0, tzinfo=UTC),
        ),
        make_alert(
            title="Medium Alert",
            severity=Severity.MEDIUM,
            priority=AlertPriority.MEDIUM,
            host="workstation-10",
            rule_id="rule_medium",
            contextual_confidence=0.60,
            created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
        ),
        make_alert(
            title="Low Alert",
            severity=Severity.LOW,
            priority=AlertPriority.LOW,
            host="workstation-10",
            rule_id="rule_low",
            contextual_confidence=0.40,
            created_at=datetime(2026, 8, 31, 11, 0, 0, tzinfo=UTC),
        ),
        make_alert(
            title="Info Alert",
            severity=Severity.INFO,
            priority=AlertPriority.LOW,
            host="workstation-10",
            rule_id="rule_info",
            contextual_confidence=0.20,
            created_at=datetime(2026, 8, 31, 10, 0, 0, tzinfo=UTC),
        ),
    ]


@pytest.fixture
def fingerprint() -> AlertFingerprint:
    return AlertFingerprint(FingerprintConfig())


# ---------------------------------------------------------------------------
# Queue Basics
# ---------------------------------------------------------------------------


class TestQueueBasics:
    """Tests for basic queue operations."""

    def test_empty_queue(self, queue: AlertQueue) -> None:
        """An empty queue should have length 0."""
        assert len(queue) == 0
        assert queue.values() == []

    def test_enqueue_alert(self, queue: AlertQueue) -> None:
        """Enqueue should add an alert to the queue."""
        alert = make_alert()
        result = queue.enqueue(alert)
        assert result is True
        assert len(queue) == 1

    def test_retrieve_by_alert_id(self, queue: AlertQueue) -> None:
        """get() should return the alert with the matching ID."""
        alert = make_alert()
        queue.enqueue(alert)
        retrieved = queue.get(alert.alert_id)
        assert retrieved is not None
        assert retrieved.alert_id == alert.alert_id
        assert retrieved.title == alert.title

    def test_list_alerts(self, queue: AlertQueue, alert_collection: list[Alert]) -> None:
        """list() should return all alerts when no filters are applied."""
        for alert in alert_collection:
            queue.enqueue(alert)
        result = queue.list()
        assert len(result) == len(alert_collection)

    def test_unknown_alert_lookup(self, queue: AlertQueue) -> None:
        """get() for an unknown ID should return None."""
        unknown_id = uuid4()
        assert queue.get(unknown_id) is None

    def test_duplicate_alert_id_behavior(self, queue: AlertQueue) -> None:
        """Enqueue with duplicate alert_id should return False."""
        alert = make_alert()
        assert queue.enqueue(alert) is True
        assert queue.enqueue(alert) is False
        assert len(queue) == 1

    def test_bounded_capacity(self, queue: AlertQueue) -> None:
        """Queue should enforce max_size."""
        for i in range(100):
            queue.enqueue(make_alert(title=f"Alert{i}"))
        assert len(queue) == 100
        with pytest.raises(AlertQueueFullError):
            queue.enqueue(make_alert(title="Overflow"))

    def test_deterministic_capacity_behavior(self) -> None:
        """Queue with small capacity should reject new alerts deterministically."""
        q = AlertQueue(max_size=2)
        a1 = make_alert(title="A1")
        a2 = make_alert(title="A2")
        a3 = make_alert(title="A3")
        assert q.enqueue(a1) is True
        assert q.enqueue(a2) is True
        assert len(q) == 2
        with pytest.raises(AlertQueueFullError):
            q.enqueue(a3)
        assert q.get(a1.alert_id) is not None
        assert q.get(a2.alert_id) is not None
        assert q.get(a3.alert_id) is None


# ---------------------------------------------------------------------------
# Lifecycle Workflow
# ---------------------------------------------------------------------------


class TestLifecycleWorkflow:
    """Tests for lifecycle transitions through the queue."""

    def test_acknowledge_open_alert(self, queue: AlertQueue) -> None:
        """acknowledge() should transition OPEN -> ACKNOWLEDGED."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.OPEN)
        queue.enqueue(alert)
        updated = queue.acknowledge(alert.alert_id)
        assert updated.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED
        stored = queue.get(alert.alert_id)
        assert stored is not None
        assert stored.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_close_open_alert(self, queue: AlertQueue) -> None:
        """close() should transition OPEN -> CLOSED."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.OPEN)
        queue.enqueue(alert)
        updated = queue.close(alert.alert_id)
        assert updated.lifecycle_state == AlertLifecycleState.CLOSED
        stored = queue.get(alert.alert_id)
        assert stored is not None
        assert stored.lifecycle_state == AlertLifecycleState.CLOSED

    def test_close_acknowledged_alert(self, queue: AlertQueue) -> None:
        """close() should transition ACKNOWLEDGED -> CLOSED."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.ACKNOWLEDGED)
        queue.enqueue(alert)
        updated = queue.close(alert.alert_id)
        assert updated.lifecycle_state == AlertLifecycleState.CLOSED

    def test_invalid_closed_to_open_transition(self, queue: AlertQueue) -> None:
        """CLOSED -> OPEN should raise ValueError."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.CLOSED)
        queue.enqueue(alert)
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            queue.acknowledge(alert.alert_id)

    def test_invalid_closed_to_acknowledged_transition(self, queue: AlertQueue) -> None:
        """CLOSED -> ACKNOWLEDGED should raise ValueError."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.CLOSED)
        queue.enqueue(alert)
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            queue.acknowledge(alert.alert_id)

    def test_invalid_acknowledged_to_open_transition(self, queue: AlertQueue) -> None:
        """ACKNOWLEDGED -> OPEN should raise ValueError."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.ACKNOWLEDGED)
        queue.enqueue(alert)
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            queue.acknowledge(alert.alert_id)

    def test_queue_stores_returned_immutable_lifecycle_replacement(self, queue: AlertQueue) -> None:
        """Queue should store the new immutable alert returned by transition."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.OPEN)
        original_id = alert.alert_id
        queue.enqueue(alert)
        queue.acknowledge(alert.alert_id)
        stored = queue.get(original_id)
        assert stored is not None
        assert stored.alert_id == original_id
        assert stored.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED
        assert alert.lifecycle_state == AlertLifecycleState.OPEN


# ---------------------------------------------------------------------------
# Filtering Integration
# ---------------------------------------------------------------------------


class TestFilteringIntegration:
    """Tests for filtering integration with 4.7.5B."""

    def test_minimum_priority(self, queue: AlertQueue, alert_collection: list[Alert]) -> None:
        """list() with min_priority should filter correctly."""
        for alert in alert_collection:
            queue.enqueue(alert)
        result = queue.list(min_priority=AlertPriority.HIGH)
        assert len(result) == 2
        for alert in result:
            assert alert.priority is not None
            assert alert.priority.order >= AlertPriority.HIGH.order

    def test_minimum_severity(self, queue: AlertQueue, alert_collection: list[Alert]) -> None:
        """list() with min_severity should filter correctly."""
        for alert in alert_collection:
            queue.enqueue(alert)
        result = queue.list(min_severity=Severity.HIGH)
        assert len(result) == 2
        for alert in result:
            assert alert.severity >= Severity.HIGH

    def test_rule_id(self, queue: AlertQueue, alert_collection: list[Alert]) -> None:
        """list() with rule_id should filter correctly."""
        for alert in alert_collection:
            queue.enqueue(alert)
        result = queue.list(rule_id="rule_high")
        assert len(result) == 1
        assert result[0].metadata.get("rule_id") == "rule_high"

    def test_host(self, queue: AlertQueue, alert_collection: list[Alert]) -> None:
        """list() with host should filter correctly."""
        for alert in alert_collection:
            queue.enqueue(alert)
        result = queue.list(host="workstation-23")
        assert len(result) == 1
        assert result[0].entity_context is not None
        assert result[0].entity_context.get("host") == "workstation-23"

    def test_lifecycle_state(self, queue: AlertQueue, alert_collection: list[Alert]) -> None:
        """list() with lifecycle_state should filter correctly."""
        for alert in alert_collection:
            queue.enqueue(alert)
        result = queue.list(lifecycle_state=AlertLifecycleState.OPEN)
        assert len(result) == len(alert_collection)

    def test_combined_filters_and_semantics(
        self, queue: AlertQueue, alert_collection: list[Alert]
    ) -> None:
        """Combined filters should use AND semantics."""
        for alert in alert_collection:
            queue.enqueue(alert)
        result = queue.list(
            min_priority=AlertPriority.HIGH,
            lifecycle_state=AlertLifecycleState.OPEN,
            host="workstation-23",
        )
        assert len(result) == 1
        assert result[0].metadata.get("rule_id") == "rule_high"


# ---------------------------------------------------------------------------
# Sorting Integration
# ---------------------------------------------------------------------------


class TestSortingIntegration:
    """Tests for sorting integration with 4.7.5B."""

    def test_priority_descending(self, queue: AlertQueue, alert_collection: list[Alert]) -> None:
        """list() should sort by priority descending by default."""
        for alert in alert_collection:
            queue.enqueue(alert)
        result = queue.list()
        assert result[0].priority == AlertPriority.CRITICAL
        assert result[-1].priority == AlertPriority.LOW

    def test_severity_descending(self, queue: AlertQueue, alert_collection: list[Alert]) -> None:
        """list() should sort by severity descending when priority is equal."""
        alerts = [
            make_alert(title="Low Severity", severity=Severity.LOW, priority=AlertPriority.HIGH),
            make_alert(title="High Severity", severity=Severity.HIGH, priority=AlertPriority.HIGH),
        ]
        for alert in alerts:
            queue.enqueue(alert)
        result = queue.list()
        assert result[0].severity == Severity.HIGH
        assert result[1].severity == Severity.LOW

    def test_contextual_confidence_descending(self, queue: AlertQueue) -> None:
        """list() should sort by contextual confidence descending."""
        alerts = [
            make_alert(title="Low Confidence", contextual_confidence=0.4),
            make_alert(title="High Confidence", contextual_confidence=0.9),
        ]
        for alert in alerts:
            queue.enqueue(alert)
        result = queue.list()
        assert result[0].contextual_confidence == 0.9
        assert result[1].contextual_confidence == 0.4

    def test_timestamp_descending(self, queue: AlertQueue) -> None:
        """list() should sort by created_at descending (newest first)."""
        alerts = [
            make_alert(title="Old Alert", created_at=datetime(2026, 8, 31, 10, 0, 0, tzinfo=UTC)),
            make_alert(title="New Alert", created_at=datetime(2026, 8, 31, 14, 0, 0, tzinfo=UTC)),
        ]
        for alert in alerts:
            queue.enqueue(alert)
        result = queue.list()
        assert result[0].created_at > result[1].created_at

    def test_alert_id_deterministic_tiebreaker(self, queue: AlertQueue) -> None:
        """list() should use alert_id as final tie-breaker."""
        id1 = uuid4()
        id2 = uuid4()
        if id1 > id2:
            id1, id2 = id2, id1
        alerts = [
            make_alert(
                title="Alert 1",
                alert_id=id1,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            ),
            make_alert(
                title="Alert 2",
                alert_id=id2,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            ),
        ]
        for alert in alerts:
            queue.enqueue(alert)
        result = queue.list()
        assert result[0].alert_id == id1
        assert result[1].alert_id == id2

    def test_list_without_sort(self, queue: AlertQueue) -> None:
        """list(sort=False) should return alerts in insertion order."""
        alerts = [
            make_alert(title="First", created_at=datetime(2026, 8, 31, 14, 0, 0, tzinfo=UTC)),
            make_alert(title="Second", created_at=datetime(2026, 8, 31, 10, 0, 0, tzinfo=UTC)),
        ]
        for alert in alerts:
            queue.enqueue(alert)
        result = queue.list(sort=False)
        assert result[0].title == "First"
        assert result[1].title == "Second"


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    """Tests verifying that queue operations never mutate stored alerts."""

    def test_enqueue_does_not_mutate_alert(self, queue: AlertQueue) -> None:
        """enqueue() should not mutate the alert object."""
        alert = make_alert()
        original_dict = alert.to_dict()
        queue.enqueue(alert)
        assert alert.to_dict() == original_dict

    def test_acknowledge_does_not_mutate_original_alert(self, queue: AlertQueue) -> None:
        """acknowledge() should not mutate the original alert object."""
        alert = make_alert()
        original_dict = alert.to_dict()
        queue.enqueue(alert)
        _ = queue.acknowledge(alert.alert_id)
        assert alert.lifecycle_state == AlertLifecycleState.OPEN
        assert alert.to_dict() == original_dict

    def test_close_does_not_mutate_original_alert(self, queue: AlertQueue) -> None:
        """close() should not mutate the original alert object."""
        alert = make_alert()
        original_dict = alert.to_dict()
        queue.enqueue(alert)
        _ = queue.close(alert.alert_id)
        assert alert.lifecycle_state == AlertLifecycleState.OPEN
        assert alert.to_dict() == original_dict

    def test_list_does_not_mutate_alerts(
        self, queue: AlertQueue, alert_collection: list[Alert]
    ) -> None:
        """list() should not mutate any stored alerts."""
        for alert in alert_collection:
            queue.enqueue(alert)
        original_dicts = [a.to_dict() for a in alert_collection]
        _ = queue.list(min_priority=AlertPriority.HIGH)
        for i, alert in enumerate(alert_collection):
            assert alert.to_dict() == original_dicts[i]


# ---------------------------------------------------------------------------
# Deduplication Invariants
# ---------------------------------------------------------------------------


class TestDeduplicationInvariants:
    """Tests proving queue operations don't affect fingerprint identity."""

    def test_queue_operations_do_not_alter_fingerprint(
        self, queue: AlertQueue, fingerprint: AlertFingerprint
    ) -> None:
        """Queue operations should not change alert fingerprints."""
        alert = make_alert()
        original_fp = fingerprint.create(alert)
        queue.enqueue(alert)
        stored = queue.get(alert.alert_id)
        assert stored is not None
        assert fingerprint.create(stored) == original_fp

    def test_lifecycle_change_does_not_alter_fingerprint(
        self, queue: AlertQueue, fingerprint: AlertFingerprint
    ) -> None:
        """Lifecycle transitions should not alter fingerprint."""
        alert = make_alert()
        original_fp = fingerprint.create(alert)
        queue.enqueue(alert)
        _ = queue.acknowledge(alert.alert_id)
        stored = queue.get(alert.alert_id)
        assert stored is not None
        assert fingerprint.create(stored) == original_fp

    def test_priority_change_does_not_alter_fingerprint(
        self, fingerprint: AlertFingerprint
    ) -> None:
        """Priority changes should not alter fingerprint."""
        alert = make_alert()
        original_fp = fingerprint.create(alert)
        from dataclasses import replace

        modified = replace(alert, priority=AlertPriority.CRITICAL)
        assert fingerprint.create(modified) == original_fp

    def test_contextual_confidence_change_does_not_alter_fingerprint(
        self, fingerprint: AlertFingerprint
    ) -> None:
        """Contextual confidence changes should not alter fingerprint."""
        alert = make_alert()
        original_fp = fingerprint.create(alert)
        from dataclasses import replace

        modified = replace(alert, contextual_confidence=0.99)
        assert fingerprint.create(modified) == original_fp


# ---------------------------------------------------------------------------
# Backward Compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Tests for backward compatibility with legacy alerts."""

    def test_legacy_alert_without_lifecycle_behaves_as_open(self, queue: AlertQueue) -> None:
        """Legacy alerts without lifecycle should behave as OPEN."""
        alert = Alert(
            title="Legacy Alert",
            description="Legacy alert without lifecycle",
            severity=Severity.MEDIUM,
            source="legacy_source",
            alert_id=uuid4(),
            created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            metadata={"rule_id": "legacy_rule"},
        )
        queue.enqueue(alert)
        result = queue.list(lifecycle_state=AlertLifecycleState.OPEN)
        assert len(result) == 1

    def test_legacy_alert_without_priority_remains_queryable(self, queue: AlertQueue) -> None:
        """Legacy alerts without priority should remain queryable."""
        alert = Alert(
            title="No Priority Alert",
            description="Alert without priority",
            severity=Severity.HIGH,
            source="test",
            alert_id=uuid4(),
            priority=None,
        )
        queue.enqueue(alert)
        result = queue.list()
        assert len(result) == 1

    def test_legacy_alert_without_contextual_confidence_sorts_deterministically(
        self, queue: AlertQueue
    ) -> None:
        """Legacy alerts without contextual confidence should sort deterministically."""
        alerts = [
            Alert(
                title="With Confidence",
                description="With",
                severity=Severity.HIGH,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
                contextual_confidence=0.5,
            ),
            Alert(
                title="Without Confidence",
                description="Without",
                severity=Severity.HIGH,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
                contextual_confidence=None,
            ),
        ]
        for alert in alerts:
            queue.enqueue(alert)
        result = queue.list()
        assert result[0].contextual_confidence == 0.5
        assert result[1].contextual_confidence is None


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Tests for deterministic behavior."""

    def test_repeated_list_operations_return_same_ordering(
        self, queue: AlertQueue, alert_collection: list[Alert]
    ) -> None:
        """Repeated list() calls should return identical ordering."""
        for alert in alert_collection:
            queue.enqueue(alert)
        result1 = queue.list()
        result2 = queue.list()
        assert [a.alert_id for a in result1] == [a.alert_id for a in result2]

    def test_serialization_roundtrip_preserves_queue_fields(self) -> None:
        """Alert serialization round-trip should preserve queue-relevant fields."""
        q = AlertQueue(max_size=500)
        alert = make_alert()
        q.enqueue(alert)
        data = alert.to_dict()
        restored = Alert.from_dict(data)
        assert q.get(restored.alert_id) is not None
        assert len(q) == 1


# ---------------------------------------------------------------------------
# Bulk Helpers
# ---------------------------------------------------------------------------


class TestBulkHelpers:
    """Tests for bulk enqueue operations."""

    def test_extend_returns_accepted_alerts(self, queue: AlertQueue) -> None:
        """extend() should return only accepted alerts."""
        alerts = [make_alert(title=f"Alert{i}") for i in range(5)]
        accepted = queue.extend(alerts)
        assert len(accepted) == 5
        assert len(queue) == 5

    def test_extend_skips_duplicates(self, queue: AlertQueue) -> None:
        """extend() should skip duplicate alert_ids."""
        a1 = make_alert(title="A1")
        a2 = make_alert(title="A2")
        queue.enqueue(a1)
        accepted = queue.extend([a1, a2])
        assert len(accepted) == 1
        assert accepted[0].title == "A2"

    def test_extend_stops_at_capacity(self, queue: AlertQueue) -> None:
        """extend() should stop at capacity without raising."""
        q = AlertQueue(max_size=3)
        alerts = [make_alert(title=f"Alert{i}") for i in range(5)]
        accepted = q.extend(alerts)
        assert len(accepted) == 3
        assert len(q) == 3

    def test_extend_empty_iterable(self, queue: AlertQueue) -> None:
        """extend() with empty iterable should return empty list."""
        accepted = queue.extend([])
        assert accepted == []
        assert len(queue) == 0


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests for AlertQueue."""

    def test_zero_max_size_raises(self) -> None:
        """max_size=0 should raise ValueError."""
        with pytest.raises(ValueError, match="max_size must be a positive integer"):
            AlertQueue(max_size=0)

    def test_negative_max_size_raises(self) -> None:
        """max_size=-1 should raise ValueError."""
        with pytest.raises(ValueError, match="max_size must be a positive integer"):
            AlertQueue(max_size=-1)

    def test_close_already_closed_raises(self, queue: AlertQueue) -> None:
        """close() on already CLOSED alert should raise ValueError."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.CLOSED)
        queue.enqueue(alert)
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            queue.close(alert.alert_id)

    def test_acknowledge_already_acknowledged_raises(self, queue: AlertQueue) -> None:
        """acknowledge() on already ACKNOWLEDGED alert should raise ValueError."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.ACKNOWLEDGED)
        queue.enqueue(alert)
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            queue.acknowledge(alert.alert_id)

    def test_list_after_acknowledge_shows_new_state(self, queue: AlertQueue) -> None:
        """list() should reflect lifecycle state after transition."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.OPEN)
        queue.enqueue(alert)
        _ = queue.acknowledge(alert.alert_id)
        result = queue.list(lifecycle_state=AlertLifecycleState.ACKNOWLEDGED)
        assert len(result) == 1
        result = queue.list(lifecycle_state=AlertLifecycleState.OPEN)
        assert len(result) == 0

    def test_get_unknown_raises_not_found(self, queue: AlertQueue) -> None:
        """get() for unknown ID should return None, not raise."""
        unknown_id = uuid4()
        result = queue.get(unknown_id)
        assert result is None

    def test_contains_operator(self, queue: AlertQueue) -> None:
        """The 'in' operator should work with alert_id."""
        alert = make_alert()
        queue.enqueue(alert)
        assert alert.alert_id in queue
        assert uuid4() not in queue
