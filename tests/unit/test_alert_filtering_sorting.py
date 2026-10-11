"""Tests for Phase 4.7.5B — Alert Filtering & Deterministic Sorting.

Covers:
- filter_alerts() with all filter criteria
- sort_alerts() with deterministic ordering
- Deduplication invariance
- Backward compatibility with legacy alerts
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.deduplication import AlertFingerprint, FingerprintConfig
from argusprowl.lifecycle import filter_alerts, sort_alerts
from argusprowl.lifecycle.transition import transition_lifecycle
from argusprowl.models.alert import Alert

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def base_alert() -> Alert:
    """Create a base alert for testing."""
    return Alert(
        title="Test Alert",
        description="Test description",
        severity=Severity.HIGH,
        source="test_source",
        alert_id=uuid4(),
        created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
        metadata={
            "rule_id": "test_rule",
            "evidence": {"host": "workstation-23"},
        },
        entity_context={"host": "workstation-23", "src_ip": "192.168.1.100"},
        priority=AlertPriority.HIGH,
        contextual_confidence=0.85,
    )


@pytest.fixture
def alert_collection(base_alert: Alert) -> list[Alert]:
    """Create a collection of alerts with varying properties."""
    return [
        Alert(
            title="Critical Alert",
            description="Critical severity",
            severity=Severity.CRITICAL,
            source="critical_source",
            alert_id=uuid4(),
            created_at=datetime(2026, 8, 31, 14, 0, 0, tzinfo=UTC),
            metadata={"rule_id": "rule_critical"},
            entity_context={"host": "server-01"},
            priority=AlertPriority.CRITICAL,
            contextual_confidence=0.95,
        ),
        Alert(
            title="High Alert",
            description="High severity",
            severity=Severity.HIGH,
            source="high_source",
            alert_id=uuid4(),
            created_at=datetime(2026, 8, 31, 13, 0, 0, tzinfo=UTC),
            metadata={"rule_id": "rule_high"},
            entity_context={"host": "workstation-23"},
            priority=AlertPriority.HIGH,
            contextual_confidence=0.85,
        ),
        Alert(
            title="Medium Alert",
            description="Medium severity",
            severity=Severity.MEDIUM,
            source="medium_source",
            alert_id=uuid4(),
            created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            metadata={"rule_id": "rule_medium"},
            entity_context={"host": "workstation-10"},
            priority=AlertPriority.MEDIUM,
            contextual_confidence=0.60,
        ),
        Alert(
            title="Low Alert",
            description="Low severity",
            severity=Severity.LOW,
            source="low_source",
            alert_id=uuid4(),
            created_at=datetime(2026, 8, 31, 11, 0, 0, tzinfo=UTC),
            metadata={"rule_id": "rule_low"},
            entity_context={"host": "workstation-10"},
            priority=AlertPriority.LOW,
            contextual_confidence=0.40,
        ),
        Alert(
            title="Info Alert",
            description="Info severity",
            severity=Severity.INFO,
            source="info_source",
            alert_id=uuid4(),
            created_at=datetime(2026, 8, 31, 10, 0, 0, tzinfo=UTC),
            metadata={"rule_id": "rule_info"},
            entity_context={"host": "workstation-10"},
            priority=AlertPriority.LOW,
            contextual_confidence=0.20,
        ),
    ]


@pytest.fixture
def legacy_alert() -> Alert:
    """Create a legacy alert without lifecycle state (simulates pre-4.7.5A)."""
    return Alert(
        title="Legacy Alert",
        description="Legacy alert without lifecycle",
        severity=Severity.MEDIUM,
        source="legacy_source",
        alert_id=uuid4(),
        created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
        metadata={"rule_id": "legacy_rule"},
        # No lifecycle_state specified - should default to OPEN
    )


@pytest.fixture
def fingerprint() -> AlertFingerprint:
    """Create a fingerprint generator."""
    return AlertFingerprint(FingerprintConfig())


# ---------------------------------------------------------------------------
# Filtering Tests
# ---------------------------------------------------------------------------


class TestFilterAlerts:
    """Tests for filter_alerts() function."""

    def test_no_filters_returns_all(self, alert_collection: list[Alert]) -> None:
        """No filters should return all alerts."""
        result = filter_alerts(alert_collection)
        assert len(result) == len(alert_collection)
        assert result == alert_collection

    def test_min_priority(self, alert_collection: list[Alert]) -> None:
        """min_priority should keep alerts with priority >= threshold."""
        result = filter_alerts(alert_collection, min_priority=AlertPriority.HIGH)
        assert len(result) == 2
        for alert in result:
            assert alert.priority is not None
            assert alert.priority.order >= AlertPriority.HIGH.order

    def test_min_severity(self, alert_collection: list[Alert]) -> None:
        """min_severity should keep alerts with severity >= threshold."""
        result = filter_alerts(alert_collection, min_severity=Severity.HIGH)
        assert len(result) == 2
        for alert in result:
            assert alert.severity >= Severity.HIGH

    def test_rule_id(self, alert_collection: list[Alert]) -> None:
        """rule_id should match alerts with the specified rule."""
        result = filter_alerts(alert_collection, rule_id="rule_high")
        assert len(result) == 1
        assert result[0].metadata.get("rule_id") == "rule_high"

    def test_host(self, alert_collection: list[Alert]) -> None:
        """host should match alerts with the specified host in entity_context."""
        result = filter_alerts(alert_collection, host="workstation-23")
        assert len(result) == 1
        assert result[0].entity_context is not None
        assert result[0].entity_context.get("host") == "workstation-23"

    def test_lifecycle_state(self, alert_collection: list[Alert]) -> None:
        """lifecycle_state should filter by lifecycle state."""
        # All alerts default to OPEN
        result = filter_alerts(alert_collection, lifecycle_state=AlertLifecycleState.OPEN)
        assert len(result) == len(alert_collection)

    def test_multiple_filters_and_semantics(self, alert_collection: list[Alert]) -> None:
        """Multiple filters should use AND semantics."""
        result = filter_alerts(
            alert_collection,
            min_priority=AlertPriority.HIGH,
            lifecycle_state=AlertLifecycleState.OPEN,
            host="workstation-23",
        )
        # Only the HIGH alert with workstation-23 should match
        assert len(result) == 1
        assert result[0].metadata.get("rule_id") == "rule_high"

    def test_no_matching_alerts(self, alert_collection: list[Alert]) -> None:
        """No matching alerts should return empty list."""
        result = filter_alerts(alert_collection, rule_id="nonexistent_rule")
        assert len(result) == 0
        assert result == []

    def test_legacy_alert_missing_lifecycle_is_open(self, legacy_alert: Alert) -> None:
        """Legacy alerts without lifecycle should behave as OPEN."""
        result = filter_alerts([legacy_alert], lifecycle_state=AlertLifecycleState.OPEN)
        assert len(result) == 1

    def test_missing_host_does_not_match(self, alert_collection: list[Alert]) -> None:
        """Alerts without host should not match a host filter."""
        no_host_alert = Alert(
            title="No Host Alert",
            description="Alert without host",
            severity=Severity.LOW,
            source="test",
            alert_id=uuid4(),
            metadata={"rule_id": "no_host_rule"},
            entity_context=None,
        )
        result = filter_alerts([no_host_alert], host="some-host")
        assert len(result) == 0

    def test_filtering_does_not_mutate_original_list(self, alert_collection: list[Alert]) -> None:
        """Filtering should not mutate the original list."""
        original_len = len(alert_collection)
        original_ids = {a.alert_id for a in alert_collection}
        _ = filter_alerts(alert_collection, min_priority=AlertPriority.HIGH)
        assert len(alert_collection) == original_len
        assert {a.alert_id for a in alert_collection} == original_ids

    def test_filtering_does_not_mutate_alerts(self, alert_collection: list[Alert]) -> None:
        """Filtering should not mutate individual alerts."""
        original_dicts = [a.to_dict() for a in alert_collection]
        _ = filter_alerts(alert_collection, min_priority=AlertPriority.HIGH)
        for i, alert in enumerate(alert_collection):
            assert alert.to_dict() == original_dicts[i]


class TestFilterAlertsEdgeCases:
    """Edge case tests for filter_alerts()."""

    def test_empty_collection(self) -> None:
        """Empty collection should return empty list."""
        result = filter_alerts([])
        assert result == []

    def test_none_filters(self) -> None:
        """All None filters should return all alerts."""
        alerts = [
            Alert(
                title="Test",
                description="Test",
                severity=Severity.HIGH,
                source="test",
                alert_id=uuid4(),
            ),
        ]
        result = filter_alerts(
            alerts,
            min_priority=None,
            min_severity=None,
            rule_id=None,
            host=None,
            lifecycle_state=None,
        )
        assert len(result) == 1

    def test_priority_none_alerts(self, base_alert: Alert) -> None:
        """Alerts without priority should not match min_priority filter."""
        no_priority = Alert(
            title="No Priority",
            description="No priority",
            severity=Severity.HIGH,
            source="test",
            alert_id=uuid4(),
            priority=None,
        )
        result = filter_alerts([no_priority], min_priority=AlertPriority.HIGH)
        assert len(result) == 0

    def test_severity_boundary(self, base_alert: Alert) -> None:
        """Severity filter should use >= comparison."""
        result = filter_alerts([base_alert], min_severity=Severity.HIGH)
        assert len(result) == 1

        result = filter_alerts([base_alert], min_severity=Severity.CRITICAL)
        assert len(result) == 0

    def test_rule_id_fallback_to_source(self, base_alert: Alert) -> None:
        """rule_id filter should fallback to source if rule_id not in metadata."""
        no_rule_id = Alert(
            title="No Rule ID",
            description="No rule ID",
            severity=Severity.HIGH,
            source="test_source",
            alert_id=uuid4(),
            metadata={},
        )
        result = filter_alerts([no_rule_id], rule_id="test_source")
        assert len(result) == 1

    def test_host_fallback_to_metadata(self, base_alert: Alert) -> None:
        """host filter should fallback to metadata evidence."""
        metadata_host = Alert(
            title="Metadata Host",
            description="Host in metadata",
            severity=Severity.HIGH,
            source="test",
            alert_id=uuid4(),
            metadata={"evidence": {"host": "metadata-host"}},
            entity_context=None,
        )
        result = filter_alerts([metadata_host], host="metadata-host")
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Sorting Tests
# ---------------------------------------------------------------------------


class TestSortAlerts:
    """Tests for sort_alerts() function."""

    def test_priority_descending(self, base_alert: Alert) -> None:
        """Higher priority should come first."""
        alerts = [
            Alert(
                title="Low Priority",
                description="Low",
                severity=Severity.LOW,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.LOW,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            ),
            Alert(
                title="High Priority",
                description="High",
                severity=Severity.HIGH,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            ),
        ]
        result = sort_alerts(alerts)
        assert result[0].priority == AlertPriority.HIGH
        assert result[1].priority == AlertPriority.LOW

    def test_severity_descending(self, base_alert: Alert) -> None:
        """Higher severity should come first when priority is equal."""
        alerts = [
            Alert(
                title="Low Severity",
                description="Low",
                severity=Severity.LOW,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            ),
            Alert(
                title="High Severity",
                description="High",
                severity=Severity.HIGH,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            ),
        ]
        result = sort_alerts(alerts)
        assert result[0].severity == Severity.HIGH
        assert result[1].severity == Severity.LOW

    def test_contextual_confidence_descending(self, base_alert: Alert) -> None:
        """Higher contextual confidence should come first."""
        alerts = [
            Alert(
                title="Low Confidence",
                description="Low",
                severity=Severity.HIGH,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
                contextual_confidence=0.4,
            ),
            Alert(
                title="High Confidence",
                description="High",
                severity=Severity.HIGH,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
                contextual_confidence=0.9,
            ),
        ]
        result = sort_alerts(alerts)
        assert result[0].contextual_confidence == 0.9
        assert result[1].contextual_confidence == 0.4

    def test_legacy_missing_confidence(self, base_alert: Alert) -> None:
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
        result = sort_alerts(alerts)
        # Alert with confidence should come first (0.5 > 0.0)
        assert result[0].contextual_confidence == 0.5
        assert result[1].contextual_confidence is None

    def test_timestamp_descending(self, base_alert: Alert) -> None:
        """Newer alerts should come first."""
        alerts = [
            Alert(
                title="Old Alert",
                description="Old",
                severity=Severity.HIGH,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 10, 0, 0, tzinfo=UTC),
            ),
            Alert(
                title="New Alert",
                description="New",
                severity=Severity.HIGH,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 14, 0, 0, tzinfo=UTC),
            ),
        ]
        result = sort_alerts(alerts)
        assert result[0].created_at > result[1].created_at

    def test_alert_id_ascending_tiebreaker(self, base_alert: Alert) -> None:
        """Alert ID should be the final tie-breaker in ascending order."""
        id1 = uuid4()
        id2 = uuid4()
        # Ensure id1 < id2 for deterministic test
        if id1 > id2:
            id1, id2 = id2, id1

        alerts = [
            Alert(
                title="Alert 1",
                description="First",
                severity=Severity.HIGH,
                source="test",
                alert_id=id1,
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            ),
            Alert(
                title="Alert 2",
                description="Second",
                severity=Severity.HIGH,
                source="test",
                alert_id=id2,
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            ),
        ]
        result = sort_alerts(alerts)
        assert result[0].alert_id == id1
        assert result[1].alert_id == id2

    def test_complete_multi_key_ordering(self, alert_collection: list[Alert]) -> None:
        """Complete multi-key ordering should be deterministic."""
        result = sort_alerts(alert_collection)
        # Should be sorted by priority desc, then severity desc, etc.
        for i in range(len(result) - 1):
            a, b = result[i], result[i + 1]
            # a should come before b
            key_a = _get_sort_key(a)
            key_b = _get_sort_key(b)
            assert key_a <= key_b

    def test_repeated_sorting_identical(self, alert_collection: list[Alert]) -> None:
        """Repeated sorting should produce identical ordering."""
        result1 = sort_alerts(alert_collection)
        result2 = sort_alerts(alert_collection)
        assert [a.alert_id for a in result1] == [a.alert_id for a in result2]

    def test_sorting_does_not_mutate_original_list(self, alert_collection: list[Alert]) -> None:
        """Sorting should not mutate the original list."""
        original_order = [a.alert_id for a in alert_collection]
        _ = sort_alerts(alert_collection)
        assert [a.alert_id for a in alert_collection] == original_order

    def test_sorting_does_not_mutate_alerts(self, alert_collection: list[Alert]) -> None:
        """Sorting should not mutate individual alerts."""
        original_dicts = [a.to_dict() for a in alert_collection]
        _ = sort_alerts(alert_collection)
        for i, alert in enumerate(alert_collection):
            assert alert.to_dict() == original_dicts[i]


def _get_sort_key(alert: Alert) -> tuple:
    """Helper to get the sort key for an alert (for testing)."""
    priority_order = 0
    priority_order = alert.priority.order if alert.priority is not None else -1

    return (
        -priority_order,
        -alert.severity.value,
        -(alert.contextual_confidence or 0.0),
        -alert.created_at.timestamp(),
        alert.alert_id,
    )


# ---------------------------------------------------------------------------
# Deduplication Invariance Tests
# ---------------------------------------------------------------------------


class TestDeduplicationInvariance:
    """Tests proving filtering and sorting don't affect deduplication."""

    def test_filtering_does_not_affect_fingerprint(
        self, alert_collection: list[Alert], fingerprint: AlertFingerprint
    ) -> None:
        """Filtering should not change alert fingerprints."""
        original_fingerprints = {a.alert_id: fingerprint.create(a) for a in alert_collection}
        filtered = filter_alerts(alert_collection, min_priority=AlertPriority.HIGH)
        for alert in filtered:
            assert fingerprint.create(alert) == original_fingerprints[alert.alert_id]

    def test_sorting_does_not_affect_fingerprint(
        self, alert_collection: list[Alert], fingerprint: AlertFingerprint
    ) -> None:
        """Sorting should not change alert fingerprints."""
        original_fingerprints = {a.alert_id: fingerprint.create(a) for a in alert_collection}
        sorted_alerts = sort_alerts(alert_collection)
        for alert in sorted_alerts:
            assert fingerprint.create(alert) == original_fingerprints[alert.alert_id]

    def test_lifecycle_does_not_affect_fingerprint(
        self, base_alert: Alert, fingerprint: AlertFingerprint
    ) -> None:
        """Lifecycle state changes should not affect fingerprint."""
        original_fp = fingerprint.create(base_alert)
        acknowledged = transition_lifecycle(base_alert, AlertLifecycleState.ACKNOWLEDGED)
        closed = transition_lifecycle(base_alert, AlertLifecycleState.CLOSED)
        assert fingerprint.create(acknowledged) == original_fp
        assert fingerprint.create(closed) == original_fp

    def test_priority_does_not_affect_fingerprint(
        self, base_alert: Alert, fingerprint: AlertFingerprint
    ) -> None:
        """Priority changes should not affect fingerprint."""
        from dataclasses import replace

        original_fp = fingerprint.create(base_alert)
        modified = replace(base_alert, priority=AlertPriority.CRITICAL)
        assert fingerprint.create(modified) == original_fp


# ---------------------------------------------------------------------------
# Backward Compatibility Tests
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Tests for backward compatibility with legacy alerts."""

    def test_legacy_alert_without_lifecycle_is_filterable(self, legacy_alert: Alert) -> None:
        """Legacy alerts without lifecycle should be filterable."""
        result = filter_alerts([legacy_alert], lifecycle_state=AlertLifecycleState.OPEN)
        assert len(result) == 1

    def test_legacy_alert_without_confidence_sorts_correctly(self, legacy_alert: Alert) -> None:
        """Legacy alerts without contextual confidence should sort deterministically."""
        alerts = [
            legacy_alert,
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
        ]
        result = sort_alerts(alerts)
        # The one with confidence should come first
        assert result[0].contextual_confidence == 0.5

    def test_legacy_alert_without_priority_sorts_correctly(self, legacy_alert: Alert) -> None:
        """Legacy alerts without priority should sort deterministically."""
        alerts = [
            legacy_alert,
            Alert(
                title="With Priority",
                description="With",
                severity=Severity.HIGH,
                source="test",
                alert_id=uuid4(),
                priority=AlertPriority.HIGH,
                created_at=datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
            ),
        ]
        result = sort_alerts(alerts)
        # The one with priority should come first
        assert result[0].priority is not None
        assert result[1].priority is None

    def test_old_serialized_alert_without_lifecycle_remains_filterable(self) -> None:
        """Old serialized alerts without lifecycle field should remain filterable."""
        old_data = {
            "alert_id": str(uuid4()),
            "title": "Old Alert",
            "description": "Old alert without lifecycle",
            "severity": "HIGH",
            "priority": "HIGH",
            "source": "old_source",
            "created_at": datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC).isoformat(),
            "tags": [],
            "metadata": {"rule_id": "old_rule"},
            "schema_version": 2,
            # No lifecycle_state field
        }
        alert = Alert.from_dict(old_data)
        assert alert.lifecycle_state == AlertLifecycleState.OPEN
        result = filter_alerts([alert], lifecycle_state=AlertLifecycleState.OPEN)
        assert len(result) == 1
