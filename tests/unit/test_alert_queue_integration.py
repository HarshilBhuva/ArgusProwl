"""Tests for Phase 4.7.6 — Alert Queue DI Integration & Operational Views.

Covers:
- AlertQueue DI registration and singleton behavior
- AlertManager receives queue through DI
- Backward compatibility (AlertManager without queue)
- Queue integration in send_alert
- Queue-full handling does not block provider delivery
- Queue identity (alert_id) remains unchanged
- Deduplication invariants preserved
- Lifecycle delegation through AlertManager
- Filtering/sorting delegation
- Queue statistics
- Configuration validation
"""

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.alerting.console_provider import ConsoleAlertProvider
from argusprowl.config.config_manager import ConfigManager
from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.deduplication.engine import AlertDeduplicationEngine
from argusprowl.deduplication.fingerprint import AlertFingerprint, FingerprintConfig
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.exceptions.exceptions import ValidationError
from argusprowl.lifecycle.queue import AlertNotFoundError, AlertQueue, AlertQueueError
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
    rule_id: str | None = None,
    source: str | None = None,
    created_at: datetime | None = None,
    alert_id: UUID | None = None,
) -> Alert:
    """Helper to create a test alert with sensible defaults.

    Note: Uses unique source to avoid deduplication suppression in tests.
    """
    return Alert(
        title=title,
        description=f"Test alert: {title}",
        severity=severity,
        source=source or f"test_source_{uuid4()}",  # Unique source per alert
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
    """Create an isolated AlertQueue for testing."""
    return AlertQueue(max_size=100)


@pytest.fixture
def deduplication_engine() -> AlertDeduplicationEngine:
    """Create an isolated deduplication engine for testing with zero cooldown."""
    return AlertDeduplicationEngine(cooldown=0.0, max_fingerprints=1000)


@pytest.fixture
def alert_manager_no_queue(deduplication_engine: AlertDeduplicationEngine) -> AlertManager:
    """Create an AlertManager without a queue (backward compatibility)."""
    return AlertManager(deduplication_engine=deduplication_engine, alert_queue=None)


@pytest.fixture
def alert_manager_with_queue(
    deduplication_engine: AlertDeduplicationEngine,
    queue: AlertQueue,
) -> AlertManager:
    """Create an AlertManager with a queue."""
    return AlertManager(deduplication_engine=deduplication_engine, alert_queue=queue)


# ---------------------------------------------------------------------------
# DI Tests
# ---------------------------------------------------------------------------


class TestDIContainer:
    """Tests for AlertQueue DI registration."""

    def test_queue_is_registered(self, temp_dir: Path) -> None:
        """AlertQueue should be registered in DI container."""
        cfg_file = temp_dir / "test_config.yaml"
        cfg_file.write_text("app_name: 'Test App'\n")
        ConfigManager.reset_instance()
        ServiceContainer.reset_instance()
        try:
            config_manager = ConfigManager()
            config = config_manager.load(cfg_file)

            container = ServiceContainer()
            from argusprowl.lifecycle.queue import AlertQueue

            container.register_singleton(
                AlertQueue,
                lambda: AlertQueue(max_size=config.reliability.alert_queue.max_size),
            )
            assert container.is_registered(AlertQueue)
        finally:
            ConfigManager.reset_instance()
            ServiceContainer.reset_instance()

    def test_queue_resolves_successfully(self, temp_dir: Path) -> None:
        """AlertQueue should resolve successfully from container."""
        cfg_file = temp_dir / "test_config.yaml"
        cfg_file.write_text("app_name: 'Test App'\n")
        ConfigManager.reset_instance()
        ServiceContainer.reset_instance()
        try:
            config_manager = ConfigManager()
            config = config_manager.load(cfg_file)

            container = ServiceContainer()
            from argusprowl.lifecycle.queue import AlertQueue

            container.register_singleton(
                AlertQueue,
                lambda: AlertQueue(max_size=config.reliability.alert_queue.max_size),
            )
            queue = container.resolve(AlertQueue)
            assert queue is not None
            assert isinstance(queue, AlertQueue)
        finally:
            ConfigManager.reset_instance()
            ServiceContainer.reset_instance()

    def test_queue_is_singleton(self, temp_dir: Path) -> None:
        """AlertQueue should resolve to same instance (singleton)."""
        cfg_file = temp_dir / "test_config.yaml"
        cfg_file.write_text("app_name: 'Test App'\n")
        ConfigManager.reset_instance()
        ServiceContainer.reset_instance()
        try:
            config_manager = ConfigManager()
            config = config_manager.load(cfg_file)

            container = ServiceContainer()
            from argusprowl.lifecycle.queue import AlertQueue

            container.register_singleton(
                AlertQueue,
                lambda: AlertQueue(max_size=config.reliability.alert_queue.max_size),
            )
            queue1 = container.resolve(AlertQueue)
            queue2 = container.resolve(AlertQueue)
            assert queue1 is queue2
        finally:
            ConfigManager.reset_instance()
            ServiceContainer.reset_instance()

    def test_alert_manager_receives_queue_instance(self, temp_dir: Path) -> None:
        """AlertManager should receive the same queue instance from container."""
        cfg_file = temp_dir / "test_config.yaml"
        cfg_file.write_text("app_name: 'Test App'\n")
        ConfigManager.reset_instance()
        ServiceContainer.reset_instance()
        try:
            config_manager = ConfigManager()
            config = config_manager.load(cfg_file)

            container = ServiceContainer()
            from argusprowl.lifecycle.queue import AlertQueue

            container.register_singleton(
                AlertQueue,
                lambda: AlertQueue(max_size=config.reliability.alert_queue.max_size),
            )
            dedup = AlertDeduplicationEngine()
            container.register_singleton(
                AlertManager,
                lambda: AlertManager(
                    deduplication_engine=dedup,
                    alert_queue=container.resolve(AlertQueue),
                ),
            )
            queue = container.resolve(AlertQueue)
            manager = container.resolve(AlertManager)
            # Verify queue is wired into manager (via private attribute)
            assert manager._alert_queue is queue
        finally:
            ConfigManager.reset_instance()
            ServiceContainer.reset_instance()


# ---------------------------------------------------------------------------
# AlertManager Backward Compatibility
# ---------------------------------------------------------------------------


class TestAlertManagerBackwardCompatibility:
    """Tests for AlertManager backward compatibility without queue."""

    def test_alert_manager_without_queue_works(self, alert_manager_no_queue: AlertManager) -> None:
        """AlertManager should work without a queue."""
        alert = make_alert()
        provider = ConsoleAlertProvider()
        alert_manager_no_queue.register_provider(provider)
        # Should not raise
        result = alert_manager_no_queue.send_alert(alert)
        assert isinstance(result, dict)

    def test_list_alerts_without_queue_returns_empty(
        self, alert_manager_no_queue: AlertManager
    ) -> None:
        """list_alerts() should return empty list when no queue is configured."""
        result = alert_manager_no_queue.list_alerts()
        assert result == []

    def test_acknowledge_alert_without_queue_raises(
        self, alert_manager_no_queue: AlertManager
    ) -> None:
        """acknowledge_alert() should raise when no queue is configured."""
        with pytest.raises(AlertQueueError, match="queue is not available"):
            alert_manager_no_queue.acknowledge_alert(uuid4())

    def test_close_alert_without_queue_raises(self, alert_manager_no_queue: AlertManager) -> None:
        """close_alert() should raise when no queue is configured."""
        with pytest.raises(AlertQueueError, match="queue is not available"):
            alert_manager_no_queue.close_alert(uuid4())


# ---------------------------------------------------------------------------
# Queue Integration in send_alert
# ---------------------------------------------------------------------------


class TestQueueIntegration:
    """Tests for queue integration in AlertManager.send_alert."""

    def test_alert_is_enqueued(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """Alert should be enqueued when sent."""
        alert = make_alert()
        alert_manager_with_queue.send_alert(alert)
        assert len(queue) == 1
        assert queue.get(alert.alert_id) is not None

    def test_provider_still_receives_alert(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """Provider should receive alert even when queue is integrated."""
        alert = make_alert()
        provider = ConsoleAlertProvider()
        alert_manager_with_queue.register_provider(provider)
        # Capture output
        import io
        import sys

        captured = io.StringIO()
        sys.stdout = captured
        try:
            alert_manager_with_queue.send_alert(alert)
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        assert "Test Alert" in output or "test alert" in output.lower()

    def test_queue_and_provider_receive_same_alert(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """Both queue and provider should receive the same logical alert."""
        alert = make_alert()
        alert_manager_with_queue.send_alert(alert)
        # Queue has the alert
        queued = queue.get(alert.alert_id)
        assert queued is not None
        assert queued.alert_id == alert.alert_id
        assert queued.title == alert.title


# ---------------------------------------------------------------------------
# Queue Full Handling
# ---------------------------------------------------------------------------


class TestQueueFullHandling:
    """Tests for queue-full behavior."""

    def test_queue_full_does_not_block_provider(
        self, deduplication_engine: AlertDeduplicationEngine
    ) -> None:
        """Provider should still receive alert when queue is full."""
        small_queue = AlertQueue(max_size=2)
        manager = AlertManager(
            deduplication_engine=deduplication_engine,
            alert_queue=small_queue,
        )
        provider = ConsoleAlertProvider()
        manager.register_provider(provider)

        # Fill the queue
        a1 = make_alert(title="Alert1")
        a2 = make_alert(title="Alert2")
        manager.send_alert(a1)
        manager.send_alert(a2)

        # Queue is full - send another alert
        a3 = make_alert(title="Alert3")
        # Should complete without exception (provider delivery continues)
        result = manager.send_alert(a3)
        assert isinstance(result, dict)

    def test_queue_full_handled_explicitly(
        self, deduplication_engine: AlertDeduplicationEngine
    ) -> None:
        """AlertQueueFullError should be caught and not propagate."""
        small_queue = AlertQueue(max_size=1)
        manager = AlertManager(
            deduplication_engine=deduplication_engine,
            alert_queue=small_queue,
        )

        # Fill the queue
        a1 = make_alert(title="First")
        manager.send_alert(a1)

        # Send another - should not raise AlertQueueFullError
        a2 = make_alert(title="Second")
        result = manager.send_alert(a2)  # Should not raise
        assert isinstance(result, dict)

    def test_no_existing_item_evicted_on_full(
        self, deduplication_engine: AlertDeduplicationEngine
    ) -> None:
        """No existing queue items should be evicted when queue is full."""
        small_queue = AlertQueue(max_size=2)
        manager = AlertManager(
            deduplication_engine=deduplication_engine,
            alert_queue=small_queue,
        )

        # Fill the queue
        a1 = make_alert(title="Alert1")
        a2 = make_alert(title="Alert2")
        manager.send_alert(a1)
        manager.send_alert(a2)
        assert len(small_queue) == 2

        # Try to add more - should not evict existing
        a3 = make_alert(title="Alert3")
        manager.send_alert(a3)

        # Original alerts should still be there (queue rejects newest)
        assert small_queue.get(a1.alert_id) is not None
        assert small_queue.get(a2.alert_id) is not None
        # Queue remains bounded at max_size
        assert len(small_queue) <= 2

    def test_no_unbounded_fallback(self, deduplication_engine: AlertDeduplicationEngine) -> None:
        """No unbounded fallback should occur on queue full."""
        small_queue = AlertQueue(max_size=1)
        manager = AlertManager(
            deduplication_engine=deduplication_engine,
            alert_queue=small_queue,
        )

        # Send many alerts beyond capacity
        for i in range(10):
            manager.send_alert(make_alert(title=f"Alert{i}"))

        # Queue should still be bounded
        assert len(small_queue) == 1


# ---------------------------------------------------------------------------
# Queue Identity and Deduplication Invariants
# ---------------------------------------------------------------------------


class TestQueueIdentityAndDeduplication:
    """Tests for queue identity and deduplication invariants."""

    def test_queue_uses_alert_id(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """Queue should use alert_id for lookup."""
        alert = make_alert()
        alert_manager_with_queue.send_alert(alert)
        # Can retrieve by alert_id
        assert queue.get(alert.alert_id) is not None

    def test_fingerprint_unchanged_after_queue_integration(self) -> None:
        """Fingerprint should be unchanged after queue integration."""
        fp = AlertFingerprint(FingerprintConfig())
        alert = make_alert()
        original_fp = fp.create(alert)

        # Send through manager with queue
        queue = AlertQueue()
        dedup = AlertDeduplicationEngine(cooldown=0.0, max_fingerprints=1000)
        manager = AlertManager(deduplication_engine=dedup, alert_queue=queue)
        manager.send_alert(alert)

        # Fingerprint should be same
        stored = queue.get(alert.alert_id)
        assert stored is not None
        assert fp.create(stored) == original_fp

    def test_queue_does_not_deduplicate_by_fingerprint(self) -> None:
        """Queue should not deduplicate by fingerprint."""
        queue = AlertQueue()
        # Two alerts with different alert_ids but same fingerprint content
        alert1 = make_alert(title="Same", rule_id="same_rule")
        alert2 = make_alert(title="Same", rule_id="same_rule")
        # They have different alert_ids
        assert alert1.alert_id != alert2.alert_id
        # Both should be enqueued
        queue.enqueue(alert1)
        queue.enqueue(alert2)  # Should succeed, not rejected
        assert len(queue) == 2


# ---------------------------------------------------------------------------
# Lifecycle Delegation
# ---------------------------------------------------------------------------


class TestLifecycleDelegation:
    """Tests for lifecycle operations through AlertManager."""

    def test_acknowledge_through_alert_manager(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """acknowledge() should work through AlertManager."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.OPEN)
        alert_manager_with_queue.send_alert(alert)

        updated = alert_manager_with_queue.acknowledge_alert(alert.alert_id)
        assert updated.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED
        # Queue should have updated state
        stored = queue.get(alert.alert_id)
        assert stored.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_close_through_alert_manager(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """close() should work through AlertManager."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.OPEN)
        alert_manager_with_queue.send_alert(alert)

        updated = alert_manager_with_queue.close_alert(alert.alert_id)
        assert updated.lifecycle_state == AlertLifecycleState.CLOSED
        stored = queue.get(alert.alert_id)
        assert stored.lifecycle_state == AlertLifecycleState.CLOSED

    def test_invalid_lifecycle_transition_raises(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """Invalid lifecycle transitions should still raise ValueError."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.CLOSED)
        alert_manager_with_queue.send_alert(alert)

        # Can't acknowledge a closed alert
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            alert_manager_with_queue.acknowledge_alert(alert.alert_id)

    def test_original_alert_not_mutated(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """Original immutable alert should not be mutated."""
        alert = make_alert(lifecycle_state=AlertLifecycleState.OPEN)
        original_state = alert.lifecycle_state

        alert_manager_with_queue.send_alert(alert)
        alert_manager_with_queue.acknowledge_alert(alert.alert_id)

        # Original alert should be unchanged
        assert alert.lifecycle_state == original_state


# ---------------------------------------------------------------------------
# Filtering/Sorting Delegation
# ---------------------------------------------------------------------------


class TestFilteringSortingDelegation:
    """Tests for filtering and sorting delegation."""

    def test_list_alerts_with_priority_filter(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """list_alerts() should filter by priority."""
        high = make_alert(priority=AlertPriority.HIGH)
        low = make_alert(priority=AlertPriority.LOW)
        alert_manager_with_queue.send_alert(high)
        alert_manager_with_queue.send_alert(low)

        result = alert_manager_with_queue.list_alerts(min_priority=AlertPriority.HIGH)
        assert len(result) == 1
        assert result[0].alert_id == high.alert_id

    def test_list_alerts_with_severity_filter(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """list_alerts() should filter by severity."""
        critical = make_alert(severity=Severity.CRITICAL)
        info = make_alert(severity=Severity.INFO)
        alert_manager_with_queue.send_alert(critical)
        alert_manager_with_queue.send_alert(info)

        result = alert_manager_with_queue.list_alerts(min_severity=Severity.HIGH)
        assert len(result) == 1
        assert result[0].alert_id == critical.alert_id

    def test_list_alerts_with_lifecycle_filter(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """list_alerts() should filter by lifecycle state."""
        open_alert = make_alert(lifecycle_state=AlertLifecycleState.OPEN)
        closed_alert = make_alert(lifecycle_state=AlertLifecycleState.CLOSED)
        alert_manager_with_queue.send_alert(open_alert)
        alert_manager_with_queue.send_alert(closed_alert)

        result = alert_manager_with_queue.list_alerts(lifecycle_state=AlertLifecycleState.OPEN)
        assert len(result) == 1
        assert result[0].alert_id == open_alert.alert_id

    def test_list_alerts_deterministic_sorting(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """list_alerts() should return deterministically sorted results."""
        # Use different priorities to verify sorting
        low = make_alert(title="Low", priority=AlertPriority.LOW)
        critical = make_alert(title="Critical", priority=AlertPriority.CRITICAL)
        medium = make_alert(title="Medium", priority=AlertPriority.MEDIUM)
        alert_manager_with_queue.send_alert(low)
        alert_manager_with_queue.send_alert(critical)
        alert_manager_with_queue.send_alert(medium)

        result1 = alert_manager_with_queue.list_alerts()
        result2 = alert_manager_with_queue.list_alerts()
        # Same ordering on repeated calls
        assert [a.alert_id for a in result1] == [a.alert_id for a in result2]
        # Verify deterministic ordering (highest priority first)
        priorities = [a.priority for a in result1]
        assert priorities[0] == AlertPriority.CRITICAL


# ---------------------------------------------------------------------------
# Queue Statistics
# ---------------------------------------------------------------------------


class TestQueueStatistics:
    """Tests for queue statistics in get_statistics()."""

    def test_statistics_include_queue_size(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """Statistics should include queue_size."""
        alert = make_alert()
        alert_manager_with_queue.send_alert(alert)
        stats = alert_manager_with_queue.get_statistics()
        assert "queue_size" in stats
        assert stats["queue_size"] == 1

    def test_statistics_include_queue_capacity(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """Statistics should include queue_capacity."""
        stats = alert_manager_with_queue.get_statistics()
        assert "queue_capacity" in stats
        assert stats["queue_capacity"] == queue.max_size

    def test_statistics_include_available_capacity(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """Statistics should include queue_available."""
        stats = alert_manager_with_queue.get_statistics()
        assert "queue_available" in stats
        assert stats["queue_available"] == queue.max_size

    def test_statistics_include_lifecycle_counts(
        self,
        alert_manager_with_queue: AlertManager,
        queue: AlertQueue,
    ) -> None:
        """Statistics should include lifecycle counts."""
        open_alert = make_alert(lifecycle_state=AlertLifecycleState.OPEN)
        acknowledged_alert = make_alert(lifecycle_state=AlertLifecycleState.ACKNOWLEDGED)
        alert_manager_with_queue.send_alert(open_alert)
        alert_manager_with_queue.send_alert(acknowledged_alert)
        # Acknowledge the open alert
        alert_manager_with_queue.acknowledge_alert(open_alert.alert_id)

        stats = alert_manager_with_queue.get_statistics()
        assert "queue_open" in stats
        assert "queue_acknowledged" in stats
        assert "queue_closed" in stats
        assert stats["queue_open"] == 0  # After acknowledgment
        assert stats["queue_acknowledged"] == 2  # Both acknowledged

    def test_statistics_without_queue(self, alert_manager_no_queue: AlertManager) -> None:
        """Statistics should not include queue fields when no queue configured."""
        stats = alert_manager_no_queue.get_statistics()
        assert "queue_size" not in stats
        assert "queue_capacity" not in stats


# ---------------------------------------------------------------------------
# Configuration Tests
# ---------------------------------------------------------------------------


class TestConfigurationValidation:
    """Tests for queue configuration validation."""

    def test_valid_queue_capacity(self, temp_dir: Path) -> None:
        """Valid queue capacity should be accepted."""
        cfg_file = temp_dir / "test_config.yaml"
        cfg_file.write_text(
            "app_name: 'Test App'\nreliability:\n  alert_queue:\n    max_size: 5000\n"
        )
        ConfigManager.reset_instance()
        ServiceContainer.reset_instance()
        try:
            config_manager = ConfigManager()
            config = config_manager.load(cfg_file)
            assert config.reliability.alert_queue.max_size == 5000
        finally:
            ConfigManager.reset_instance()
            ServiceContainer.reset_instance()

    def test_default_queue_capacity(self, temp_dir: Path) -> None:
        """Default queue capacity should be 10000."""
        cfg_file = temp_dir / "test_config.yaml"
        cfg_file.write_text("app_name: 'Test App'\n")
        ConfigManager.reset_instance()
        ServiceContainer.reset_instance()
        try:
            config_manager = ConfigManager()
            config = config_manager.load(cfg_file)
            assert config.reliability.alert_queue.max_size == 10_000
        finally:
            ConfigManager.reset_instance()
            ServiceContainer.reset_instance()

    def test_invalid_queue_capacity_zero(self, temp_dir: Path) -> None:
        """Zero queue capacity should be rejected."""
        cfg_file = temp_dir / "test_config.yaml"
        cfg_file.write_text("app_name: 'Test App'\nreliability:\n  alert_queue:\n    max_size: 0\n")
        ConfigManager.reset_instance()
        ServiceContainer.reset_instance()
        try:
            config_manager = ConfigManager()
            with pytest.raises(ValidationError):
                config_manager.load(cfg_file)
        finally:
            ConfigManager.reset_instance()
            ServiceContainer.reset_instance()

    def test_invalid_queue_capacity_negative(self, temp_dir: Path) -> None:
        """Negative queue capacity should be rejected."""
        cfg_file = temp_dir / "test_config.yaml"
        cfg_file.write_text(
            "app_name: 'Test App'\nreliability:\n  alert_queue:\n    max_size: -100\n"
        )
        ConfigManager.reset_instance()
        ServiceContainer.reset_instance()
        try:
            config_manager = ConfigManager()
            with pytest.raises(ValidationError):
                config_manager.load(cfg_file)
        finally:
            ConfigManager.reset_instance()
            ServiceContainer.reset_instance()


# ---------------------------------------------------------------------------
# Replay Semantics
# ---------------------------------------------------------------------------


class TestReplaySemantics:
    """Tests for replay/live semantics."""

    def test_alert_queue_works_with_constructor_injection(self) -> None:
        """AlertQueue should work with constructor injection pattern."""
        queue = AlertQueue(max_size=1000)
        dedup = AlertDeduplicationEngine(cooldown=300.0, max_fingerprints=1000)
        manager = AlertManager(deduplication_engine=dedup, alert_queue=queue)

        alert = make_alert()
        manager.send_alert(alert)

        assert queue.get(alert.alert_id) is not None

    def test_replay_can_use_separate_queue_instance(self) -> None:
        """Replay can use a separate queue instance if needed."""
        # Production queue
        production_queue = AlertQueue(max_size=10000)
        # Replay-specific queue
        replay_queue = AlertQueue(max_size=500)

        prod_dedup = AlertDeduplicationEngine(cooldown=300.0, max_fingerprints=1000)
        replay_dedup = AlertDeduplicationEngine(cooldown=300.0, max_fingerprints=1000)

        AlertManager(
            deduplication_engine=prod_dedup,
            alert_queue=production_queue,
        )
        replay_manager = AlertManager(
            deduplication_engine=replay_dedup,
            alert_queue=replay_queue,
        )

        alert = make_alert()
        replay_manager.send_alert(alert)

        # Alert should be in replay queue only
        assert replay_queue.get(alert.alert_id) is not None
        assert production_queue.get(alert.alert_id) is None


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests."""

    def test_acknowledge_unknown_alert_raises(self, alert_manager_with_queue: AlertManager) -> None:
        """Acknowledging unknown alert should raise AlertNotFoundError."""
        with pytest.raises(AlertNotFoundError):
            alert_manager_with_queue.acknowledge_alert(uuid4())

    def test_close_unknown_alert_raises(self, alert_manager_with_queue: AlertManager) -> None:
        """Closing unknown alert should raise AlertNotFoundError."""
        with pytest.raises(AlertNotFoundError):
            alert_manager_with_queue.close_alert(uuid4())

    def test_list_alerts_empty_queue(self, alert_manager_with_queue: AlertManager) -> None:
        """list_alerts() on empty queue should return empty list."""
        result = alert_manager_with_queue.list_alerts()
        assert result == []

    def test_duplicate_alert_id_skipped(
        self, alert_manager_with_queue: AlertManager, queue: AlertQueue
    ) -> None:
        """Duplicate alert_id should be skipped in queue."""
        alert = make_alert()
        alert_manager_with_queue.send_alert(alert)
        # Same alert sent again
        alert_manager_with_queue.send_alert(alert)
        assert len(queue) == 1

    def test_provider_failure_does_not_affect_queue(
        self, alert_manager_with_queue: AlertManager, queue: AlertQueue
    ) -> None:
        """Provider failure should not affect queue state."""
        from argusprowl.interfaces.alert_provider import AlertProvider

        class FailingProvider(AlertProvider):
            @property
            def provider_name(self):
                return "failing"

            def is_available(self):
                return True

            def send(self, alert):
                raise RuntimeError("Provider failed")

        provider = FailingProvider()
        alert_manager_with_queue.register_provider(provider)

        alert = make_alert()
        # Should not raise
        alert_manager_with_queue.send_alert(alert)
        # Alert should still be in queue
        assert queue.get(alert.alert_id) is not None
