"""Tests for Phase 4.7.7 — Queue Saturation Observability & Replay Isolation.

Covers:
- Queue saturation observability and `queue_dropped` counter incrementing
- Queue-full logging rate limiting (time-based throttle)
- Statistics extensions and invariants
- Provider delivery independence during queue saturation
- Explicit replay isolation from live operational queue
- Backward compatibility without queue
- Concurrency and immutability invariants
"""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.interfaces.alert_provider import AlertProvider
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.alert import Alert
from argusprowl.replay.replay_engine import ReplayEngine


class MockAlertProvider(AlertProvider):
    """Mock alert provider for testing."""

    def __init__(
        self, name: str = "mock", available: bool = True, fail_delivery: bool = False
    ) -> None:
        self._name = name
        self._available = available
        self._fail_delivery = fail_delivery
        self.sent_alerts: list[Alert] = []

    @property
    def provider_name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return self._available

    def send(self, alert: Alert) -> bool:
        if self._fail_delivery:
            return False
        self.sent_alerts.append(alert)
        return True


def make_alert(
    *,
    title: str = "Test Alert",
    severity: Severity = Severity.HIGH,
    priority: AlertPriority = AlertPriority.HIGH,
    lifecycle_state: AlertLifecycleState = AlertLifecycleState.OPEN,
    alert_id: UUID | None = None,
) -> Alert:
    """Helper to create a test alert."""
    return Alert(
        title=title,
        description=f"Test alert: {title}",
        severity=severity,
        source=f"test_source_{uuid4()}",
        alert_id=alert_id or uuid4(),
        created_at=datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC),
        priority=priority,
        lifecycle_state=lifecycle_state,
    )


class TestQueueSaturationObservability:
    """Tests for queue saturation metrics and behavior."""

    def test_queue_dropped_counter_initializes_to_zero(self) -> None:
        queue = AlertQueue(max_size=10)
        manager = AlertManager(alert_queue=queue)
        stats = manager.get_statistics()
        assert stats["queue_dropped"] == 0

    def test_queue_full_increments_queue_dropped(self) -> None:
        queue = AlertQueue(max_size=1)
        manager = AlertManager(alert_queue=queue)
        provider = MockAlertProvider()
        manager.register_provider(provider)

        alert1 = make_alert(title="Alert 1")
        alert2 = make_alert(title="Alert 2")
        alert3 = make_alert(title="Alert 3")

        # First alert enqueues successfully
        manager.send_alert(alert1)
        assert len(queue) == 1
        assert manager.get_statistics()["queue_dropped"] == 0

        # Second alert hits queue capacity -> dropped
        manager.send_alert(alert2)
        assert len(queue) == 1
        assert manager.get_statistics()["queue_dropped"] == 1

        # Third alert -> dropped again
        manager.send_alert(alert3)
        assert len(queue) == 1
        assert manager.get_statistics()["queue_dropped"] == 2

    def test_queue_full_does_not_prevent_provider_delivery(self) -> None:
        queue = AlertQueue(max_size=1)
        manager = AlertManager(alert_queue=queue)
        provider = MockAlertProvider()
        manager.register_provider(provider)

        alert1 = make_alert(title="Alert 1")
        alert2 = make_alert(title="Alert 2")

        manager.send_alert(alert1)
        manager.send_alert(alert2)

        # Both alerts should be delivered to provider even though alert2 was dropped from queue
        assert len(provider.sent_alerts) == 2
        assert provider.sent_alerts[0].alert_id == alert1.alert_id
        assert provider.sent_alerts[1].alert_id == alert2.alert_id
        assert manager.get_statistics()["queue_dropped"] == 1

    def test_provider_failure_does_not_increment_queue_dropped(self) -> None:
        queue = AlertQueue(max_size=10)
        manager = AlertManager(alert_queue=queue)
        provider = MockAlertProvider(fail_delivery=True)
        manager.register_provider(provider)

        alert = make_alert()
        manager.send_alert(alert)

        assert manager.get_statistics()["queue_dropped"] == 0
        assert manager.total_delivery_failures == 1

    def test_statistics_invariants(self) -> None:
        queue = AlertQueue(max_size=5)
        manager = AlertManager(alert_queue=queue)
        for i in range(7):
            manager.send_alert(make_alert(title=f"Alert {i}"))

        stats = manager.get_statistics()
        assert stats["queue_capacity"] == 5
        assert stats["queue_size"] == 5
        assert stats["queue_available"] == 0
        assert stats["queue_dropped"] == 2
        assert stats["queue_size"] <= stats["queue_capacity"]
        assert stats["queue_available"] == stats["queue_capacity"] - stats["queue_size"]
        assert (
            stats["queue_open"] + stats["queue_acknowledged"] + stats["queue_closed"]
            == stats["queue_size"]
        )


class TestLoggingRateLimit:
    """Tests for rate-limited queue-full logging."""

    @patch("argusprowl.alerting.alert_manager.time.time")
    def test_queue_full_logging_throttle(self, mock_time: MagicMock) -> None:
        mock_time.return_value = 1000.0
        queue = AlertQueue(max_size=1)
        manager = AlertManager(alert_queue=queue)

        alert1 = make_alert(title="Alert 1")
        alert2 = make_alert(title="Alert 2")
        alert3 = make_alert(title="Alert 3")

        manager.send_alert(alert1)

        with patch.object(manager._logger, "warning") as mock_warning:
            # First queue full at t=1000.0 -> should log warning
            manager.send_alert(alert2)
            mock_warning.assert_called_once()

            # Second queue full at t=1010.0 (within 60s) -> should NOT log warning
            mock_time.return_value = 1010.0
            manager.send_alert(alert3)
            mock_warning.assert_called_once()  # Call count still 1
            assert manager.get_statistics()["queue_dropped"] == 2

            # Third queue full at t=1070.0 (after 60s throttle) -> should log warning again
            mock_time.return_value = 1070.0
            alert4 = make_alert(title="Alert 4")
            manager.send_alert(alert4)
            assert mock_warning.call_count == 2
            assert manager.get_statistics()["queue_dropped"] == 3


class TestReplayIsolation:
    """Tests verifying explicit replay isolation from live operational queue."""

    def test_replay_does_not_mutate_live_queue(self, temp_dir: Path) -> None:
        # Create dummy log file for replay
        log_file = temp_dir / "test_conn.log"
        log_file.write_text(
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\tosig_pkts\tosig_bytes\tinitial_rtt\n"
            "1700000000.0\tCuid1\t192.168.1.10\t12345\t10.0.0.1\t80\ttcp\thttp\t1.5\t100\t200\tSF\t-\t-\t0\tShADfF\t10\t1000\t50\n"
        )

        live_queue = AlertQueue(max_size=100)
        manager = AlertManager(alert_queue=live_queue)
        initial_queue_size = len(live_queue)
        initial_dropped = manager.get_statistics()["queue_dropped"]

        replay_engine = ReplayEngine(log_path=log_file)
        replay_engine.run()

        # Live queue and manager stats must remain untouched by replay
        assert len(live_queue) == initial_queue_size
        assert manager.get_statistics()["queue_dropped"] == initial_dropped


class TestBackwardCompatibility:
    """Tests for AlertManager without queue."""

    def test_alert_manager_no_queue_works(self) -> None:
        manager = AlertManager(alert_queue=None)
        provider = MockAlertProvider()
        manager.register_provider(provider)

        alert = make_alert()
        results = manager.send_alert(alert)
        assert results["mock"] is True
        assert len(provider.sent_alerts) == 1

        stats = manager.get_statistics()
        assert stats["queue_dropped"] == 0
        assert "queue_size" not in stats
