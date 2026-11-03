"""Operational health checks must expose queue loss and storage failures."""

from unittest.mock import MagicMock

from argusprowl.interfaces.storage import Storage
from argusprowl.models.system_status import HealthStatus
from argusprowl.reliability.buffer import BoundedIngestionBuffer
from argusprowl.services.health_service import HealthService


def test_ingestion_queue_reports_healthy_while_idle() -> None:
    queue = BoundedIngestionBuffer[int](max_size=10)
    component = HealthService(event_queue=queue)._check_processing_queue()

    assert component.status == HealthStatus.HEALTHY
    assert "dropped=0" in component.message
    assert "processing_failed=0" in component.message


def test_ingestion_queue_reports_dropped_events_as_degraded() -> None:
    queue = BoundedIngestionBuffer[int](max_size=1)
    assert queue.put(1) is True
    assert queue.put(2) is False

    component = HealthService(event_queue=queue)._check_processing_queue()

    assert component.status == HealthStatus.DEGRADED
    assert "dropped=1" in component.message
    assert "rejected=1" in component.message


def test_ingestion_queue_reports_processing_failures_as_degraded() -> None:
    queue = BoundedIngestionBuffer[int](max_size=10)
    queue.record_processing_result(False, 0.25)

    component = HealthService(event_queue=queue)._check_processing_queue()

    assert component.status == HealthStatus.DEGRADED
    assert "processing_failed=1" in component.message


def test_ingestion_queue_reports_saturation_and_closed_state() -> None:
    queue = BoundedIngestionBuffer[int](max_size=2)
    assert queue.put(1) is True
    assert queue.put(2) is True

    saturated = HealthService(event_queue=queue)._check_processing_queue()
    assert saturated.status == HealthStatus.DEGRADED
    assert "near capacity" in saturated.message

    queue.close()
    closed = HealthService(event_queue=queue)._check_processing_queue()
    assert closed.status == HealthStatus.UNHEALTHY
    assert "closed" in closed.message


def test_storage_health_probe_is_read_only() -> None:
    storage = MagicMock(spec=Storage)
    storage.list_records.return_value = []
    component = HealthService(storage=storage)._check_storage()

    assert component.status == HealthStatus.HEALTHY
    storage.list_records.assert_called_once_with("__argusprowl_health_probe__", limit=1)


def test_storage_health_probe_reports_failures() -> None:
    storage = MagicMock(spec=Storage)
    storage.list_records.side_effect = OSError("database unavailable")

    component = HealthService(storage=storage)._check_storage()

    assert component.status == HealthStatus.UNHEALTHY
    assert "database unavailable" in component.message
