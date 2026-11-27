"""Regression tests for graceful ingestion shutdown."""

from threading import Event

from argusprowl.core.application import Application
from argusprowl.metrics.collector import MetricsCollector
from argusprowl.reliability.buffer import BoundedIngestionBuffer


def test_processing_loop_drains_closed_buffer_after_shutdown_signal(monkeypatch) -> None:
    """A shutdown signal must not cause queued events to be abandoned."""
    app = Application()
    queue = BoundedIngestionBuffer[str](max_size=4)
    app._event_queue = queue
    app._shutdown_event.set()

    assert queue.put("event-already-accepted")
    queue.close()

    processed: list[str] = []
    monkeypatch.setattr(app, "_process_event", processed.append)

    app._processing_loop()

    assert processed == ["event-already-accepted"]
    assert queue.empty()


def test_shutdown_timeout_preserves_services_until_worker_exits(tmp_path, monkeypatch) -> None:
    """A timed-out drain must retain dependencies and allow shutdown retry."""
    config_path = tmp_path / "shutdown-timeout.yaml"
    config_path.write_text(
        "api:\n  enabled: false\n"
        "logging:\n  console_enabled: false\n  file_enabled: false\n  json_enabled: false\n"
        "events:\n  shutdown_timeout_seconds: 0.01\n",
        encoding="utf-8",
    )
    app = Application(config_path=config_path)
    app.startup(start_api=False)

    worker_entered = Event()
    allow_worker_exit = Event()

    def blocked_process(_event: str) -> bool:
        worker_entered.set()
        allow_worker_exit.wait(timeout=2.0)
        return True

    monkeypatch.setattr(app, "_process_event", blocked_process)
    assert app._event_queue is not None
    assert app._event_queue.put("accepted-before-shutdown")
    assert worker_entered.wait(timeout=2.0)

    app.shutdown()

    # The worker is still using application services, so teardown must defer.
    assert app.is_running is True
    assert app._container.resolve(MetricsCollector) is not None

    allow_worker_exit.set()
    assert app._processing_thread is not None
    app._processing_thread.join(timeout=2.0)
    assert not app._processing_thread.is_alive()

    # A second shutdown call completes teardown after the worker has drained.
    app.shutdown()
    assert app.is_running is False
