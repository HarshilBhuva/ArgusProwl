"""Regression tests for graceful ingestion shutdown."""

from argusprowl.core.application import Application
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
