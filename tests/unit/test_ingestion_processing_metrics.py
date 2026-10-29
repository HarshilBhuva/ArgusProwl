"""Regression tests for ingestion processing metrics and consumer outcomes."""

import logging

from argusprowl.core.application import Application
from argusprowl.reliability.buffer import BoundedIngestionBuffer


def test_dequeue_does_not_count_as_successful_processing() -> None:
    buffer = BoundedIngestionBuffer[str](max_size=2)

    assert buffer.put("event")
    assert buffer.get(timeout=0) == "event"

    assert buffer.dequeue_count.get_value() == 1
    assert buffer.events_processed.get_value() == 0
    assert buffer.events_processing_failed.get_value() == 0

    buffer.record_processing_result(True, 0.25)

    assert buffer.events_processed.get_value() == 1
    assert buffer.events_processing_failed.get_value() == 0
    assert buffer.consumer_processing_latency.get_value()["count"] == 1


def test_failed_processing_is_not_counted_as_success() -> None:
    buffer = BoundedIngestionBuffer[str](max_size=2)

    assert buffer.put("bad-event")
    assert buffer.get(timeout=0) == "bad-event"
    buffer.record_processing_result(False, 0.5)

    assert buffer.dequeue_count.get_value() == 1
    assert buffer.events_processed.get_value() == 0
    assert buffer.events_processing_failed.get_value() == 1
    assert buffer.consumer_processing_latency.get_value()["count"] == 1


def _run_consumer(events: list[str], processor):
    """Run the real consumer loop against a closed, preloaded buffer."""
    app = Application.__new__(Application)
    app._logger = logging.getLogger("test.ingestion-processing-metrics")
    app._event_queue = BoundedIngestionBuffer[str](max_size=len(events) + 1)
    app._process_event = processor

    for event in events:
        assert app._event_queue.put(event)
    app._event_queue.close()
    app._processing_loop()
    return app._event_queue


def test_consumer_loop_records_success_failure_and_latency_once_per_event() -> None:
    def processor(event: str) -> bool:
        return event != "failure"

    buffer = _run_consumer(["success-1", "failure", "success-2"], processor)

    assert buffer.dequeue_count.get_value() == 3
    assert buffer.events_processed.get_value() == 2
    assert buffer.events_processing_failed.get_value() == 1
    assert buffer.consumer_processing_latency.get_value()["count"] == 3


def test_consumer_survives_unexpected_processor_exception() -> None:
    seen: list[str] = []

    def processor(event: str) -> bool:
        seen.append(event)
        if event == "raises":
            raise RuntimeError("synthetic processor failure")
        return True

    buffer = _run_consumer(["raises", "after-exception"], processor)

    assert seen == ["raises", "after-exception"]
    assert buffer.dequeue_count.get_value() == 2
    assert buffer.events_processed.get_value() == 1
    assert buffer.events_processing_failed.get_value() == 1
    assert buffer.consumer_processing_latency.get_value()["count"] == 2


def test_consumer_does_not_double_count_outcomes() -> None:
    outcomes = {"ok": True, "bad": False, "ok-2": True, "bad-2": False}
    buffer = _run_consumer(list(outcomes), outcomes.__getitem__)

    assert buffer.dequeue_count.get_value() == len(outcomes)
    assert buffer.events_processed.get_value() == sum(outcomes.values())
    assert buffer.events_processing_failed.get_value() == len(outcomes) - sum(outcomes.values())
    assert buffer.consumer_processing_latency.get_value()["count"] == len(outcomes)
