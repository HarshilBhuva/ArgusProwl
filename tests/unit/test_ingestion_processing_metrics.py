"""Regression tests for ingestion processing metrics."""

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


def test_failed_processing_is_not_counted_as_success() -> None:
    buffer = BoundedIngestionBuffer[str](max_size=2)

    assert buffer.put("bad-event")
    assert buffer.get(timeout=0) == "bad-event"
    buffer.record_processing_result(False, 0.5)

    assert buffer.dequeue_count.get_value() == 1
    assert buffer.events_processed.get_value() == 0
    assert buffer.events_processing_failed.get_value() == 1
