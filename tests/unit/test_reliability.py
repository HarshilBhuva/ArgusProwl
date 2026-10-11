from threading import Thread

from argusprowl.reliability import (
    BoundedIngestionBuffer,
    OverflowPolicy,
)


def test_buffer_is_fifo_and_bounded() -> None:
    buffer = BoundedIngestionBuffer[int](2)
    assert buffer.put(1) and buffer.put(2)
    assert not buffer.put(3)
    assert buffer.get() == 1
    assert buffer.get() == 2
    assert buffer.events_dropped.get_value() == 1
    assert buffer.max_queue_depth.get_value() == 2


def test_buffer_drop_oldest_and_shutdown_wakes_waiters() -> None:
    buffer = BoundedIngestionBuffer[int](1, OverflowPolicy.DROP_OLDEST)
    assert buffer.put(1) and buffer.put(2)
    assert buffer.get() == 2
    buffer.close()
    assert not buffer.put(3)
    assert buffer.get(timeout=0) is None


def test_buffer_is_safe_for_concurrent_producer_consumer() -> None:
    buffer = BoundedIngestionBuffer[int](100, OverflowPolicy.BLOCK)
    consumed: list[int] = []
    producer = Thread(target=lambda: [buffer.put(value, timeout=1) for value in range(20)])
    consumer = Thread(target=lambda: [consumed.append(buffer.get(timeout=1)) for _ in range(20)])
    consumer.start()
    producer.start()
    producer.join()
    consumer.join()
    assert consumed == list(range(20))
