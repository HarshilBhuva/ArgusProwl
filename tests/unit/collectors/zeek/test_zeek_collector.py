"""Tests for Zeek Collector."""

import os
import queue
import threading
from contextlib import suppress
from pathlib import Path

from argusprowl.collectors.zeek.collector import ZeekCollector
from argusprowl.collectors.zeek.config import ZeekCollectorConfig
from argusprowl.collectors.zeek.offset import ZeekOffsetStore
from argusprowl.collectors.zeek.tailer import ZeekTailReader
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.replay.replay_reader import ReplayReader


def _line(uid: str) -> str:
    return (
        f"1590000000.000\t{uid}\t10.0.0.1\t1\t10.0.0.2\t2\ttcp\t-\t0.0\t0\t0"
        "\t-\t-\t-\t0\t-\t0\t0\t0\t0\t-\n"
    )


def test_offset_store(tmp_path: Path) -> None:
    """Test offset store functionality."""
    offset_file = tmp_path / "offsets.json"
    store = ZeekOffsetStore(offset_file)

    # Should default to 0
    assert store.get_offset(123) == 0

    # Save offset
    store.save_offset(123, 1024)
    assert store.get_offset(123) == 1024

    # Check persistence
    store2 = ZeekOffsetStore(offset_file)
    assert store2.get_offset(123) == 1024


def test_zeek_tailer(tmp_path: Path) -> None:
    """Test tail reader behavior."""
    log_file = tmp_path / "conn.log"
    offset_file = tmp_path / "offsets.json"

    # Write initial data
    log_file.write_text(
        "1590000000.000\tC1\t10.0.0.1\t1\t10.0.0.2\t2\ttcp\t-\t0.0\t0\t0\t-\t-\t-\t0\t-\t0\t0\t0\t0\t-\n",
        encoding="utf-8",
    )

    store = ZeekOffsetStore(offset_file)
    tailer = ZeekTailReader(log_file, store, poll_interval=0.01)

    # Get iterator
    iterator = tailer.tail()

    # Read first line
    line = next(iterator)
    assert "C1" in line

    # Ensure it's waiting
    tailer.stop()
    with suppress(StopIteration):
        next(iterator)


def test_zeek_collector_integration(tmp_path: Path) -> None:
    """Test the collector end-to-end."""
    log_file = tmp_path / "conn.log"
    offset_file = tmp_path / "offsets.json"

    # Write initial data
    log_file.write_text(
        "1590000000.000\tC1\t10.0.0.1\t1\t10.0.0.2\t2\ttcp\t-\t0.0\t0\t0\t-\t-\t-\t0\t-\t0\t0\t0\t0\t-\n",
        encoding="utf-8",
    )

    collector = ZeekCollector()
    collector.initialize(
        {"log_path": str(log_file), "offset_file": str(offset_file), "poll_interval_sec": 0.01}
    )

    collector.start()

    iterator = collector.collect()
    event = next(iterator)
    assert isinstance(event, NormalizedEvent)
    assert event.attributes["uid"] == "C1"

    collector.stop()


def test_tailer_resumes_from_offset_and_handles_rotation(tmp_path: Path) -> None:
    log_file = tmp_path / "conn.log"
    offset_file = tmp_path / "offsets.json"
    log_file.write_text(_line("first") + _line("second"), encoding="utf-8")
    tailer = ZeekTailReader(log_file, ZeekOffsetStore(offset_file), 0.001)
    iterator = tailer.tail()
    assert "first" in next(iterator)
    tailer.stop()

    resumed = ZeekTailReader(log_file, ZeekOffsetStore(offset_file), 0.001)
    resumed_iterator = resumed.tail()
    assert "second" in next(resumed_iterator)
    os.replace(log_file, tmp_path / "conn.log.1")
    log_file.write_text(_line("rotated"), encoding="utf-8")
    assert "rotated" in next(resumed_iterator)
    resumed.stop()


def test_collector_publishes_normalized_events_tracks_errors_and_restarts(tmp_path: Path) -> None:
    log_file = tmp_path / "conn.log"
    offset_file = tmp_path / "offsets.json"
    log_file.write_text("malformed\n" + _line("valid"), encoding="utf-8")
    q: queue.Queue[NormalizedEvent] = queue.Queue()
    collector = ZeekCollector(event_queue=q)
    collector.initialize(
        {"log_path": str(log_file), "offset_file": str(offset_file), "poll_interval_sec": 0.001}
    )
    collector.start()
    assert next(collector.collect()).attributes["uid"] == "valid"
    queued = q.get(timeout=5.0)
    assert queued.attributes["uid"] == "valid"
    assert collector.health().is_healthy
    assert collector.metrics.snapshot().errors_total == 1
    assert collector.metrics.snapshot().events_collected == 1
    collector.stop()

    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(_line("restarted"))
    collector.start()
    assert next(collector.collect()).attributes["uid"] == "restarted"
    collector.stop()


def test_missing_file_recovers_and_config_rejects_invalid_interval(tmp_path: Path) -> None:
    log_file = tmp_path / "conn.log"
    tailer = ZeekTailReader(log_file, ZeekOffsetStore(tmp_path / "offsets.json"), 0.001)
    received: list[str] = []
    worker = threading.Thread(target=lambda: received.append(next(tailer.tail())))
    worker.start()
    # Allow at least one failed open before the producer creates conn.log.
    threading.Event().wait(0.01)
    log_file.write_text(_line("created-later"), encoding="utf-8")
    worker.join(timeout=1)
    assert not worker.is_alive()
    assert "created-later" in received[0]
    tailer.stop()

    config = ZeekCollectorConfig(log_file, tmp_path / "offsets.json", poll_interval_sec=0)
    try:
        config.validate()
    except ValueError as exc:
        assert "poll_interval_sec" in str(exc)
    else:
        raise AssertionError("invalid collector configuration was accepted")


def test_collector_output_is_replay_compatible(tmp_path: Path) -> None:
    log_file = tmp_path / "conn.log"
    log_file.write_text(_line("same-envelope"), encoding="utf-8")
    collector = ZeekCollector()
    collector.initialize(
        {
            "log_path": str(log_file),
            "offset_file": str(tmp_path / "offsets.json"),
            "poll_interval_sec": 0.001,
        }
    )
    collector.start()
    collected = next(collector.collect())
    collector.stop()
    replayed = next(ReplayReader(log_file).read_events())

    assert collected.to_dict() | {"event_id": "ignored"} == replayed.to_dict() | {
        "event_id": "ignored"
    }
