"""Tests for the real-PCAP Rust/Python benchmark harness."""

from __future__ import annotations

import cProfile
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "evaluation"))

from rust_python_pcap_benchmark import (
    create_python_stress_log,
    create_saturation_pcap,
    find_template,
    format_profile,
    percentile,
    summarize,
)


def _write_classic_pcap(path: Path, packet_count: int = 1) -> bytes:
    frame = bytearray(54)
    frame[12:14] = b"\x08\x00"
    frame[14] = 0x45
    frame[16:18] = (40).to_bytes(2, "big")
    frame[22] = 64
    frame[23] = 6
    frame[26:30] = bytes((192, 0, 2, 10))
    frame[30:34] = bytes((198, 51, 100, 20))
    frame[34:36] = (50000).to_bytes(2, "big")
    frame[36:38] = (443).to_bytes(2, "big")
    frame[46] = 0x50
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    path.write_bytes(
        global_header
        + b"".join(
            struct.pack("<IIII", 1, index, len(frame), len(frame)) + frame
            for index in range(packet_count)
        )
    )
    return bytes(frame)


def test_percentile_and_summary_are_deterministic():
    assert percentile([5.0, 1.0, 4.0, 2.0, 3.0], 0.95) == 5.0
    assert summarize([5.0, 1.0, 4.0]) == {
        "min": 1.0, "median": 4.0, "p95": 5.0, "max": 5.0,
    }


def test_find_template_extracts_supported_real_packet(tmp_path: Path):
    capture = tmp_path / "input.pcap"
    frame = _write_classic_pcap(capture)
    header, extracted = find_template(capture)
    assert len(header) == 24
    assert extracted == frame


def test_saturation_capture_mutates_unique_flow_keys_from_real_frame(tmp_path: Path):
    source = tmp_path / "source.pcap"
    _write_classic_pcap(source)
    destination = tmp_path / "stress.pcap"

    result = create_saturation_pcap(source, destination, packet_count=12)

    assert result["classification"] == "derived_saturation_fixture_not_real_capture"
    assert result["packets"] == 12
    assert result["file_bytes"] > source.stat().st_size
    _, frame = find_template(destination)
    assert frame[12:14] == b"\x08\x00"


def test_python_stress_log_uses_unique_ids_and_monotonic_timestamps(tmp_path: Path):
    source = tmp_path / "conn.log"
    source.write_text(
        "#separator \x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "1.0\tC123\t192.0.2.1\t12345\t198.51.100.1\t443\ttcp\n",
        encoding="utf-8",
    )
    destination = tmp_path / "stress.log"

    result = create_python_stress_log(source, destination, event_count=3)

    lines = [line for line in destination.read_text(encoding="utf-8").splitlines() if not line.startswith("#")]
    assert result["events"] == 3
    assert len(lines) == 3
    assert len({line.split("\t")[1] for line in lines}) == 3
    assert [float(line.split("\t")[0]) for line in lines] == sorted(
        float(line.split("\t")[0]) for line in lines
    )


def test_format_profile_reports_cumulative_and_self_time():
    profiler = cProfile.Profile()

    def workload():
        return sum(range(100))

    profiler.enable()
    workload()
    profiler.disable()

    report = format_profile(profiler)

    assert "function calls" in report["profile_cumulative_top_50"]
    assert "workload" in report["profile_cumulative_top_50"]
    assert "workload" in report["profile_self_time_top_50"]
