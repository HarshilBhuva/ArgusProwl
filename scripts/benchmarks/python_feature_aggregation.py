"""End-to-end Python FeatureExtractor benchmark used for Rust parity testing.

Measures NormalizedEvent construction/validation, FeatureExtractor registry and
SlidingWindow operations, aggregation, FeatureVector construction/validation,
and per-event latency. It is a focused feature-pipeline benchmark, not a full
collector/queue/rule/storage/API benchmark.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from argusprowl.feature_engineering.feature_extractor import FeatureExtractor
from argusprowl.models.normalized_event import NormalizedEvent

NUMERIC_FIELDS = (
    "connection_count", "unique_dst_ports", "unique_dst_ips",
    "failed_connections", "syn_count", "avg_duration", "max_duration",
    "min_duration", "std_duration", "total_bytes_sent",
    "total_bytes_received", "avg_bytes_per_connection", "connection_rate",
    "bytes_rate", "port_concentration", "is_multi_port", "is_multi_dst",
    "time_since_first_connection", "src_port", "dst_port",
)
BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
SOURCE_IPS = tuple(f"192.0.2.{i}" for i in range(1, 9))


def percentile(samples: list[int], pct: float) -> float:
    ordered = sorted(samples)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * pct)))
    return ordered[index] / 1_000_000.0


def peak_rss_kib() -> int:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def make_event(sequence: int) -> NormalizedEvent:
    src_index = sequence % len(SOURCE_IPS)
    return NormalizedEvent(
        source_type="benchmark",
        event_type="network_connection",
        timestamp=BASE_TIME + timedelta(milliseconds=sequence * 10),
        hostname=f"sensor-{src_index % 4}",
        sensor=f"sensor-{src_index % 4}",
        src_ip=SOURCE_IPS[src_index],
        src_port=40000 + sequence % 20000,
        dst_ip=f"198.51.100.{sequence % 250 + 1}",
        dst_port=(80, 443, 22, 8080)[sequence % 4],
        protocol="tcp",
        username=f"user-{sequence % 16}",
        process_name="benchmark-client",
        pid=1000 + sequence % 1000,
        command_line="benchmark-client --connect",
        attributes={
            "conn_state": ("SF", "REJ", "S0", "OTH")[sequence % 4],
            "history": "S" if sequence % 3 == 0 else "ShADadfF",
            "duration": (sequence % 500) / 100.0,
            "orig_bytes": sequence % 4096,
            "resp_bytes": sequence % 8192,
        },
    )


def run_worker(event_count: int) -> dict[str, object]:
    extractor = FeatureExtractor(
        window_size_seconds=60.0,
        max_events_per_window=512,
        max_active_windows=16,
    )
    latencies: list[int] = []
    sums = {field: 0.0 for field in NUMERIC_FIELDS}
    sums.update({"unique_src_ports": 0.0, "dst_ports_list_len": 0.0, "dst_ips_list_len": 0.0})
    processed = 0
    for sequence in range(event_count):
        started = time.perf_counter_ns()
        event = make_event(sequence)
        vector = extractor.extract(event)
        latencies.append(time.perf_counter_ns() - started)
        if vector is None:
            continue
        processed += 1
        for field in NUMERIC_FIELDS:
            value = getattr(vector, field)
            sums[field] += float(value)
        sums["unique_src_ports"] += float(vector.features.get("unique_src_ports", 0))
        sums["dst_ports_list_len"] += len(vector.features.get("dst_ports_list", []))
        sums["dst_ips_list_len"] += len(vector.features.get("dst_ips_list", []))
    return {
        "processed": processed,
        "latencies_ns": latencies,
        "feature_sums": sums,
        "active_windows": extractor.active_window_count,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=5000)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()
    if args.events < 1 or args.workers < 1:
        parser.error("events and workers must be positive")

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(run_worker, [args.events] * args.workers))
    elapsed = time.perf_counter() - started

    latencies = [sample for result in results for sample in result["latencies_ns"]]
    processed = sum(int(result["processed"]) for result in results)
    feature_sums = {
        field: sum(float(result["feature_sums"][field]) for result in results)
        for field in results[0]["feature_sums"]
    }
    print(json.dumps({
        "language": "python",
        "runtime": sys.version.split()[0],
        "workers": args.workers,
        "offered_events": args.events * args.workers,
        "processed_events": processed,
        "unprocessed_events": args.events * args.workers - processed,
        "wall_seconds": elapsed,
        "throughput_events_per_second": processed / elapsed,
        "latency_ms": {
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
            "max": max(latencies, default=0) / 1_000_000.0,
        },
        "peak_rss_kib": peak_rss_kib(),
        "feature_sums": feature_sums,
        "active_windows": sum(int(result["active_windows"]) for result in results),
        "window_events_cap": 512,
        "source_count_per_worker": len(SOURCE_IPS),
    }, indent=2))


if __name__ == "__main__":
    main()
