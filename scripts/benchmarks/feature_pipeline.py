"""Reproducible feature-extraction benchmark (standard library only).

This measures FeatureExtractor throughput and per-call latency under concurrent
source-IP streams. It is a component benchmark, not an end-to-end queue or
collector benchmark; it does not claim queue depth, drops, or wire throughput.
Run from the repository root:
    python scripts/benchmarks/feature_pipeline.py --events 20000 --workers 4
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from argusprowl.feature_engineering.feature_extractor import FeatureExtractor
from argusprowl.models.normalized_event import NormalizedEvent


def build_event(source_index: int, sequence: int, base_time: datetime) -> NormalizedEvent:
    """Build deterministic synthetic network telemetry."""
    return NormalizedEvent(
        source_type="benchmark",
        event_type="network_connection",
        timestamp=base_time + timedelta(microseconds=sequence),
        src_ip=f"192.0.2.{source_index + 1}",
        src_port=40000 + sequence % 20000,
        dst_ip=f"198.51.100.{sequence % 250 + 1}",
        dst_port=(80, 443, 22, 8080)[sequence % 4],
        protocol="tcp",
        attributes={
            "conn_state": ("SF", "REJ", "S0", "OTH")[sequence % 4],
            "history": "ShADadfF" if sequence % 3 else "S",
            "duration": (sequence % 500) / 100.0,
            "orig_bytes": sequence % 4096,
            "resp_bytes": sequence % 8192,
        },
    )


def percentile(values: list[int], fraction: float) -> float:
    """Return nearest-rank percentile in milliseconds."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index] / 1_000_000


def run_worker(
    source_index: int, event_count: int, window_size: float
) -> tuple[int, list[int]]:
    """Run one independent source stream and collect call latencies."""
    extractor = FeatureExtractor(
        window_size_seconds=window_size,
        max_events_per_window=event_count + 1,
        max_active_windows=1,
    )
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    latencies: list[int] = []
    processed = 0
    for sequence in range(event_count):
        event = build_event(source_index, sequence, base_time)
        started = time.perf_counter_ns()
        vector = extractor.extract(event)
        latencies.append(time.perf_counter_ns() - started)
        if vector is not None:
            processed += 1
    return processed, latencies


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=10_000, help="events per worker")
    parser.add_argument("--workers", type=int, default=1, help="concurrent source streams")
    parser.add_argument("--window-seconds", type=float, default=3600.0)
    args = parser.parse_args()
    if args.events < 1 or args.workers < 1 or args.window_seconds <= 0:
        parser.error("events, workers, and window-seconds must be positive")

    tracemalloc.start()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        results = list(
            executor.map(
                lambda source: run_worker(source, args.events, args.window_seconds),
                range(args.workers),
            )
        )
    wall_seconds = time.perf_counter() - wall_start
    cpu_seconds = time.process_time() - cpu_start
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    processed = sum(count for count, _ in results)
    latencies = [latency for _, samples in results for latency in samples]
    offered = args.events * args.workers
    report = {
        "benchmark": "feature_extractor.extract",
        "scope": "feature-extraction component; excludes collectors, queues, storage, and detection rules",
        "python": sys.version.split()[0],
        "workers": args.workers,
        "offered_events": offered,
        "processed_events": processed,
        "unprocessed_events": offered - processed,
        "wall_seconds": round(wall_seconds, 6),
        "cpu_seconds": round(cpu_seconds, 6),
        "throughput_events_per_second": round(processed / wall_seconds, 2),
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 4),
            "p95": round(percentile(latencies, 0.95), 4),
            "p99": round(percentile(latencies, 0.99), 4),
            "mean": round(statistics.fmean(latencies) / 1_000_000, 4),
        },
        "peak_traced_memory_bytes": peak_bytes,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
