"""Python side of the Python/Rust feature aggregation microbenchmark.

Measures the same synthetic per-source window aggregation as the Rust PoC.
This is not a full ArgusProwl pipeline benchmark.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from argusprowl.feature_engineering.aggregators import aggregate_connection_features
from argusprowl.models.normalized_event import NormalizedEvent


def make_event(sequence: int, base_time: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        source_type="benchmark",
        event_type="network_connection",
        timestamp=base_time + timedelta(microseconds=sequence),
        src_ip="192.0.2.1",
        src_port=40000 + sequence % 20000,
        dst_ip=f"198.51.100.{sequence % 250 + 1}",
        dst_port=(80, 443, 22, 8080)[sequence % 4],
        protocol="tcp",
        attributes={
            "conn_state": ("SF", "REJ", "S0", "OTH")[sequence % 4],
            "history": "S" if sequence % 3 == 0 else "ShADadfF",
            "duration": (sequence % 500) / 100.0,
            "orig_bytes": sequence % 4096,
            "resp_bytes": sequence % 8192,
        },
    )


def worker(events: int) -> tuple[int, float]:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    window: list[NormalizedEvent] = []
    checksum = 0.0
    for i in range(events):
        window.append(make_event(i, base))
        start = time.perf_counter_ns()
        features = aggregate_connection_features(window)
        checksum += (
            features["connection_count"] + features["unique_dst_ports"]
            + features["unique_dst_ips"] + features["unique_src_ports"]
            + features["failed_connections"] + features["syn_count"]
            + features["avg_duration"] + features["std_duration"]
            + features["min_duration"] + features["max_duration"]
            + features["total_bytes_sent"] + features["total_bytes_received"]
            + features["avg_bytes_per_connection"] + features["port_concentration"]
            + features["connection_rate"] + features["bytes_rate"]
            + int(features["is_multi_port"]) + int(features["is_multi_dst"])
            + features["time_since_first_connection"]
        )
        _ = time.perf_counter_ns() - start
    return events, checksum


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=1500)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()
    if args.events < 1 or args.workers < 1:
        parser.error("events and workers must be positive")
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(worker, [args.events] * args.workers))
    elapsed = time.perf_counter() - start
    processed = sum(x[0] for x in results)
    print(json.dumps({
        "language": "python",
        "python": __import__("sys").version.split()[0],
        "workers": args.workers,
        "offered_events": args.events * args.workers,
        "processed_events": processed,
        "unprocessed_events": args.events * args.workers - processed,
        "wall_seconds": round(elapsed, 6),
        "throughput_events_per_second": round(processed / elapsed, 2),
        "checksum": round(sum(x[1] for x in results), 9),
    }, indent=2))


if __name__ == "__main__":
    main()
