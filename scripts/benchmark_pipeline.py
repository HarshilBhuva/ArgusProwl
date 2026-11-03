"""Reproducible microbenchmarks for ArgusProwl's Python hot paths.

The benchmark intentionally reports measurements without enforcing timing
thresholds. CI runner timings are useful baselines, not production capacity
claims or release SLOs.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable, TypeVar
from uuid import NAMESPACE_URL, uuid5

from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detectors.failed_connections import FailedConnectionsDetector
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService
from argusprowl.storage.sqlite_storage import SQLiteAdapter
from argusprowl.temporal.engine import TemporalEngine

T = TypeVar("T")
_OPERATION_LIMIT = 100_000
_REPEAT_LIMIT = 10
_BASE_TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    """Bounded workload configuration for one benchmark report."""

    events: int = 5_000
    warmup: int = 250
    repeats: int = 3
    max_observations: int = 1_000

    def __post_init__(self) -> None:
        values = {
            "events": self.events,
            "warmup": self.warmup,
            "repeats": self.repeats,
            "max_observations": self.max_observations,
        }
        if any(not isinstance(value, int) or isinstance(value, bool) for value in values.values()):
            raise ValueError("Benchmark counts must be integers.")
        if not 2 <= self.events <= _OPERATION_LIMIT:
            raise ValueError(f"events must be between 2 and {_OPERATION_LIMIT}.")
        if not 0 <= self.warmup <= 10_000:
            raise ValueError("warmup must be between 0 and 10000.")
        if not 1 <= self.repeats <= _REPEAT_LIMIT:
            raise ValueError(f"repeats must be between 1 and {_REPEAT_LIMIT}.")
        if self.max_observations < 1:
            raise ValueError("max_observations must be positive.")


class PipelineBenchmark:
    """Run repeatable event, detection, persistence, and pivot workloads."""

    def __init__(self, config: BenchmarkConfig) -> None:
        self.config = config
        self._events = self._build_events(config.events + config.warmup)
        self._feature_vectors = self._build_feature_vectors(self._events)

    def run(self) -> dict[str, object]:
        """Execute every workload and return a versioned JSON-compatible report."""
        workloads = {
            "temporal_observe": self._repeat(self._measure_temporal_observe),
            "feature_detection_dispatch": self._repeat(self._measure_feature_detection),
            "durable_evidence_ingestion": self._repeat(self._measure_durable_ingestion),
            "entity_investigation_pivots": self._repeat(self._measure_entity_pivots),
        }
        return {
            "schema_version": 1,
            "benchmark": "argusprowl-python-pipeline-baseline",
            "created_at": datetime.now(UTC).isoformat(),
            "config": asdict(self.config),
            "environment": {
                "python_version": platform.python_version(),
                "python_implementation": sys.implementation.name,
                "platform": platform.platform(),
                "processor": platform.processor() or "unknown",
                "cpu_count": os.cpu_count(),
            },
            "workloads": workloads,
        }

    def _repeat(self, measure: Callable[[], dict[str, object]]) -> dict[str, object]:
        repetitions = [measure() for _ in range(self.config.repeats)]
        throughputs = [float(item["units_per_second"]) for item in repetitions]
        percentiles = {
            name: round(
                statistics.median(
                    float(item["latency_us"][name])  # type: ignore[index]
                    for item in repetitions
                ),
                3,
            )
            for name in ("p50", "p95", "p99")
        }
        return {
            "units_per_repeat": self.config.events,
            "median_units_per_second": round(statistics.median(throughputs), 2),
            "median_latency_us": percentiles,
            "repetitions": repetitions,
        }

    def _measure_items(
        self,
        operation: Callable[[T], object],
        warmup_items: list[T],
        measured_items: list[T],
        *,
        unit: str,
    ) -> dict[str, object]:
        for item in warmup_items:
            operation(item)

        latencies: list[float] = []
        started = time.perf_counter_ns()
        for item in measured_items:
            item_started = time.perf_counter_ns()
            operation(item)
            latencies.append((time.perf_counter_ns() - item_started) / 1_000.0)
        elapsed_ns = time.perf_counter_ns() - started
        if elapsed_ns <= 0:
            raise RuntimeError("Benchmark clock returned a non-positive elapsed duration.")

        elapsed_seconds = elapsed_ns / 1_000_000_000
        return {
            "unit": unit,
            "units_processed": len(measured_items),
            "duration_seconds": round(elapsed_seconds, 6),
            "units_per_second": round(len(measured_items) / elapsed_seconds, 2),
            "latency_us": {
                "p50": round(self._percentile(latencies, 0.50), 3),
                "p95": round(self._percentile(latencies, 0.95), 3),
                "p99": round(self._percentile(latencies, 0.99), 3),
            },
        }

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float:
        ordered = sorted(values)
        rank = max(1, math.ceil(percentile * len(ordered)))
        return ordered[rank - 1]

    def _measure_temporal_observe(self) -> dict[str, object]:
        engine = self._new_temporal_engine()
        result = self._measure_items(
            engine.observe,
            self._events[: self.config.warmup],
            self._events[self.config.warmup :],
            unit="events",
        )
        analysis = engine.get_analysis(
            "198.51.100.10",
            4444,
            src_ip="192.0.2.10",
        )
        result["validation"] = {
            "tracked_keys": engine.get_key_count(),
            "retained_observations": analysis["count"] if analysis is not None else 0,
        }
        return result

    def _measure_feature_detection(self) -> dict[str, object]:
        manager = DetectionManager()
        detector = FailedConnectionsDetector(min_failed_ratio=0.5, min_failed_count=10)
        manager.register_detector(detector)
        result = self._measure_items(
            manager.process_feature_vector,
            self._feature_vectors[: self.config.warmup],
            self._feature_vectors[self.config.warmup :],
            unit="feature_vectors",
        )
        result["validation"] = {
            "processed_vectors": manager.processed_count,
            "matched_detections": manager.detection_count,
            "registered_detectors": manager.detector_count,
        }
        return result

    def _measure_durable_ingestion(self) -> dict[str, object]:
        with tempfile.TemporaryDirectory(prefix="argusprowl-benchmark-") as directory:
            storage = SQLiteAdapter(Path(directory) / "evidence.db")
            try:
                evidence = TelemetryEvidenceService(
                    max_retained_events=self.config.events + self.config.warmup + 1,
                    storage=storage,
                )
                result = self._measure_items(
                    evidence.record_event,
                    self._events[: self.config.warmup],
                    self._events[self.config.warmup :],
                    unit="events",
                )
                expected_records = self.config.events + self.config.warmup
                persisted_records = storage.list_records(
                    "telemetry_evidence",
                    limit=expected_records + 1,
                )
                if len(persisted_records) != expected_records:
                    raise RuntimeError(
                        "Durable ingestion benchmark did not persist every fixture event: "
                        f"expected {expected_records}, found {len(persisted_records)}."
                    )
                result["validation"] = {
                    "persisted_records": len(persisted_records),
                    "expected_records": expected_records,
                }
                return result
            finally:
                storage.close()

    def _measure_entity_pivots(self) -> dict[str, object]:
        with tempfile.TemporaryDirectory(prefix="argusprowl-pivots-") as directory:
            storage = SQLiteAdapter(Path(directory) / "pivots.db")
            try:
                evidence = TelemetryEvidenceService(
                    max_retained_events=self.config.events + self.config.warmup + 1,
                    storage=storage,
                )
                fixture_events = self._events[: min(len(self._events), 250)]
                for event in fixture_events:
                    evidence.record_event(event)

                def query_pivots(_: int) -> None:
                    entities = storage.list_entity_intelligence_entities(limit=100)
                    relationships = storage.list_entity_intelligence_relationships(
                        "hostname",
                        "BENCHMARK-HOST",
                        direction="both",
                        limit=100,
                    )
                    references = storage.list_entity_intelligence_evidence(
                        "hostname",
                        "BENCHMARK-HOST",
                        limit=100,
                    )
                    if not entities or not relationships or not references:
                        raise RuntimeError("Entity pivot benchmark fixture is incomplete.")

                result = self._measure_items(
                    query_pivots,
                    list(range(self.config.warmup)),
                    list(range(self.config.events)),
                    unit="queries",
                )
                result["validation"] = {
                    "fixture_events": len(fixture_events),
                    "entity_count": len(storage.list_entity_intelligence_entities(limit=100)),
                    "relationship_count": len(
                        storage.list_entity_intelligence_relationships(
                            "hostname",
                            "BENCHMARK-HOST",
                            direction="both",
                            limit=100,
                        )
                    ),
                    "evidence_reference_count": len(
                        storage.list_entity_intelligence_evidence(
                            "hostname",
                            "BENCHMARK-HOST",
                            limit=100,
                        )
                    ),
                }
                return result
            finally:
                storage.close()

    def _new_temporal_engine(self) -> TemporalEngine:
        window = timedelta(days=30)
        return TemporalEngine(
            max_keys=32,
            max_observations_per_key=self.config.max_observations,
            window_duration=window,
            allowed_lateness=window,
        )

    @staticmethod
    def _build_events(count: int) -> list[NormalizedEvent]:
        return [
            NormalizedEvent(
                source_type="benchmark",
                event_type="network_connection",
                timestamp=_BASE_TIMESTAMP + timedelta(seconds=index * 30),
                hostname="BENCHMARK-HOST",
                src_ip="192.0.2.10",
                src_port=40_000 + (index % 20),
                dst_ip="198.51.100.10",
                dst_port=4444,
                protocol="tcp",
                username="benchmark-user",
                process_name="benchmark-agent",
                pid=4242,
                attributes={"direction": "outbound"},
                event_id=uuid5(NAMESPACE_URL, f"argusprowl-benchmark-event:{index}"),
                source_record_id=f"benchmark-record:{index}",
            )
            for index in range(count)
        ]

    @staticmethod
    def _build_feature_vectors(events: list[NormalizedEvent]) -> list[FeatureVector]:
        return [
            FeatureVector(
                event_id=event.event_id,
                window_start=event.timestamp,
                window_end=event.timestamp + timedelta(minutes=1),
                src_ip="192.0.2.10",
                dst_ip="198.51.100.10",
                src_port=40_000,
                dst_port=4444,
                proto="tcp",
                connection_count=20,
                failed_connections=15,
                unique_dst_ports=1,
                unique_dst_ips=1,
            )
            for event in events
        ]


def run_benchmark(config: BenchmarkConfig) -> dict[str, object]:
    """Convenience entry point for tests and programmatic benchmark use."""
    return PipelineBenchmark(config).run()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure reproducible ArgusProwl Python pipeline baselines."
    )
    parser.add_argument("--events", type=int, default=5_000)
    parser.add_argument("--warmup", type=int, default=250)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--max-observations", type=int, default=1_000)
    parser.add_argument("--output", type=Path, help="Optional JSON report path.")
    args = parser.parse_args(argv)

    config = BenchmarkConfig(
        events=args.events,
        warmup=args.warmup,
        repeats=args.repeats,
        max_observations=args.max_observations,
    )
    report = run_benchmark(config)
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"

    if args.output is None:
        print(serialized, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
        summary = {
            name: workload["median_units_per_second"]
            for name, workload in report["workloads"].items()  # type: ignore[union-attr]
        }
        print(f"Wrote benchmark report to {args.output}")
        print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
