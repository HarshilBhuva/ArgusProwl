"""Tests for the reproducible pipeline benchmark harness."""

from __future__ import annotations

import pytest
from scripts.benchmark_pipeline import BenchmarkConfig, run_benchmark


def test_benchmark_reports_all_workloads_and_validates_fixture_processing() -> None:
    report = run_benchmark(BenchmarkConfig(events=12, warmup=2, repeats=1))

    assert report["schema_version"] == 1
    workloads = report["workloads"]
    assert set(workloads) == {
        "temporal_observe",
        "feature_detection_dispatch",
        "durable_evidence_ingestion",
        "entity_investigation_pivots",
    }

    temporal = workloads["temporal_observe"]["repetitions"][0]
    assert temporal["units_processed"] == 12
    assert temporal["validation"]["tracked_keys"] == 1
    assert temporal["validation"]["retained_observations"] == 14

    detection = workloads["feature_detection_dispatch"]["repetitions"][0]
    assert detection["units_processed"] == 12
    assert detection["validation"]["processed_vectors"] == 14
    assert detection["validation"]["matched_detections"] == 14

    ingestion = workloads["durable_evidence_ingestion"]["repetitions"][0]
    assert ingestion["units_processed"] == 12
    assert ingestion["validation"]["persisted_records"] == 14
    assert ingestion["validation"]["expected_records"] == 14

    pivots = workloads["entity_investigation_pivots"]["repetitions"][0]
    assert pivots["units_processed"] == 12
    assert pivots["validation"]["fixture_events"] == 14
    assert pivots["validation"]["entity_count"] > 0
    assert pivots["validation"]["relationship_count"] > 0
    assert pivots["validation"]["evidence_reference_count"] > 0


def test_benchmark_latency_percentiles_are_monotonic_and_throughput_positive() -> None:
    report = run_benchmark(BenchmarkConfig(events=4, warmup=0, repeats=1))

    for workload in report["workloads"].values():
        repetition = workload["repetitions"][0]
        latency = repetition["latency_us"]
        assert 0 < latency["p50"] <= latency["p95"] <= latency["p99"]
        assert repetition["units_per_second"] > 0


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"events": 1}, "events must be between"),
        ({"warmup": -1}, "warmup must be between"),
        ({"repeats": 0}, "repeats must be between"),
        ({"max_observations": 0}, "max_observations must be positive"),
        ({"events": True}, "Benchmark counts must be integers"),
    ],
)
def test_benchmark_rejects_invalid_configuration(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        BenchmarkConfig(**kwargs)
