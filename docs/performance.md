# Performance baseline

ArgusProwl has no production performance SLO or representative, versioned telemetry benchmark corpus yet. This harness establishes a repeatable starting point for the Python hot paths without claiming production capacity.

## Run locally

From the repository root:

```bash
uv run python scripts/benchmark_pipeline.py \
  --events 5000 \
  --warmup 250 \
  --repeats 5 \
  --output artifacts/pipeline-baseline.json
```

The command uses only the project runtime dependencies and Python's standard library. It creates temporary SQLite databases and removes them when each run completes.

## Workloads

| Workload | Measured path | Fixture validation |
| --- | --- | --- |
| `temporal_observe` | Normalized event observation and bounded temporal state update | One destination key and retained observation count |
| `feature_detection_dispatch` | Feature-vector dispatch through `DetectionManager` and `FailedConnectionsDetector` | Processed vectors and matched detections |
| `durable_evidence_ingestion` | `TelemetryEvidenceService.record_event` with SQLite evidence and relational entity projection | Persisted evidence record count |
| `entity_investigation_pivots` | Indexed entity, relationship, and evidence-reference queries | Non-empty entity, relationship, and evidence results |

Events and feature vectors are generated deterministically. Fixture setup and warm-up operations are excluded from the timed sample. Every timed operation records per-operation latency using `perf_counter_ns`; throughput uses the complete timed interval. Reported p50, p95, and p99 values use nearest-rank percentiles. Each repetition receives fresh state and, for persistence workloads, a fresh temporary database.

## CI baseline artifact

Backend CI runs a bounded smoke baseline with 1,000 measured operations, 100 warm-up operations, and three repetitions. It uploads `pipeline-benchmark.json` as the `pipeline-benchmark-<commit SHA>` artifact for 14 days.

The benchmark step is a correctness gate: exceptions, incomplete persistence, or empty pivot fixtures fail the job. Timing values do not fail CI. Shared runners, virtualization, and workload contention make hard timing thresholds unsuitable as a correctness test.

## Interpreting results

- Compare results only across the same workload configuration and comparable runner classes.
- Use medians across repetitions; investigate large run-to-run variance before interpreting small changes.
- Treat the CI artifact as a regression signal, not a production capacity estimate.
- Profile representative deployments before optimizing. Include parser cost, collector I/O, API overhead, concurrency, event cardinality, and retention behavior in a production-like test plan before setting throughput or latency SLOs.
- Preserve semantic parity, event ordering, evidence durability, and bounded-state behavior when optimizing a hot path.

## Rust decision

**Do not introduce a Rust implementation based on this baseline.** The repository does not yet define a production SLO or provide a representative telemetry corpus, and CI microbenchmarks do not establish that Python is the limiting factor under real collection and investigation workloads. A language port now would add build, packaging, deployment, and maintenance complexity without a measured acceptance target.

Revisit the decision only if profiling representative workloads identifies a stable CPU-bound Python hotspot, targeted Python and SQLite improvements fail to meet an agreed SLO, and a candidate Rust implementation can be tested against the same fixture with strict behavioral and evidence-integrity parity. Any future port should be isolated behind the existing domain boundary and justified by measured end-to-end improvement, not an isolated microbenchmark.

This benchmark intentionally excludes the private C2 research pipeline and does not introduce a Rust dependency or runtime component.
