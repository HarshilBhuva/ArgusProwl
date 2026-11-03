# Performance benchmark and Rust readiness audit

## Executive conclusion

**Rust recommendation: DEFER.** No Rust implementation is included. A Rust decision is not supportable until representative production traffic, an agreed service-level objective (SLO), and a profile establish that a particular Python path is CPU-bound and remains material after low-risk Python optimization.

This PR currently provides a reproducible microbenchmark baseline for four real subsystem operations. It is not a complete measurement of the collector-to-alert production pipeline and must not be interpreted as evidence that ArgusProwl can sustain 1,000, 10,000, or 50,000 events/second.

## Environment and reproducibility

The benchmark report records Python version and implementation, operating-system/platform string, processor string when available, logical CPU count, workload configuration, UTC report time, per-operation latency percentiles, throughput, and every repetition. The CI environment observed for the initial PR validation was GitHub-hosted Ubuntu 24.04.5 LTS with CPython 3.13.18 and runner image `ubuntu-24.04` version `20261101.360.1`. This is runner metadata, not a developer workstation specification. The failed lint run did not reach benchmark execution, so it produced no baseline measurements.

The benchmark harness uses deterministic event IDs (UUIDv5) and fixed timestamps. It uses standard-library timing and temporary SQLite databases; there are no new benchmark dependencies.

Run locally from the repository root:

```bash
uv sync --frozen
uv run ruff check src tests scripts/benchmark_pipeline.py
uv run pytest -q tests/performance
uv run python scripts/benchmark_pipeline.py \
  --events 5000 --warmup 250 --repeats 5 \
  --output artifacts/pipeline-baseline.json
```

`--events` is the number of timed operations per repetition, not an arrival-rate target. The current harness bounds events to 100,000 per repetition and repetitions to 10. CI uses 1,000 timed operations, 100 warm-up operations, and three repetitions. Percentiles use nearest-rank calculation; the top-level latency and throughput are medians across repetitions. Fixture generation and warm-up operations are excluded from timed samples.

## Workloads that are currently measured

| Workload | Production method exercised | What correctness currently verifies |
| --- | --- | --- |
| Temporal observation | `TemporalEngine.observe(NormalizedEvent)` | One stable key and retained observation count |
| Detection dispatch | `DetectionManager.process_feature_vector(FeatureVector)` with `FailedConnectionsDetector` | Processed count, detector count, and matched-detection count |
| Durable evidence ingestion | `TelemetryEvidenceService.record_event(NormalizedEvent)` backed by `SQLiteAdapter` | Persisted telemetry evidence row count equals the fixture count |
| Entity investigation pivots | SQLite entity, relationship, and evidence-reference list methods | Each pivot returns populated results from the seeded fixture |

Each repeat constructs fresh state. SQLite workloads use temporary databases. Operation exceptions fail the benchmark; persistence count mismatch or empty pivot fixtures fail correctness checks. The harness does not silently drop operation exceptions.

## Production call-path inventory and coverage gaps

The inspected implementation provides the following paths. The current four workloads do not cover all the paths below.

| Area | Source / production entry point | Benchmark status and required next measurement |
| --- | --- | --- |
| Canonical event contract | `src/argusprowl/models/normalized_event.py`: `NormalizedEvent.__post_init__`, `to_dict`, `from_dict` | Not timed. Measure construction, serialization and round-trip separately; compare complete dictionaries including UUID, UTC timestamp, raw payload, tags, metadata and attributes. |
| Production application flow | `src/argusprowl/core/application.py`: application event-processing path; detection results then evidence recording | Not timed end-to-end. Build a production-wired replay test that records each stage and validates alert/evidence identities. |
| Replay | `src/argusprowl/replay/replay_engine.py`: replay reader/engine and detector callback | Not timed. Replay sanitized fixture files through the same configured services. |
| Collector and source parsing | `src/argusprowl/collectors/*` including Sysmon, Windows Event Log, Linux Audit, Zeek and Suricata | Not timed by this harness. No representative fixture corpus is bundled/validated by the benchmark. The exact parser classes and native formats must be enumerated before claiming parser coverage. |
| Collector registration and ingestion | `src/argusprowl/core/application.py` and `src/argusprowl/collectors` registry/lifecycle | Not timed. Audit configured collector registration, source I/O, batch boundaries and production queue behavior first. |
| Temporal tracking | `src/argusprowl/temporal/engine.py`: `TemporalEngine.observe` | Timed in isolation. Current one-key distribution is not representative of entity cardinality. |
| Feature extraction and detection | `src/argusprowl/detection/detection_manager.py`: `process_feature_vector`; replay/application flow creates feature vectors | Only dispatch with one detector and one repeated feature shape is timed. Feature extraction, multiple rules/detectors, DecisionEngine, AlertManager and deduplication are not timed. |
| Event-count correlation | Correlation/detector state under `src/argusprowl` | Not timed. Benchmark group cardinality, count-window rollover, snapshots and recovery with deterministic event streams. |
| Ordered sequence correlation | `src/argusprowl/detection/detectors/ordered_sequence_state.py`: `try_advance`, `to_dict`, `from_dict` | Not timed. Include sequence cardinality, successful/failed progression, late-event rejection and serialization/recovery. |
| Cardinality correlation | Cardinality correlation state and detector implementation | Not timed. Include low/high-cardinality and skewed group distributions. |
| Event-time ordering | Ordered-sequence watermark and late-event counter | Not timed. In-order-only performance is insufficient; verify out-of-order event behavior and late-event counts. No reorder buffer is established by the inspected ordered-sequence implementation; it rejects events behind the maximum event time. |
| Evidence persistence | `src/argusprowl/services/telemetry_evidence_service.py`: `record_event` and `src/argusprowl/storage/sqlite_storage.py` | Timed as an isolated durable write plus relational projection. The benchmark should additionally record database/WAL size, indexed lookup, query plan and recovery behavior. |
| Historical telemetry search | Indexed SQLite evidence search and keyset pagination in storage adapter | Not currently timed as a historical evidence search. Entity pivots are not substitutes for time-range/host/user/IP/domain combined filters. |
| Evidence retrieval | Evidence detail lookup in storage/service path | Not separately timed. Measure fetch by ID and verify referenced durable payload equality. |
| Hunt execution | `src/argusprowl/services/hunt_query_execution_service.py`: `execute` | Not timed. Needs scoped stored query fixtures, durable evidence matches and restart/recovery checks. |
| Alert/decision pipeline | DecisionEngine, AlertManager and deduplication services | Not timed in this harness. Must be exercised through application/replay call path for end-to-end numbers. |

### Why this is not yet a 1k/10k/50k events-per-second test

The CLI `--events` argument determines a finite number of sequential operation calls. It does not pace events at a configured rate, model concurrent collectors, drive a bounded ingestion queue, or measure queue wait/saturation/drop counts. It therefore cannot substantiate any target rate in the request. A rate test needs a monotonic producer schedule, an independently running real consumer path, explicit queue-depth and drop counters, run duration, and a correctness reconciliation of submitted, accepted, processed, persisted and rejected events. A target that cannot be reached must still record backlog and loss rather than silently reducing the workload.

## Benchmark methodology and limits

- Workload construction is deterministic: fixed timestamp origin, stable UUIDv5 identities, fixed host/user/network/process attributes, and fixed feature vector shape.
- Warm-up work is performed before each timed measurement; each repeat receives newly constructed subsystem state and a fresh temporary DB where applicable.
- Every operation is timed with `time.perf_counter_ns`. Throughput is measured over the full timed loop. Per-operation p50/p95/p99 use nearest-rank percentiles.
- Timings are descriptive, not pass/fail thresholds. Compare only matching configurations and comparable machine classes; use repeated-run medians and investigate variance.
- The current JSON does not measure process CPU utilization, peak/RSS memory, Python allocation counts, queue wait, queue saturation, dropped events, serialization cost, DB growth/WAL growth, or end-to-end pipeline latency.
- The current synthetic event distribution is a single network-connection shape with one host, one source address, one destination, and one process. It omits large command lines, raw Sysmon XML, Windows Event Log, Linux Audit, Zeek JSON/TSV, Suricata EVE JSON, invalid payloads, high-cardinality entities, burstiness and late-event distributions.
- It does not currently profile the workload with cProfile/py-spy/tracemalloc or report SQLite `EXPLAIN QUERY PLAN` output.
- No production or sanitized telemetry fixture corpus was ingested during this validation. No performance result is fabricated or inferred from test counts.

## Bottleneck findings

There is not enough measured runtime data to classify any component as the dominant bottleneck. The following are code-path hypotheses to profile, not measured bottlenecks:

| Source / operation | Current measured cost | Likely cost class to test | First investigation |
| --- | --- | --- | --- |
| `NormalizedEvent.to_dict` | Not measured | CPU/allocation | `copy.deepcopy` on raw payload, metadata and attributes; benchmark by payload size and immutability contract before changing. |
| `TemporalEngine.observe` | Reported by harness when it successfully runs | CPU + lock contention | Observation allocation and per-event lock; test many keys and concurrent producers before optimization. |
| `DetectionManager.process_feature_vector` | Reported by harness when it successfully runs | CPU | Cost by enabled detector count and feature extraction; avoid repeated feature work only after profiles confirm it. |
| `OrderedSequenceState.try_advance` | Not measured | CPU + lock + cardinality | Iteration over retained partial sequences, condition matching, snapshot size; include late events. |
| `TelemetryEvidenceService.record_event` / SQLite writes | Reported by harness when it successfully runs | Primarily I/O/transaction; some Python serialization/projection CPU | Separate JSON serialization, relational projection, transaction and fsync/WAL costs. |
| Entity pivots | Reported by harness when it successfully runs | SQLite I/O/index selection | Capture query plans, DB/WAL growth and result cardinality; do not label SQLite I/O as a Python CPU bottleneck. |
| Collector parsing and full replay | Not measured | Parser-dependent CPU and input I/O | Profile each native parser with representative fixtures and invalid-event cases. |
| Hunt search and historical evidence retrieval | Not measured | SQLite I/O/indexing | Capture query plans and latency over increasing DB sizes and combined predicates. |

## Python optimization assessment

No optimization is implemented in this PR because no stable production bottleneck has been measured. Candidate low-risk work, conditional on profiling:

1. **Serialization:** avoid deep-copying large immutable payloads only if callers cannot mutate data after event construction or the API contract is deliberately revised; otherwise preserve defensive copying.
2. **Detection:** compute feature values once per event/window and reuse immutable results; measure the extraction/dispatch split first.
3. **Correlation:** reduce lock hold time and repeated scans only after proving equivalent event-time, late-event, snapshot and recovery semantics.
4. **SQLite:** inspect `EXPLAIN QUERY PLAN`, batch transaction boundaries where durability semantics permit, verify indexes and keyset pagination before considering code-language changes.
5. **Ingestion:** benchmark actual bounded queue producer/consumer behavior; expose and reconcile queue wait, saturation and drop counters before changing batching or backpressure.

## Rust decision matrix

The “current cost” column deliberately says “not measured” where this PR has no timing data. It must not be replaced with estimated values.

| Component | Current cost | Bottleneck type | Python optimization | Rust potential | Recommendation |
| --- | --- | --- | --- | --- | --- |
| Source parsing | Not measured | Unknown; parser CPU vs input I/O | Profile parsers; reduce conversions/repeated parsing; use existing native XML/JSON libraries efficiently | Potentially useful only if parser dominates measured CPU and native libraries/Python tuning are insufficient; PyO3 may avoid process IPC | DEFER |
| NormalizedEvent construction/serialization | Not measured | Likely allocation/CPU; unconfirmed | Measure deepcopy/JSON cost and payload sizes; preserve contract | Could accelerate transformation but boundary conversion/ownership costs may erase gains | DEFER |
| Feature extraction/detection | Dispatch microbenchmark exists; no end-to-end cost yet | Unknown | Avoid repeated feature computation; profile enabled-rule scaling | Candidate only if stable CPU-bound Python loops dominate | DEFER |
| Temporal/correlation state | Temporal observe microbenchmark exists; count/sequence/cardinality missing | CPU, locks and cardinality all possible | Profile lock contention, scans, bounded-state data structures | Candidate only for measured CPU-heavy state transitions; keep state contract and recovery parity | DEFER |
| SQLite evidence/search | Isolated evidence write and entity pivots are timed when harness runs; actual values pending | Primarily DB I/O/transaction/indexes | Query plans, indexes, transaction/batch tuning, payload work | Low expected value for I/O-bound SQLite work; Rust does not remove SQLite storage latency | NO-GO for DB port |
| Hunt execution | Not measured | Likely mixed DB I/O and query evaluation | Optimize search plans and avoid redundant retrieval | Only consider measured CPU predicate evaluation, not storage calls | DEFER |
| Full ingest-to-alert pipeline | Not measured | Unknown across collection, parsing, queue, detection, persistence | Instrument each stage and establish SLO | No candidate can be justified until stage-level profiles identify one | DEFER |

## Profiling and next measurement protocol

On a controlled representative host, run the benchmark and capture independent profiles. Example commands (optional tools are not added to project dependencies):

```bash
# cProfile for deterministic Python call attribution
uv run python -m cProfile -o /tmp/argusprowl.prof \
  scripts/benchmark_pipeline.py --events 5000 --warmup 250 --repeats 3
uv run python - <<'PY'
import pstats
pstats.Stats("/tmp/argusprowl.prof").strip_dirs().sort_stats("cumtime").print_stats(40)
PY

# Allocation attribution (run separately; profiling changes timings)
PYTHONTRACEMALLOC=1 uv run python scripts/benchmark_pipeline.py \
  --events 5000 --warmup 250 --repeats 3

# py-spy, where installed and permitted
py-spy record -- python scripts/benchmark_pipeline.py --events 5000
```

For SQLite, capture `EXPLAIN QUERY PLAN` for each indexed historical search and investigation pivot query at several database sizes. Record SQLite version, page count, DB bytes, WAL bytes and integrity/recovery outcomes. Do not compare instrumented profile timings with uninstrumented benchmark timing.

## CI and regression policy

Backend CI runs a small correctness-gated benchmark smoke and uploads the JSON as a 14-day artifact when the step is reached. Wall-clock thresholds are intentionally not gating because general hosted runners are noisy. Ruff, full backend tests, Bandit and Docker integration remain independent checks. Frontend checks are unaffected by this benchmark-only change and must still be considered in the PR's required checks.

## Result status

At the initial PR head validation, Bandit passed and the Docker image built and health check passed. Backend CI stopped at Ruff before running the backend suite or benchmark; the linter reported the `Callable` import in `scripts/benchmark_pipeline.py` should come from `collections.abc`. No artifact was produced and no throughput, latency, CPU or memory result is claimed from that run. The follow-up lint correction must be validated on a new exact PR head commit before any numerical baseline is reported.

## Final decision

**DEFER Rust.** The current suite is a useful subsystem microbenchmark seed, not evidence for a Rust migration and not yet the full performance audit requested. Keep the stable `NormalizedEvent` contract and current architecture unchanged. Complete the missing production parser, queue, correlation, historical search, hunt, profiling and end-to-end benchmarks before drawing a per-component go/no-go conclusion.
