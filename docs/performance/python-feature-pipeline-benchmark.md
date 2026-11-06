# Python Feature Pipeline Benchmark

## Scope

The benchmark at `scripts/benchmarks/feature_pipeline.py` measures the
`FeatureExtractor.extract` component using deterministic synthetic
`NormalizedEvent` objects. It reports offered and processed event counts,
wall-clock throughput, process CPU time, p50/p95/p99 call latency, and peak
traced Python memory.

It is **not** an end-to-end collector-to-alert benchmark. It does not measure
queue depth, queue drops, storage latency, rule evaluation, or network capture.
Do not present its throughput as full ArgusProwl pipeline throughput.

## Reproduction

Run from the repository root in the project's Python environment:

```bash
python scripts/benchmarks/feature_pipeline.py --events 20000 --workers 4
```

Use the same Python version, host, power profile, and arguments for baseline
and candidate runs. Run each configuration at least five times; report the
median run and retain individual JSON outputs. Test at multiple worker counts
(e.g. 1, 2, 4, 8) and event counts (e.g. 1,000, 10,000, 50,000).

## Interpretation

- `offered_events`: number of synthetic events submitted to extractors.
- `processed_events`: events for which extraction returned a feature vector.
- `unprocessed_events`: offered minus processed; expected to be zero for this
  harness.
- `throughput_events_per_second`: processed events divided by wall time.
- Latencies include event construction? No. Timing starts immediately before
  `extract` and ends immediately after it.
- `peak_traced_memory_bytes` is Python allocation tracing, not total RSS and
  not a substitute for operating-system resident-set measurements.
- Thread workers exercise shared interpreter scheduling and independent source
  windows; they do not imply CPU-parallel Python execution under the GIL.

## Optimization notes

The current candidate reduces temporary allocations in connection aggregation
by maintaining duration moments and byte totals in the aggregation pass rather
than materializing duration and byte lists. It also avoids rebuilding a
separate sort-key list for out-of-order window insertion, and caches
FeatureVector field metadata at module import.

These changes require correctness and full-suite validation before any
performance claim is made. Capture baseline and candidate outputs under the
same conditions before documenting a speedup.
