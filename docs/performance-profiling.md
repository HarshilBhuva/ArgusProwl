# ArgusProwl performance profiling

## Purpose

The real-PCAP benchmark measures end-to-end behavior, but elapsed time alone does not identify the functions responsible for CPU cost. The benchmark now runs one additional, isolated Python replay under the standard-library cProfile profiler. That replay is stored separately and is not included in the normal timing samples.

## CI workflow

The Rust/Python real-PCAP benchmark profiles `malicious-malware-1` by default after its ordinary unprofiled repetitions. The artifact JSON contains:

- `profiles[capture].profile_cumulative_top_50`: top functions ranked by cumulative time, including time in callees.
- `profiles[capture].profile_self_time_top_50`: top functions ranked by time spent in the function body, excluding callees.
- The ordinary per-capture timing samples remain unprofiled.

The profile replay is a diagnostic sample, not a benchmark result. Do not compare its wall time with the unprofiled replay or use it to claim a speedup.

## Local use

Run the same benchmark harness with a selected capture:

```bash
uv sync --frozen
uv run python scripts/evaluation/rust_python_pcap_benchmark.py \
  --workspace .tmp/rust-python-benchmark \
  --output .tmp/rust-python-benchmark/report.json \
  --packethawk-bin .tmp/PacketHawk/target/release/packethawk \
  --repeats 1 \
  --stress-packets 262144 \
  --profile-capture malicious-malware-1
```

Inspect the JSON profile sections before changing hot paths. Optimization acceptance requires semantic equivalence tests and a repeat of the same unprofiled real-PCAP and derived saturation workloads. Rust should be introduced only for a measured hotspot where an equivalent implementation demonstrates a material end-to-end benefit without weakening correctness, bounded-state behavior, or maintainability.

## Interpretation constraints

PacketHawk processes raw packets; ArgusProwl processes Zeek-normalized events. Those are different pipelines. Their throughput numbers are not an apples-to-apples Rust-versus-Python comparison. This profile is specifically for identifying ArgusProwl Python costs.
