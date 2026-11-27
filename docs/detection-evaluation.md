# Detection efficacy evaluation

## Dataset provenance

The benchmark uses CTU-IDSEVAL-6, a public labeled PCAP dataset published by
the Stratosphere Laboratory at CTU Prague.

- DOI: https://doi.org/10.5281/zenodo.21027042
- Record: https://zenodo.org/records/21027042
- License: Creative Commons Attribution 4.0 International (CC BY 4.0)
- Six captures: one benign user-traffic capture, two malware/C2 captures, and
  three port-scan captures.
- Dataset summary: 1,106,116 packets and 286,704 labeled Zeek flows.
- PCAP and labeled-Zeek archives are downloaded at runtime; dataset payloads
  are not committed to this repository.

The runner verifies the MD5 checksums published by Zenodo for transfer
integrity, extracts archives with path-traversal protection, and replays each
raw PCAP through the official, version-pinned zeek/zeek:9.0.1 container. It
aligns generated Zeek connection records with the dataset's labeled reference
logs and fails closed below 99.9% alignment.

## Metric semantics

Generated records are submitted to ArgusProwl's production Application event
processing pipeline, with a fresh application state and isolated SQLite files
for each capture.

A flow is a predicted positive only when a persisted alert names that exact
event as detection_source_event_id. Alerts without a source event are reported
separately and are not silently counted as true positives.

- Benign is the negative class.
- Malicious is the positive class.
- Background is excluded from binary confusion-matrix denominators and reported
  separately.
- Metrics: TP, FP, FN, TN, precision, recall, F1, and false-positive rate.
- Per-capture results are reported with aggregate micro metrics.

This is a baseline measurement, not a claim that every malicious behavior must
be detected by current rules. False positives on benign traffic and misses on
malware/C2 must remain visible. Do not tune thresholds against this evaluation
set; use a separate training split and held-out test split for future tuning.

## Run locally

Requirements: Docker, Python 3.13, project dependencies, and network access to
Zenodo and Docker Hub.

    uv sync --frozen
    uv run python scripts/evaluation/ctu_idseval.py \
      --workspace .tmp/ctu-idseval \
      --output .tmp/ctu-idseval-results.json

The JSON report records the dataset DOI/license, archive checksums, application
version, Git commit, Python version, Zeek image/version, per-capture counts,
and aggregate metrics.

## CI

The dedicated CTU-IDSEVAL-6 workflow is manually dispatchable and scheduled
weekly. It is separate from pull-request CI because it downloads research data
and processes six PCAPs through Zeek and the complete application pipeline.
The JSON report is retained as a workflow artifact.

## Limitations

- The benchmark is not representative of every enterprise network, modern
  encrypted application, endpoint event, or cloud workload.
- Flow-level source-event attribution can undercount detections whose alerts
  are attributed to an aggregate trigger. Those alerts remain separately visible.
- This does not replace analyst adjudication, production shadow deployment, or
  customer-specific false-positive measurement.
- Only public PCAPs are replayed; no live attack traffic is generated.
