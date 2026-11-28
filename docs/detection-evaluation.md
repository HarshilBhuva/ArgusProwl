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
for each capture. ArgusProwl's bounded, rule-based temporal periodicity
analytics remain enabled with explicit limits. This measures ArgusProwl's
network-hunting signals, including its generic periodicity rule; it does not
load or evaluate CHIMERA's separate ML-based C2 detector.

A flow is a predicted positive only when a matched DetectionResult explicitly
references that event as its event_id (the event that crossed the detector
threshold) or one of its contributing_event_ids (events retained as evidence
for the aggregate detection). The evaluator captures these references before
alert deduplication: deduplication controls notification volume and must not
turn suppressed duplicate alerts into detector false negatives. Host/IP grouping,
alert descriptions, and inferred campaign membership are never used to assign
flow-level positives. Persisted alert counts are reported separately.

- Benign is the negative class.
- Malicious is the positive class.
- Background is excluded from binary confusion-matrix denominators and reported
  separately.
- Metrics: TP, FP, FN, TN, precision, recall, F1, and false-positive rate.
- Per-capture results are reported with aggregate micro metrics.

This is a baseline measurement, not a claim that every malicious behavior must
be detected by current rules. The malware captures include C2-labeled activity,
but ArgusProwl's generic periodicity signal is not equivalent to CHIMERA's
model-based C2 detection. False positives on benign traffic and missed
malicious flows remain visible. Do not tune thresholds against this evaluation
set; use a separate training split and held-out test split for future tuning.

## Observed CI report integrity issue (2026-11-28)

The first post-provenance-fix CTU workflow (run
[46132571003](https://github.com/HarshilBhuva/ArgusProwl/actions/runs/46132571003),
artifact `ctu-idseval-6-report`) produced a report whose source commit was
`c11e6d2adaaf88c49900e0e40544783b6eb56c0f`, a merge commit containing the
evaluated PR code at `c7467d6db753d7a71faf1d8a7aef7c8461bfec0c).

That report is **not accepted as a valid efficacy result**. For
`malicious-malware-2`, it reports 185,506 generated flows but only 28,225
matched labeled events, while also claiming zero unlabeled generated flows.
Those fields do not reconcile. The evaluator stores labels by
`NormalizedEvent.event_id`; a duplicate identity can overwrite an earlier
label and make coverage appear complete when generated records were not
individually represented. Its UID-first fallback matching also consumed the
flow-key queue twice on fallback matches.

The evaluator now fails closed on duplicate event IDs, consumes at most one
reference row per generated flow, and checks the accounting identity:

`processed = labeled_generated_flows + unlabeled_generated_flows`

A rerun must complete on the corrected evaluator before any CTU precision,
recall, F1, or false-positive rate is treated as a validated result. The
previous run's low malware metrics remain a reason for caution, but they are
not accepted as final detector-quality measurements until coverage integrity
is established. The report's 71.3% aggregate F1 must not be used in marketing
or project claims.

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
- Flow-level metrics score explicit DetectionResult provenance before alert
  deduplication. Aggregate detectors must retain the trigger event and bounded
  contributing event IDs; missing provenance remains a detection-evidence
  defect rather than an inferred TP. Persisted alert counts are operational
  output metrics, not detector recall.
- This does not replace analyst adjudication, production shadow deployment, or
  customer-specific false-positive measurement.
- Only public PCAPs are replayed; no live attack traffic is generated.
