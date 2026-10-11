# REPLAY ENGINE GUIDELINES — argusprowl

## Overview
The `ReplayEngine` (`src/argusprowl/replay/`) allows offline log files to be replayed through the production ingestion, parsing, feature engineering, and detection pipeline to validate rules and reproduce detections deterministically.

---

## 1. Core Principles & Semantic Parity

### Semantic Equivalence
- Replay processing must produce **identical** `DetectionResult` evidence, confidence scores, and `Alert` structures as live streaming processing for the exact same input telemetry.
- Replay must not modify production detection logic or bypass normal normalization.

### Production Parser Usage
- Replay tests and engines **must** use actual production parsers (e.g., `ZeekConnLogParser`, `SysmonParser`, `AuditdParser`) rather than injecting pre-parsed mock dictionaries.
- Ensure input log fixtures match actual production log formats (e.g., tab-delimited TSV Zeek logs, JSON Suricata logs, XML Sysmon logs).

---

## 2. Temporal & State Handling in Replay

### Time Preservation & Ordering
- Replay events must process in strictly chronological order based on the event timestamp embedded in the log records.
- Synthetic replay runs must control mock clock state if testing time-windowed aggregations or temporal bucket purges.

### State Isolation
- Every replay execution must instantiate isolated pipeline components (`ReplayEngine`, `DetectionManager`, `TemporalEngine`).
- State must never leak between consecutive replay runs or test cases.

### Duplicate Event Identity
- Replay engines must preserve raw `source_record_id` and `event_id` fields.
- Re-running the same replay log file multiple times into an active stateful instance must demonstrate idempotency: duplicate records are detected and ignored without inflating observation counts or statistics.

---

## 3. Fixture Standards for Replay Verification

When creating or modifying replay test fixtures:
1. **Use Real Log Headers**: Include valid header lines for structured log formats (e.g., `#fields ts uid id.orig_h id.orig_p...` for Zeek logs).
2. **Realistic Timestamps**: Use valid ISO-8601 or epoch timestamps with consistent delta intervals (e.g., 60.0s for regular beaconing).
3. **Complete Field Sets**: Ensure required fields for normalization (source IP, destination IP, ports, protocol) are present.
