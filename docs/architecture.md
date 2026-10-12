# Architecture Documentation – argusprowl

## Architectural Philosophy

argusprowl is designed following **Clean Architecture** principles. The core domain and infrastructure are strictly decoupled from operational modules and external integrations.

```
       +-------------------------------------------------------+
       |                     CLI (python -m argusprowl)                     |
       +-------------------------------------------------------+
                                   |
                                   v
       +-------------------------------------------------------+
       |               Application Lifecycle Core              |
       |              (src/argusprowl/core/application.py)     |
       +-------------------------------------------------------+
             |                     |
             v                     v
   +-------------------+ +-------------------+
   | Config Subsystem  | | Logging Subsystem |
   | (ConfigManager)   | | (LoggerFactory)   |
   +-------------------+ +-------------------+
             \                     |                     /
              +--------------------+--------------------+
                                   |
                                   v
       +-------------------------------------------------------+
       |               Dependency Injection Container          |
       |                (ServiceContainer / IoC)               |
       +-------------------------------------------------------+
                                   |
                                   v
       +-------------------------------------------------------+
       |                  Interfaces / Contracts               |
       | (LogSource, Parser, Detector, RuleEngine, Alert, etc) |
       +-------------------------------------------------------+
```

## Layer Responsibilities

1. **Constants & Exceptions (`src/argusprowl/constants/`, `src/argusprowl/exceptions/`)**:
   - Zero-dependency base layer containing application path resolvers, log names, exit codes, severity enums, and exception hierarchy.

2. **Models (`src/argusprowl/models/`)**:
   - Pure, validated data containers (dataclasses) representing domain entities: `Alert`, `Event`, `NormalizedEvent`, `DetectionResult`, `Incident`, `SystemStatus`, and `AppConfiguration`.

3. **Interfaces (`src/argusprowl/interfaces/`)**:
   - Strict Abstract Base Classes (`ABC`) defining contract rules for all future pipeline components (Parsers, Detectors, Rule Engines, Alert Providers, Reporters, Storage, and Plugins).

4. **Utilities (`src/argusprowl/utils/`)**:
   - Stateless helper modules for file operations, JSON serialization, path safety, data validation, and UTC datetime management.

5. **Configuration System (`src/argusprowl/config/`)**:
   - Settings loader merging default configs, YAML overrides, and environment variables (`TH_` prefixed). Validates inputs and supplies typed `AppConfiguration` instances.

6. **Logging System (`src/argusprowl/logging/`)**:
   - Centralized `LoggerFactory` offering ANSI colored console output, rotating file logs, and structured JSON logs.

7. **Event System**: Removed in Phase 4.2S. Events now flow directly through bounded queues.

8. **Dependency Injection (`src/argusprowl/dependency_injection/`)**:
   - Thread-safe `ServiceContainer` supporting singleton and transient service resolution.

9. **Services & Core (`src/argusprowl/services/`, `src/argusprowl/core/`)**:
   - System diagnostics (`HealthService`) and application lifecycle orchestration (`Application`).

10. **Feature Engineering (`src/argusprowl/feature_engineering/`)**:
    - Sliding window aggregation, statistical calculations, and feature vector generation.
    - Transforms normalized events into feature vectors suitable for detection.

11. **Detection (`src/argusprowl/detection/`)**:
    - Detector registry, detection manager, and concrete detector implementations.
    - YAML-backed rule configuration for easy extension with new detection rules.

12. **Temporal (`src/argusprowl/temporal/`)**:
    - Bounded in-memory state tracking for beaconing detection.
    - Periodicity calculation using coefficient of variation.
    - Thread-safe for concurrent collector access.

13. **Decision Engine (`src/argusprowl/decision_engine/`)**:
    - Alert creation, deduplication, correlation, severity normalization, and suppression.
    - Only component authorized to create final Alert objects.

14. **Alerting (`src/argusprowl/alerting/`)**:
    - Alert manager and pluggable alert providers (console, JSON, email, Slack, etc.).
    - Supports multiple output destinations without modifying core logic.

15. **Metrics (`src/argusprowl/metrics/`)**:
    - Lightweight, thread-safe metrics collection (Counters, Gauges, Histograms).
    - Provides observability into system performance and operational health.

16. **Replay (`src/argusprowl/replay/`)**:
    - Log replay engine for testing and debugging detection pipelines.
    - Reuses production ingestion and detection components.

17. **Storage adapters (`src/argusprowl/storage/`)**:
    - Repositories depend only on the `Storage` contract. `SQLiteAdapter` is the local Phase 1 implementation; PostgreSQL, ClickHouse, and Redis adapters are intentionally documented skeletons.
    - This boundary prevents business logic from acquiring database-specific imports and lets deployment topology change without rewriting use cases.

17. **Plugins**: Plugin framework removed in Phase 4.2S. No dynamic plugin loading infrastructure exists.

## Data Flow

The complete detection pipeline flows as follows:

```
Collector
    ↓
Parser
    ↓
NormalizedEvent
    ↓
Direct bounded/event queue
    ↓
Processing loop
    ↓
FeatureExtractor (src/argusprowl/feature_engineering/feature_extractor.py)
    ↓ [SlidingWindow aggregation]
FeatureVector (src/argusprowl/feature_engineering/feature_vector.py)
    ↓
DetectionManager (src/argusprowl/detection/detection_manager.py)
    ↓
Detectors (src/argusprowl/detection/detectors/*.py)
    ↓
DetectionResult (src/argusprowl/models/detection_result.py)
    ↓
DecisionEngine (src/argusprowl/decision_engine/decision_engine.py)
    ↓ [Deduplication, Severity Normalization]
Alert (src/argusprowl/models/alert.py)
    ↓
AlertManager (src/argusprowl/alerting/alert_manager.py)
    ↓
AlertProviders (src/argusprowl/alerting/*_provider.py)
    ↓
Console / JSON / Future Providers
```

### Current ingestion flow

```
Collector → Parser → NormalizedEvent → Direct queue → Processing loop → Feature Engineering → Detection
```

`NormalizedEvent` is the stable boundary after parsing. It carries schema version, UUID identity, UTC timestamp, common host/network/process fields, raw source data, tags, metadata, and extensible attributes. Zeek-specific models remain compatible with the current pipeline; future collectors target this canonical model rather than making detectors vendor-aware.

### Normalization Contract (Phase 3.1)

The normalization contract establishes the vocabulary and rules for mapping source telemetry into `NormalizedEvent`.

- **`source_type`**: Answers "Which telemetry source produced the original observation?" (e.g., `zeek`, `suricata`, `sysmon`). It does not imply attack category, detection category, or severity. Canonical values are registered in `SourceType`.
- **`event_type`**: Answers "What kind of security-relevant observation is this?" (e.g., `network_connection`, `process_create`). It is independent of `source_type`. Canonical values are registered in `EventType`.
- **Severity Semantics**: `NormalizedEvent.severity` represents the normalized severity assigned to the *source telemetry observation*, not the final severity of a argusprowl detection or alert.
- **Metadata Semantics**: Platform processing context added by argusprowl while processing the event (e.g., collector identity, collection timestamp, source channel, bookmark context). It is not a second arbitrary event schema.
- **Attributes Semantics**: Source-specific information about the original telemetry observation. Canonical fields (like `src_ip`) must not be duplicated in attributes. Source-specific attributes that could collide with generic concepts must be namespaced (e.g., `zeek_uid`, `suricata_signature_id`).
- **Tags Semantics**: Additional multi-valued classification labels useful for search, filtering, detection, or analyst workflows (e.g., `network`, `authentication`). They do not replace `event_type` or `source_type`.
- **Canonical Field Promotion Rule**: A field becomes canonical when it represents a meaningful security concept, appears across multiple sources (or is fundamental to cross-source correlation), has stable semantics independent of a vendor, and is likely to be queried frequently.
- **Event Identity Terminology**:
  - `event_id`: argusprowl's identity for the normalized event.
  - `source_record_id`: Native identifier supplied by the telemetry source, when available (e.g., Zeek `uid`, Sysmon `EventRecordID`).
- **Unknown Event Policy**: The contract explicitly supports unknown/unrecognized source events. Unknown telemetry is not discarded merely because it does not fit the current taxonomy (e.g., `suricata_unknown`).

### Detection Contract — Phase 4.1

Phase 4.1 defines the semantic detection contract without changing the runtime ownership model. The live and replay path remains:

```
NormalizedEvent → FeatureExtractor → DetectionManager → DetectionResult
                → DecisionEngine → AlertDeduplicationEngine → AlertManager
```

`DetectionManager` remains the execution owner. Existing detector classes and the YAML-backed `RuleLoader` remain compatible configuration adapters; no second event bus, scheduler, rule worker, distributed execution layer, or correlation store was introduced.

#### DetectionRule

`argusprowl.detection.contract.DetectionRule` is the canonical implementation-independent rule model. Its stable identity is `rule_id` (for example, `TH-NET-C2-001`), which is independent of a process ID, event ID, source record ID, or alert ID. Every rule declares `name`, `description`, positive integer `version`, and `enabled` state. A disabled rule remains loadable, visible, and validatable but must not generate a detection when executed.

Rules carry deterministic detection `severity`, explicit `confidence` in the closed range $[0.0, 1.0]$, classification `tags`, optional MITRE ATT&CK `tactic`, `technique`, and `subtechnique`, optional references, and an optional author/owner. A rule-version change distinguishes edits to conditions, severity, confidence, or declared temporal behavior from an execution-engine implementation change.

`RuleApplicability` limits a rule by canonical `source_types`, `event_types`, `protocols`, hosts, or sensors. It deliberately does not promote vendor fields into `NormalizedEvent`: universal semantics stay canonical, while source-specific data remains addressable as `attributes["QueryName"]` in a condition. Network direction is derived later from canonical endpoint fields and deployment context; it is not added as a `NormalizedEvent` field. This supports inbound attacks, outbound C2/reverse shells/exfiltration, internal lateral movement, and unusual internal connections.

#### Conditions and logical composition

An atomic `Condition` is `{field, operator, value}`. The Phase 4.1 vocabulary is `equals`, `not_equals`, `contains`, `starts_with`, `ends_with`, `regex`, `exists`, `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal`, `in`, and `not_in`. Rule validation rejects unsupported operators and malformed condition structures deterministically.

Conditions compose structurally with `AND`, `OR`, and `NOT` through `LogicalExpression`; this is not a new expression runtime. `AND` requires every child, `OR` requires at least one child, and `NOT` requires exactly one child. A missing field never silently becomes `false`, zero, or an empty string. Every condition declares `MissingFieldPolicy`; the default `fail_closed` treats a missing field as a non-match, while an explicit policy is required for any other behavior. `exists` tests presence and ignores its `value`.

#### Temporal and stateful semantics

`TemporalSpec` reserves representation for a later stateful engine: `within_seconds`, `min_count`, `group_by`, `ordered`, and an ordered `sequence`. It can describe such intent as five authentication failures from the same `src_ip` in 60 seconds or process creation followed by network activity. Phase 4.1 does **not** implement temporal execution, correlation state storage, a scheduler, or aggregation workers.

#### DetectionResult, evidence, and explainability

`argusprowl.models.DetectionResult` remains the single canonical runtime result model and feeds the existing `DecisionEngine`. A result identifies the firing rule, primary `event_id`, optional `contributing_event_ids` for future multi-event rules, UTC creation time, detection severity, normalized confidence, rule version, bounded metadata, structured evidence, and an explanation. It serializes with `to_dict()` and round-trips with `from_dict()`.

Each evidence entry contains `field`, `observed`, and `condition`, with optional event references or expected values. It records enough information to explain a match without embedding unbounded raw telemetry or complete `NormalizedEvent` objects. The `explanation` field supplies the human-readable reason. Source telemetry severity, detection severity, and final alert severity remain separate: no source-specific severity is implicitly treated as a argusprowl detection severity.

#### Representation and interoperability decisions

YAML is a serialization/configuration representation consumed by `RuleLoader`; it is not the semantic authority. The same `DetectionRule` contract can later be constructed from YAML, a Sigma importer, or programmatic rules. Sigma is therefore a future interoperability target, not a parser introduced in this phase. YARA remains specialized content matching for file content, memory artifacts, binary artifacts, and malware classification; it is not the event-stream or correlation rule language and is not integrated in Phase 4.1.

### Streaming reliability (Phase 2.3)

```
Collector -> Raw record -> Parser -> NormalizedEvent -> Bounded ingestion buffer
                                                        -> Detection -> Alert
                                                                        -> Alert deduplication -> Provider
```

The ingestion buffer is FIFO, thread-safe, and has O(1) enqueue/dequeue with O(capacity) memory. Its default `drop_newest` policy makes overload explicit: it preserves already accepted ordering, increments drop/rejection metrics, and emits a saturation diagnostic. Sources able to pause safely can select `block`; `drop_oldest` is also explicit. A bounded dead-letter queue receives malformed records with source, collector, safe raw payload, parse error, location, attempts, and metadata. Its overflow is measured and never silent.

Transient ingestion actions use a finite, cancellation-aware exponential retry policy. Permanent failures are not retried. Reliability components close by rejecting new work and waking waiting producers/consumers; they do not wait indefinitely.

**Events are not deduplicated. Alerts are deduplicated.** The alert boundary uses a versioned SHA-256 fingerprint of selected normalized identity fields, not the entire alert payload. The process-local engine atomically updates bounded, TTL-expiring state (`first_seen`, `last_seen`, occurrence count, cooldown and alert ID); matching alerts inside cooldown are suppressed while their occurrence count is retained. The cache is behind `DeduplicationCache`, so an atomic Redis/PostgreSQL implementation can replace the bounded in-memory cache for distributed deployments.

### Sysmon collector (Phase 2.4)

`argusprowl.collectors.sysmon` follows the same collector lifecycle as Zeek while translating Windows Sysmon XML into `NormalizedEvent`. It supports Event IDs 1 (Process Create), 3 (Network Connection), 7 (Image Loaded), 8 (CreateRemoteThread), 10 (Process Access), 11 (File Create), 12 (Registry Create/Delete), 13 (Registry Set), 14 (Registry Rename), and 22 (DNS Query). Unknown IDs are preserved as `sysmon_unknown` with their original ID rather than being discarded.

The canonical semantic mapping is aligned to the registry contract: `1 -> process_create`, `3 -> network_connection`, `7 -> image_loaded`, `8 -> remote_thread`, `10 -> process_access`, `11 -> file_create`, `12 -> registry_create`, `13 -> registry_set`, `14 -> registry_rename`, and `22 -> dns_query`. The Sysmon parser promotes only universal concepts into `NormalizedEvent` (`hostname`, `username`, `process_name`, `command_line`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) while leaving vendor-specific fields such as `ProcessGuid`, `EventRecordID`, `ImageLoaded`, `TargetObject`, and query details in `attributes`. `raw_event` preserves the original exported XML.

`source_record_id` is set from the native Sysmon `EventRecordID` when present, because that is the source-native event identity rather than the process or network record identity. If the XML lacks a reliable `EventRecordID`, the collector falls back to the record metadata only when it is genuinely the event identity supplied by the acquisition layer.

Production acquisition is deliberately Windows-only and uses the Windows-supplied `wevtutil` command through a shell-free, isolated adapter. No Windows API is faked on Linux. Linux development and CI use `ReplaySysmonEventSource` with exported XML records. The collector persists only an atomic EventRecordID bookmark, resumes after restarts, and clears stale checkpoints before reconnecting to retained log data. Parser failures use the shared bounded dead-letter queue; sensitive XML fields are not emitted in normal logs.

### Windows Event Log collector (Phase 2.5 / Phase 3.7)

`argusprowl.collectors.windows_event_log` collects standard Windows Event Logs through the same lifecycle, metrics, health, and reliability boundaries as other collectors. One collector supports a validated list of channels (default: `Security`; `System` and `Application` are optional) and persists an atomic per-channel `EventRecordID` checkpoint. Incremental queries request records after that checkpoint; a stale checkpoint is cleared before retrying, so log retention or truncation does not cause full-log reprocessing.

The parser safely converts exported Windows Event XML to `NormalizedEvent` complying with the Phase 3 normalization contract (`SourceType.WINDOWS_EVENT_LOG`). Canonical semantic event types map supported Security/System IDs to canonical `EventType` constants: `4624 -> authentication_success`, `4625 -> authentication_failure`, `4648 -> explicit_credential_logon`, `4672 -> privilege_assignment`, `4688 -> process_create`, `4697 -> service_install`, `4720 -> account_create`, `4728/4732/4756 -> group_membership_change`, and `1102 -> audit_log_cleared`. Unknown IDs map to `windows_unknown` and are measured rather than discarded.

Universal security concepts are promoted to canonical fields: `Computer -> hostname`, account fields (`SubjectUserName` / `TargetUserName` / `User`) -> `username`, process fields (`NewProcessName` / `ProcessName` / `Image`) -> `process_name`, `CommandLine -> command_line`, `IpAddress` / `SourceAddress` -> `src_ip`, `IpPort` / `SourcePort` -> `src_port`, `DestinationAddress` / `DestAddress` -> `dst_ip`, `DestinationPort` / `DestPort` -> `dst_port`. Source identity `source_record_id` is populated from native `EventRecordID` (string-converted, per-channel scoped via `metadata["channel"]`). Original vendor fields remain available in `attributes` (`windows_event_id`, `event_record_id`, and raw XML fields); `raw_event` preserves original XML.

Production acquisition is Windows-only through the native `wevtutil` utility, invoked with a validated channel and argument list (never a shell). Linux development, CI, and replay use `ReplayWindowsEventSource` with exported XML fixtures; no Windows API is emulated. Parser failures use the existing bounded dead-letter queue, while health exposes state, channel checkpoints, timestamps, and aggregate metrics only—not event payloads. Raw XML is not logged at normal log levels because Security events may contain sensitive authentication and account information.

### Linux Audit collector (Phase 2.6 / Phase 3.8)

`argusprowl.collectors.linux_audit` follows the shared collector lifecycle and normalizes auditd text records from a configured audit log (default `/var/log/audit/audit.log`) to comply with the Phase 3 normalization contract (`SourceType.LINUX_AUDIT`). The production file adapter tails incrementally using an atomic inode-and-byte-offset checkpoint, restarts from the saved position, and resets safely after truncation or inode rotation. It does not invoke a shell or execute telemetry. `ReplayLinuxAuditSource` feeds the same raw-record and parser path for Linux development and CI, so tests do not require a running auditd daemon.

Audit records are tokenized and mapped to canonical `EventType` constants: `SYSCALL`/`EXECVE -> process_execution`, `USER_LOGIN -> authentication_success` / `authentication_failure` (or `authentication`), `USER_START -> session_start`, `USER_END -> session_end`, `USER_ACCT -> account_activity`, `USER_CMD -> command_activity`, `USER_ROLE_CHANGE -> role_change`, `USER_CHAUTHTOK -> credential_change`, `CRED_ACQ -> credential_acquisition`, `CRED_REFR -> credential_refresh`, `CRED_DISP -> credential_disposal`; unknown records map to `linux_audit_unknown`. Native audit serial is populated into `source_record_id` (string-converted). Canonical fields (`hostname`, `username`, `process_name`, `command_line`, `src_ip`, `src_port`, `dst_ip`, `dst_port`) are promoted when present, while `auid`, `uid`, `euid`, `pid`, `ppid`, `syscall`, `exit`, `audit_key`, and original EXECVE arguments stay in `attributes`. `raw_event` preserves original text payload(s).

The bounded `AuditRecordAssembler` performs transaction assembly for `SYSCALL`, `EXECVE`, `PATH`, `CWD`, and `PROCTITLE` records sharing an audit serial. Incomplete or capacity-evicted groups are emitted safely as single `NormalizedEvent` envelopes. Malformed records use the shared bounded dead-letter queue, while health reports checkpoints, timestamps, pending-group count, rotation/retry counters, and lag without exposing raw audit payloads.

The bounded `AuditRecordAssembler` is record assembly rather than attack correlation: it groups `SYSCALL`, `EXECVE`, `PATH`, `CWD`, and `PROCTITLE` records sharing an audit serial, with O(1) average lookup, a configured timeout, and a strict maximum number of pending groups. Incomplete or capacity-evicted groups are emitted safely. Malformed records use the shared bounded dead-letter queue, while health reports checkpoints, timestamps, pending-group count, rotation/retry counters, and lag without exposing raw audit payloads.

### Suricata collector (Phase 2.7)

`argusprowl.collectors.suricata` ingests Suricata EVE JSON records continuously using file tailing (`EveFileSource`) or deterministic replay (`ReplaySuricataEventSource`). It uses atomic inode-and-offset bookmarking (`SuricataBookmarkStore`) for rotation and restart recovery.

EVE event types are dispatched to semantic `NormalizedEvent` mappings (`alert` → `ids_alert`, `flow` → `network_flow`, `dns` → `dns_query`, `http` → `http_transaction`, `tls` → `tls_connection`, `ssh` → `ssh_activity`, `fileinfo` → `file_observation`, unknown → `suricata_unknown`). Canonical network fields, `flow_id`, `community_id`, and event-specific details are preserved in attributes. Suricata IDS alerts are source telemetry and do **not** automatically become platform `Alert` objects or bypass downstream detection. Malformed JSON records are safely routed to the shared dead-letter queue.

### Phase 3.9 — Cross-Collector Normalization Review

A rigorous cross-collector audit was performed across Zeek, Suricata, Sysmon, Windows Event Log, and Linux Audit to determine which semantics are genuinely shared and which should remain source-specific.

**Normalization Invariants:**
- `NormalizedEvent` is a semantic contract, not a lowest-common-denominator flattening mechanism.
- No `UniversalNormalizer` or large conditional tree was introduced. The collector parser remains responsible for interpreting its native schema.
- Source-specific telemetry remains available in `attributes`.
- Unknown events are preserved and remain observable.
- Suricata alerts remain telemetry and do not bypass the Detection Engine.

**Confirmed Common Semantics:**
- All collectors use canonical `SourceType` and `EventType` constants.
- All timestamps are UTC-aware `datetime` objects.

**Intentionally Source-Specific Semantics:**
- **Timestamp parsing:** While semantics are identical (UTC), input formats differ (ISO vs epoch) and implementations are trivial. Kept source-specific.
- **Network parsing:** Source semantics differ for "empty" values (e.g., `-`, `::`, `0.0.0.0`, `localhost`, `none`). Kept source-specific.
- **Username handling:** Actor/target semantics differ across sources. Kept source-specific.
- **Source identity:** Native identity mechanisms differ significantly (e.g., `uid`, `tx_id`, `EventRecordID`, `audit_serial`). Kept source-specific.
- **Process and Hostname:** Source semantics differ. Kept source-specific.

**Shared Helpers Created:**
- No shared normalization helper was introduced because the audited semantics are not sufficiently identical.

**Remaining Normalization Debt:**
- `ConnectionEvent` is no longer a runtime dependency; feature engineering and detection use `NormalizedEvent`.
- Tag generation and UID resolution are deferred to later semantic layers.

### Phase 3.10 — Complete Canonical Runtime Migration

The Phase 3 normalization architecture was completed by making `NormalizedEvent` the canonical runtime event contract throughout the downstream feature-engineering and detection pipeline.

**Key Changes:**
- `ConnectionEvent` was removed as a runtime dependency.
- Feature engineering and detection now consume `NormalizedEvent` natively.
- Replay now produces `NormalizedEvent` without conversion.
- All tests were migrated to use `NormalizedEvent`.

**Final Runtime Contract:**
- All collectors emit `NormalizedEvent`.
- Replay emits `NormalizedEvent`.
- Feature engineering consumes `NormalizedEvent`.
- Detection consumes `NormalizedEvent`.
- Detection results are downstream from `NormalizedEvent`.

### Storage adapter purpose

SQLite is appropriate for a single-node foundation with transactional local persistence. PostgreSQL is reserved for shared transactional deployments, ClickHouse for high-volume analytical event storage, and Redis for ephemeral low-latency/cache workloads. Each conforms to `Storage`; repositories never name an adapter, preserving dependency inversion.

### Plugin lifecycle

Plugin framework removed in Phase 4.2S. No plugin infrastructure exists.

### Incident before correlation

`Incident` exists now as the UUID-backed, schema-versioned investigation aggregate for alert references and analyst metadata. It contains no grouping or correlation logic: defining the durable domain contract early means the future correlation engine can be added without a persistence or API migration.


## Extension Points

### Adding New Detectors
1. Create detector class inheriting from `BaseDetector`
2. Implement `detect()` method
3. Register with `DetectorRegistry`
4. Create YAML rule file in `rules/`

### Adding New Alert Providers
1. Implement `AlertProvider` interface
2. Register with `AlertManager`
3. Provider is automatically used for all alerts

### Adding New Metrics
1. Register metric with `MetricsCollector`
2. Instrument code using counters, gauges, or histograms
3. Metrics are automatically collected and reportable

### Adding a New Collector (Phase 2.1 framework)

1. Sub-class `BaseCollector` from `src/argusprowl/collectors/base_collector.py`
2. Declare a `name` property returning the unique collector identifier
3. Implement only the `_do_*` template hooks you need:
   - `_do_initialize(config)` — open config, validate settings
   - `_do_start()` — open file handles, bind sockets, start threads
   - `_do_stop()` — release resources, join threads
   - `_do_pause()` — suspend reads without closing connections (optional)
   - `_do_resume()` — re-enable reads (optional)
   - `_do_collect()` — `yield` raw `Event` objects
4. Register the type with `CollectorFactory.register_type("my_source", MyCollector)`
5. Use `CollectorManager.add_collector(factory.create("my_source", config))`
   or register directly via `CollectorRegistry`

The framework handles collector state transitions, locking, metrics, and error recording. Collectors route normalized events through the configured queue.

---

## Collector Framework (Phase 2.1)

### Overview

`src/argusprowl/collectors/` is the generic infrastructure layer that all concrete
collectors (Zeek, Sysmon, Windows Event Logs, Suricata, Linux Audit, CloudTrail,
Kafka, S3, …) inherit from. **No source-specific logic lives here.**

### Architecture Position

```
 CollectorManager  ──manages──►  CollectorRegistry
        │                               │
        │                      BaseCollector (1..N)
        │                               │
        ▼                               ▼
    Direct Queue            Template hooks (_do_*)
    MetricsCollector       └── implemented by concrete collectors
    HealthService
```

### CollectorState Lifecycle

All state transitions are validated against a data-driven allowlist. Any
transition not in the table raises `CollectorStateError` before touching I/O.

```
  UNINITIALIZED
       │ initialize()
       ▼
  INITIALIZING ──► STOPPED ──start()──► STARTING ──► RUNNING
       │                                                 │  │
       ▼ (on error)                            pause()   │  │ stop()
    FAILED ◄──────────────────────── any state           │  ▼
       │                                           PAUSING  STOPPING
       │ stop()                                      │         │
       ▼                                        PAUSED         ▼
    STOPPED                                      │  │       STOPPED
                                         resume()│  │stop()
                                                 ▼  ▼
                                             RESUMING  STOPPING
                                                 │       │
                                                 ▼       ▼
                                              RUNNING  STOPPED
```

### Component Responsibilities

| Class | Responsibility |
|---|---|
| `CollectorState` | `StrEnum` with `valid_transitions` map; JSON-serializable |
| `CollectorMetrics` | Per-collector thread-safe Counter/Gauge/Histogram wrapper |
| `CollectorMetricsSnapshot` | Immutable frozen dataclass for health reporting |
| `BaseCollector` | Abstract lifecycle base; all plumbing (locking, events, metrics) |
| `CollectorRegistry` | Thread-safe `name → BaseCollector` store; no lifecycle logic |
| `CollectorFactory` | Type-based and instance-based constructor/initializer |
| `CollectorManager` | Bulk `start_all / stop_all / pause_all / resume_all`; failure isolation |
| `CollectorHealth` | Frozen health snapshot consumed by `HealthService` |

### Failure Isolation Guarantee

`CollectorManager` wraps every per-collector call in its own `try/except`.
A collector that raises during `start_all()` or `stop_all()`:
- transitions itself to `FAILED` (recorded in metrics and error_message)
- records the failure in collector state, metrics, and the collector error message
- is captured in the returned `{name: Exception | None}` result dict
- **never prevents other collectors from completing their operation**

### Integration Points

- **Direct Queue**: Events flow directly from collectors to the processing queue.
- **MetricsCollector**: Manager-level gauges track running/failed/total counts.
  Each collector owns its own `CollectorMetrics` instance.
- **HealthService**: When a `CollectorManager` is injected, `_check_collectors()`
  produces one `ComponentHealth` per collector. FAILED → UNHEALTHY, PAUSED →
  DEGRADED, RUNNING → HEALTHY. Absent manager = silent skip (backward-compatible).
- **ServiceContainer**: `CollectorManager` is registered as a singleton in
  `Application._register_services()`. Shutdown stops collectors before the
  application processing loop and dependent services are torn down.

---

## Dependency Graph

```
src/argusprowl/core/application.py
    ├── src/argusprowl/config/
    ├── src/argusprowl/logging/
    ├── src/argusprowl/dependency_injection/
    └── [Phase 2 Components]
        ├── src/argusprowl/collectors/               ← Phase 2.1
        │   ├── src/argusprowl/interfaces/collector.py
        │   ├── src/argusprowl/metrics/
        │   └── src/argusprowl/models/collector_health.py
        ├── src/argusprowl/feature_engineering/
        │   └── src/argusprowl/models/connection_event.py
        ├── src/argusprowl/detection/
        │   ├── src/argusprowl/feature_engineering/
        │   └── src/argusprowl/models/
        ├── src/argusprowl/decision_engine/
        │   └── src/argusprowl/models/alert.py
        ├── src/argusprowl/alerting/
        │   └── src/argusprowl/models/alert.py
        ├── src/argusprowl/metrics/
        └── src/argusprowl/replay/
            ├── src/argusprowl/feature_engineering/
            ├── src/argusprowl/detection/
            └── src/argusprowl/services/
```

### Temporal Detection — Phase 4.3

Phase 4.3 introduces a bounded in-memory temporal engine for beaconing detection. The temporal engine tracks network observations by `(dst_ip, dst_port)` key and computes periodicity metrics without persistent storage.

```
NormalizedEvent → TemporalEngine (bounded sliding window)
                  → BeaconingDetector
                  → DetectionResult (behavioral evidence, not verdict)
                  → DecisionEngine → AlertDeduplicationEngine → AlertManager
```

**Key design principles:**
- The temporal engine produces **behavioral signals**, not alerts. It does not assign maliciousness.
- A high periodicity score is evidence, not proof of C2.
- State is bounded: max keys, max observations per key, max window duration.
- Eviction is deterministic (LRU for keys, FIFO for observations within window).
- Thread-safe for concurrent access from multiple collectors.
- Replay and live mode use the same temporal logic.

**Periodicity calculation:**
- Uses coefficient of variation (CV) of inter-observation intervals.
- Periodicity score = `exp(-3 * CV)`, mapped to `[0.0, 1.0]`.
- Classification: `none` (<0.3), `low` (<0.5), `moderate` (<0.7), `high` (<0.9), `very_high` (≥0.9).

**Beaconing detector thresholds (configurable):**
- `min_observations`: Minimum observations required (default: 10).
- `min_duration_seconds`: Minimum duration for assessment (default: 300s).
- `periodicity_threshold`: Minimum score to flag (default: 0.7).

**False positive considerations:**
- Benign periodic traffic (NTP, browser updates, health checks) may trigger.
- The detector provides structured evidence for analyst review, not an automated verdict.
- Evidence includes destination, port, observation count, duration, mean interval, dispersion, and periodicity score.
