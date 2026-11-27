# Alpha Exit Readiness Audit

**Baseline:** `main` after PRs #80 and #81  
**Audit branch:** `audit/alpha-exit-readiness`  
**Scope:** release gates for a single-tenant, SQLite-backed deployment  
**Status:** initial evidence-backed baseline; not a production certification

This document separates verified implementation facts from release requirements that still need runtime validation. Passing CI is necessary, but it is not evidence of operational readiness by itself.

## Executive assessment

ArgusProwl has substantial security and reliability foundations: deny-by-default API authorization, owner-scoped resource checks, persistent API-key and browser-session revocation, a hash-chained audit log, bounded ingestion buffers with loss counters, SQLite evidence indexing, consistent online backups, and restore verification.

The current evidence does **not** justify removing the Alpha designation. The largest remaining gaps are operational recovery, end-to-end detection acceptance on real telemetry, and explicit failure/reconciliation guarantees between independently committed alert and evidence stores.

The v1 release target should remain deliberately narrow:

- one application instance per customer/workspace;
- SQLite as the supported application persistence backend;
- telemetry supplied by separately configured collectors or replay;
- no multi-tenant shared instance, multi-replica deployment, or PostgreSQL parity claim.

## Confirmed implementation and boundaries

| Area | Verified baseline | Release implication |
| --- | --- | --- |
| API authorization | Viewer/analyst/admin roles; deny-by-default route allowlists; object-level ownership checks; non-admin evidence access constrained to exact event IDs | Keep the endpoint-by-role and cross-resource regression matrix as a release gate. |
| Credential lifecycle | First-admin bootstrap; named credentials; expiry/disable checks; persistent key revocation; persistent browser-session revocation | Validate restart, concurrent-request, and shared-database behavior in integration tests. |
| Authentication throttling | 10 failures per client IP in 60 seconds, followed by a 5-minute lockout; limiter is process-local | Multi-replica use requires a shared reverse-proxy rate limit or a distributed limiter. |
| Ingestion overload | Bounded FIFO buffer supports block, drop-newest, and drop-oldest; receive/buffer/process/failure/drop/reject counters and queue-depth metrics are present | Do not treat overflow as invisible. Verify each configured policy and expose loss counters operationally. |
| Alert queue | Bounded, process-local queue rejects new alerts at capacity; queue state is lost on restart | Do not mistake the analyst workflow queue for durable alert storage. Verify durable alert recovery separately. |
| Alert/evidence persistence | Alert and evidence writes use independent stores/transactions; alert persistence is configurable; failures are counted/logged; no automatic retry or cross-store transaction | A crash or persistence fault can leave an alert without evidence or evidence without a durable alert. This needs an explicit reconciliation/recovery policy and fault-injection tests. |
| Evidence persistence | SQLite authoritative JSON records and derived search index are updated transactionally; evidence cache is bounded independently of durable retention | Monitor disk/WAL growth and verify index rebuild/recovery from malformed legacy rows. |
| Retention | Evidence retention is opt-in and SQLite-only; alert, incident, hunt and audit lifecycles are not governed by the same policy | Define product-level retention and dangling-reference expectations before Stable. |
| Backup/restore | Consistent online SQLite backup, manifest/checksum verification, staged offline restore are implemented | Scheduling, off-host copy, encryption, generation retention, and restore drills remain operator responsibilities. |
| Audit integrity | SHA-256 chain and HMAC external checkpoints are implemented | Checkpoint scheduling, transport, key rotation/recovery and audit retention remain operational tasks. |
| Storage | SQLite is the active application store. PostgreSQL adapter is not a drop-in application-store replacement; evidence search/entity projections/retention parity are missing | Officially scope v1 to SQLite; do not advertise PostgreSQL application parity. |
| Tenancy | Single-tenant-per-instance model; owner scoping is not tenant isolation | Separate instances and volumes per customer until tenant IDs are enforced in every query and relationship. |

## Release blockers and work order

### P0 — must be closed before Beta

1. **Prove alert/evidence failure behavior.**
   - Add fault-injection tests for evidence write failure, alert write failure, process interruption between commits, and provider delivery failure.
   - Assert that counters, health state, logs, and API-visible provenance accurately represent partial success.
   - Implement a durable reconciliation mechanism for missing alert/evidence counterparts, or document and expose an operator repair procedure with machine-readable diagnostics.
   - Preserve idempotency; do not claim exactly-once delivery.

2. **Prove overload and shutdown behavior.**
   - Exercise every supported ingestion overflow policy at capacity.
   - Verify loss/rejection counters and health diagnostics after saturation, consumer exceptions, blocked producers, and shutdown.
   - Verify graceful shutdown drains accepted work within the configured timeout and clearly reports work that cannot be drained.

3. **Complete authorization acceptance matrix.**
   - Test viewer, analyst, and admin access for alerts, incidents, hunts, evidence, entity pivots, ATT&CK investigation, audit, exports, and all mutation routes.
   - Include missing ownership metadata, foreign-owned embedded evidence references, revoked/expired credentials, copied browser cookies after logout, restart, and concurrent requests.
   - Ensure authorization is applied before pagination, aggregation, and lookup side effects.

### P1 — required for a supported Stable single-node deployment

4. **Operational backup lifecycle.**
   - Supply an example scheduled backup job and off-host encrypted-copy procedure.
   - Define backup generation retention and operator-visible last-success/last-failure state.
   - Add a repeatable restore drill that starts the restored application and validates schema, authentication, alerts, evidence, and audit integrity.
   - Publish an explicit RPO/RTO statement only after drills support it.

5. **Storage and retention lifecycle.**
   - Document disk-capacity thresholds and WAL monitoring.
   - Define alert, incident, hunt, evidence, and audit retention semantics, including references to expired evidence.
   - Test retention concurrent with evidence search and application restart.
   - Keep SQLite as the supported application backend until another backend has full feature parity.

6. **Deployment hardening.**
   - Publish a single-instance deployment profile covering persistent volumes, TLS/reverse proxy, secrets, permissions, health checks, upgrades, and offline restore.
   - Explicitly warn that process-local authentication throttling is not a multi-replica control.
   - Test restart and interrupted shutdown with persistent volumes.

### P1 — detection acceptance

7. **Validate with real telemetry, not generated fixtures alone.**
   - Maintain a versioned test corpus with source URL, license, dataset/version, checksum, and replay instructions.
   - Exercise representative Zeek, Suricata EVE, Sysmon/Windows Event, and Linux Audit records supported by the current parsers.
   - Record accepted, rejected, quarantined, and malformed record counts.
   - For each detection, document expected behavior, observed detections, false positives, and known blind spots.
   - Include replay reproducibility and sustained-ingestion/overload recovery results.

8. **Rule lifecycle and regression.**
   - Verify stable rule identity/versioning, validation, enable/disable, rollback, and audit history.
   - Add benign and malicious regression cases for every shipped high-value rule.
   - Do not add ML detectors or claim detection efficacy without measured evaluation.

### P2 — after Beta stability

9. **Release engineering.**
   - Add versioned container publication, SBOM, image provenance/signing, release notes, and upgrade/rollback instructions.
   - Verify a clean install from a tagged release, not only a development checkout.
   - Define support policy and compatibility/deprecation expectations.

10. **Documentation accuracy.**
    - Replace the historical placeholder in `docs/productization.md` with current CI-derived verification data.
    - Rewrite `docs/single-process.md` against current runtime code; it currently carries an explicit warning that its content is historical and must be revalidated.
    - Keep README capability and deployment claims aligned with tested behavior.

## CI coverage: what it proves and what it does not

The current backend workflow runs compile checks, Ruff, the full pytest suite, configuration validation, Bandit, PostgreSQL adapter integration tests, and a Docker Compose startup/health probe. The frontend workflow runs TypeScript checks, Vitest, a production build, and Playwright E2E.

The Docker integration job currently verifies that the API becomes healthy; it does not itself replay telemetry through the complete detection path or assert alert/evidence outcomes. PostgreSQL CI validates the generic adapter contract, not full application persistence parity.

Therefore, green CI is not sufficient to close the real-telemetry, crash-recovery, backup-drill, or authorization-coverage gates above.

## Explicitly out of scope for v1

- Rust rewrite or language migration.
- Kubernetes or multi-node deployment.
- Shared multi-tenant SaaS.
- PostgreSQL/ClickHouse parity before there is a concrete deployment requirement.
- Autonomous response.
- A bundled host sensor, packet-capture agent, message broker, or telemetry lake.
- Additional ML detectors without measured false-positive and detection results.

## Evidence reviewed

- `README.md`: product workflow, deployment distinction, supported telemetry, SQLite scope, and current Alpha label.
- `docs/security.md`: authentication, bootstrap, credential revocation, rate limiting, role boundaries, audit chain, tenant boundary, and object ownership.
- `docs/persistence-guarantees.md`: independent alert/evidence commits, no retries/exactly-once guarantee, SQLite evidence index, retention, and backup/restore guarantees.
- `docs/postgresql-storage.md`: PostgreSQL adapter limitations and missing application-store parity.
- `docs/architecture.md`: current processing pipeline and SQLite entity projection.
- `src/argusprowl/reliability/buffer.py`: explicit overflow policies and ingestion counters.
- `src/argusprowl/lifecycle/queue.py`: bounded, in-memory alert workflow queue.
- `src/argusprowl/alerting/alert_manager.py`: queue-full handling, optional alert persistence, and provider dispatch behavior.
- `.github/workflows/backend-ci.yml` and `.github/workflows/frontend-ci.yml`: current automated validation scope.
- `docs/single-process.md` and `docs/productization.md`: historical documentation warnings.

This is a source/documentation audit baseline. The P0 fault-injection and authorization acceptance tests remain open until executed and reported from CI.
