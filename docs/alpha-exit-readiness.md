# Alpha Exit Readiness Audit

**Baseline:** `main` after PR #94 (2026-11-27)  
**Audit branch:** `audit/alpha-exit-readiness`  
**Scope:** release gates for a single-tenant, SQLite-backed deployment  
**Status:** updated after reliability validation; remains Alpha and is not a production certification

This document separates verified implementation facts from release requirements that still need runtime validation. Passing CI is necessary, but it is not evidence of operational readiness by itself.

## Executive assessment

ArgusProwl now has additional verified reliability coverage: API startup test-harness cleanup, evidence-outage isolation, graceful-shutdown timeout handling, a role/method authorization matrix, a read-only alert/evidence reconciliation CLI, a cross-store partial-commit regression test, a three-store SQLite restore drill, and a real Zeek PCAP replay through a production detection rule.

The current evidence still does **not** justify removing the Alpha designation. Cross-store commits remain non-atomic, missing telemetry cannot be reconstructed automatically, off-host backup automation is absent, and the real-PCAP acceptance case is a benign baseline rather than a malicious efficacy/false-positive evaluation.

The v1 release target should remain deliberately narrow:

- one application instance per customer/workspace;
- SQLite as the supported application persistence backend;
- telemetry supplied by separately configured collectors or replay;
- no multi-tenant shared instance, multi-replica deployment, or PostgreSQL parity claim.

## Confirmed implementation and boundaries

| Area | Verified baseline | Release implication |
| --- | --- | --- |
| API authorization | Viewer/analyst/admin roles; deny-by-default route allowlists; object-level ownership checks; non-admin evidence access constrained to exact event IDs; route/method role matrix and owner-isolation integration tests are in CI | Keep authorization fail-closed; extend the matrix whenever routes or roles change. |
| Credential lifecycle | First-admin bootstrap; named credentials; expiry/disable checks; persistent key revocation; persistent browser-session revocation | Validate restart, concurrent-request, and shared-database behavior in integration tests. |
| Authentication throttling | 10 failures per client IP in 60 seconds, followed by a 5-minute lockout; limiter is process-local | Multi-replica use requires a shared reverse-proxy rate limit or a distributed limiter. |
| Ingestion overload | Bounded FIFO buffer supports block, drop-newest, and drop-oldest; receive/buffer/process/failure/drop/reject counters and queue-depth metrics are present | Do not treat overflow as invisible. Verify each configured policy and expose loss counters operationally. |
| Alert queue | Bounded, process-local queue rejects new alerts at capacity; queue state is lost on restart | Do not mistake the analyst workflow queue for durable alert storage. Verify durable alert recovery separately. |
| Alert/evidence persistence | Independent stores and commits; evidence-write failure is fault-injected; a read-only reconciliation command reports missing references and provenance mismatches; an end-to-end partial-commit test exercises the diagnostic | Cross-store atomicity and automatic retry remain absent. Missing event payloads cannot be rebuilt automatically; keep this as a Beta gate. |
| Evidence persistence | SQLite authoritative JSON records and derived search index are updated transactionally; evidence cache is bounded independently of durable retention | Monitor disk/WAL growth and verify index rebuild/recovery from malformed legacy rows. |
| Retention | Evidence retention is opt-in and SQLite-only; alert, incident, hunt and audit lifecycles are not governed by the same policy | Define product-level retention and dangling-reference expectations before Stable. |
| Backup/restore | Online backup/manifest verification and staged restore; an automated restore drill verifies event/evidence, alert, audit, and credential-revocation state across the configured core SQLite stores | Scheduling, off-host copy, encryption, generation retention, and last-success/failure reporting remain open. No RPO/RTO claim. |
| Audit integrity | SHA-256 chain and HMAC external checkpoints are implemented | Checkpoint scheduling, transport, key rotation/recovery and audit retention remain operational tasks. |
| Storage | SQLite is the active application store. PostgreSQL adapter is not a drop-in application-store replacement; evidence search/entity projections/retention parity are missing | Officially scope v1 to SQLite; do not advertise PostgreSQL application parity. |
| Tenancy | Single-tenant-per-instance model; owner scoping is not tenant isolation | Separate instances and volumes per customer until tenant IDs are enforced in every query and relationship. |

## Release blockers and work order

### P0 — must be closed before Beta

1. **Prove alert/evidence failure behavior — partially validated; recovery remains open.**
   - CI now injects evidence-store failure after a production alert commit and verifies that core processing succeeds while reconciliation reports the missing event reference.
   - Provider exception logging and evidence persistence counters are covered; the `reconcile alert-evidence` CLI emits bounded JSON findings and a non-zero exit for incomplete/degraded state.
   - The command is diagnostic only. It does not reconstruct missing telemetry, retry commits, or make the two stores atomic. A durable replay identity/outbox or an explicit repair workflow is still required before Beta.
   - Preserve idempotency; do not claim exactly-once delivery.

2. **Prove overload and shutdown behavior — core cases covered.**
   - Existing live-buffer tests cover drop-newest, drop-oldest, block timeout, blocked producer/consumer wake-up on close, queue metrics, and provider delivery during alert-queue saturation.
   - Shutdown tests verify accepted-event draining and that a timed-out worker retains its dependencies until a second shutdown completes.
   - Continue testing real deployment interruption and persistent-volume restart behavior.

3. **Complete authorization acceptance matrix — route and ownership coverage added.**
   - A viewer/analyst/admin method-and-endpoint matrix now checks read, investigation-write, admin, audit-read-only, unknown-role, unsupported-method, and full-path matching behavior.
   - Existing integration tests cover missing ownership metadata, foreign-owned embedded evidence references, revoked/expired credentials, copied browser cookies after logout, restart, and object-level concealment.
   - Continue adding cases for new routes and verify authorization remains before pagination, aggregation, and lookup side effects.

### P1 — required for a supported Stable single-node deployment

4. **Operational backup lifecycle — restore drill added; automation remains open.**
   - CI creates independent online backups, simulates loss of the event/evidence, alert, and security (audit plus credential/session revocation) SQLite stores, restores them offline, and verifies schema, evidence provenance, alerts, audit-chain integrity, and key revocation.
   - Still required: scheduled execution, off-host encrypted copies, backup-generation retention, last-success/last-failure state, and a production-like restore drill that starts the full application.
   - Publish an explicit RPO/RTO statement only after operational drills support it.

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

7. **Validate with real telemetry — first benign PCAP baseline added.**
   - CI downloads a pinned Zeek quickstart PCAP, runs it through the official Zeek container, parses the resulting two conn.log records, and submits them to the production `first_seen_src_dst` detection path with evidence persistence assertions.
   - Source and replay instructions are documented in `docs/real-telemetry-validation.md`; the PCAP is downloaded at test time, not vendored.
   - This is a benign baseline, not malicious-detection efficacy. Still required: labeled malicious captures, positive/negative regression cases, false-positive measurement, parser coverage for other telemetry families, and sustained replay results.

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

The backend workflow now runs compile checks, Ruff, the full pytest suite, configuration validation, Bandit, PostgreSQL adapter integration, a Docker Compose startup/health probe, and a dedicated real-PCAP-to-Zeek-to-production-detection acceptance job. The frontend workflow runs TypeScript checks, Vitest, a production build, and Playwright E2E when frontend files change.

The Docker integration job still verifies API health rather than telemetry detection; the separate real-telemetry job covers the narrow Zeek quickstart baseline. PostgreSQL CI validates the generic adapter contract, not full application persistence parity.

Green CI does not close off-host backup operations, missing-event reconstruction, malicious detection efficacy, false-positive measurement, or production restore drills.

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

This audit records verified implementation and CI evidence, not operational certification. Alert/evidence recovery remains a Beta blocker; operational backup automation and malicious telemetry evaluation remain Stable-release work.
