# Open-source ecosystem and integration strategy

Research snapshot: 2026-11-28

This is an integration strategy, not a dependency shopping list. The goal is to reduce custom code, duplicated security functionality, operational burden, and long-term maintenance while preserving ArgusProwl's identity as an analyst-led threat-hunting suite.

## Executive decision

ArgusProwl should be an integration and investigation layer over an open security ecosystem.

1. Keep the core focused on canonical telemetry, evidence provenance, cross-source pivots, hunts, investigations, and analyst workflow.
2. Use mature upstream tools for specialist collection, protocol analysis, endpoint acquisition, threat-intelligence management, and forensic timelines.
3. Connect through documented APIs, files, and standard formats. Do not bundle every upstream service into the default Compose deployment.
4. Prefer optional, read-only integrations first. Make collection, response, and write actions explicit, scoped, permissioned, and audited.
5. Keep proprietary model weights, training assets, and licensed inference outside this public repository. Model interfaces remain optional.
6. Do not add a broker, search cluster, graph database, or data lake until measured scale and query requirements justify their operating cost.

Open source does not mean zero cost. Every added service creates patching, upgrades, credentials, backups, monitoring, resource, and incident-response obligations. A remote integration can lower code maintenance while increasing deployment burden; assess both.

## Existing capabilities found in this repository

The current branch already contains:
- Zeek connection-log collector and parser.
- Suricata EVE JSON collector and parser.
- Sysmon, Windows Event Log, and Linux Audit collectors.
- Canonical normalized events, bounded ingestion, replay, evidence, entity intelligence, hunting, incidents, IOC investigation, and ATT&CK snapshot support.
- SQLite as the default local store and an optional PostgreSQL adapter.
- A ThreatIntelProvider contract and alert-provider boundaries.

Do not rebuild these capabilities merely to adopt another project's name. Improve compatibility and operational documentation around the existing source contracts first.

## Ecosystem decision matrix

| Capability | Candidate | Fit | Decision |
|---|---|---|---|
| Network protocol telemetry | [Zeek](https://zeek.org/) | Rich protocol logs; already supported | Keep and document |
| Network IDS/NSM | [Suricata](https://suricata.io/) | EVE JSON alerts and flows; already supported | Keep and document |
| Endpoint collection / live response | [Velociraptor](https://docs.velociraptor.app/) | Artifact-based targeted collection, hunts, API automation | High-value optional adapter |
| Endpoint SQL telemetry | [osquery](https://www.osquery.io/) | Cross-platform process, socket, package, host queries | Ingest results; do not build a fleet manager |
| Portable detection content | [Sigma](https://github.com/SigmaHQ/sigma) and [pySigma](https://github.com/SigmaHQ/pySigma) | Broad rule ecosystem and conversion framework | Evaluate constrained import |
| Threat intelligence | [MISP](https://www.misp-project.org/) and [PyMISP](https://github.com/MISP/PyMISP) | Indicator management, warning lists, API, STIX/NIDS exports | Highest-value optional integration |
| CTI knowledge graph | [OpenCTI](https://github.com/OpenCTI-Platform/opencti) | Rich CTI platform, connectors, STIX/TAXII | Alternative provider later; do not duplicate MISP |
| Forensic timelines | [Timesketch](https://github.com/google/timesketch) | Collaborative timeline analysis and annotation | Export integration later |
| Incident case management | [DFIR-IRIS](https://docs.dfir-iris.org/) | Cases, evidence, IOCs, tasks, audit, API | Optional case sync; avoid duplicating existing incident features |
| Telemetry transport | [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) | Vendor-neutral receivers, processors, exporters | Deployment option, not a core dependency |
| Metrics and dashboards | [Prometheus](https://prometheus.io/) and [Grafana](https://grafana.com/) | External metrics collection and visualization | Optional metrics export |
| Endpoint/XDR/SIEM platform | [Wazuh](https://documentation.wazuh.com/current/) | Agents, manager, indexer, dashboard, rules, inventory, API | Import selected alerts/context; do not recreate Wazuh |
| Network forensics | [Arkime](https://arkime.com/) / [Malcolm](https://github.com/cisagov/Malcolm) | Full packet capture/search and network analysis | Link/pivot to external deployments |
| File analysis | [YARA](https://virustotal.github.io/yara/) and [capa](https://github.com/mandiant/capa) | Signature scanning and capability identification | Optional analyst-invoked enrichment |
| Windows event triage | [Hayabusa](https://github.com/Yamato-Security/Hayabusa) / [Chainsaw](https://github.com/WithSecureLabs/Chainsaw) | Fast offline Windows event-log hunting | External replay/import workflow |

## Priority 1: MISP read-only intelligence provider

This is the strongest first integration because ArgusProwl already has a ThreatIntelProvider contract and contextual-intelligence orchestration. A MISP adapter can use an existing seam rather than adding another intelligence database or inventing a new IOC model.

Initial scope:
- User-configured MISP URL and read-only API key.
- IP, domain, URL, and file-hash lookup using the MISP REST API.
- Preserve source event UUID, attribute UUID, tags, distribution, timestamps, source URL, and confidence/decay metadata when available.
- Apply MISP warning lists and local allowlists before promoting matches.
- Cache bounded results with explicit TTL and stale-data behavior.
- Provider outage must never become a clean/benign verdict.
- No automatic publication, synchronization, or write operations in the first release.
- Never send private telemetry to a third-party MISP instance without explicit configuration and consent.

Keep the dependency optional. Prefer a small adapter using the existing HTTP/runtime stack; use PyMISP only if it materially reduces protocol complexity. Do not require users to run MISP: the provider is disabled unless configured.

**Implementation gate discovered during code review:** the current `ThreatIntelProvider` returns only `ThreatIntelReputation` and has no typed result for provider health, freshness, cache age, or lookup failure. The contextual-intelligence service currently treats an `UNKNOWN` verdict as a normal lookup result. That contract is insufficient to distinguish a genuine no-match from an unavailable MISP service or stale cached data. Do not ship the adapter by mapping timeouts/authentication errors to `UNKNOWN` or `BENIGN`. First extend the provider contract with an explicit outcome/status and freshness metadata, preserve backward compatibility for the in-memory provider, and test no-match, stale, timeout, HTTP 401/403, rate-limit, malformed-response, and success paths. Only then wire MISP into configuration and the composition root. This is a deliberate safety gate, not a reason to add a new dependency or MISP service to the default deployment.

References:
- https://misp-project.org/tools/
- https://misp-project.org/features/
- https://github.com/MISP/PyMISP

## Priority 2: Velociraptor endpoint investigation adapter

Velociraptor is a better fit for endpoint collection and remote forensic acquisition than maintaining a bespoke remote agent inside ArgusProwl. Its artifact and hunt model packages reusable VQL collection logic, supports targeted multi-endpoint collection, and exposes a server API.

Initial scope must be analyst-initiated:
- Configure an external Velociraptor endpoint and dedicated least-privilege API identity.
- Browse an allowlisted set of approved artifacts.
- Preview parameters and target scope before collection.
- Require explicit analyst action for every hunt or collection.
- Import collection metadata and results as evidence with original client, artifact, flow, timestamp, and source references.
- Enforce server-side time, result, upload, and concurrency limits.
- Audit who requested, approved, started, and imported a collection.
- Do not expose arbitrary VQL execution, arbitrary binary upload, or automatic containment initially.

Velociraptor warns that API keys can enable powerful actions and must be protected. Treat this adapter as a privileged security boundary, not a generic webhook.

References:
- https://docs.velociraptor.app/docs/hunting/
- https://docs.velociraptor.app/docs/server_automation/server_api/
- https://docs.velociraptor.app/docs/vql/artifacts/

## Priority 3: osquery ingestion, not fleet management

Support osquery by consuming its documented JSON result/event logs or an existing fleet manager's export. Convert rows into canonical events while retaining query name, host identifier, timestamp, columns, and original row payload.

Do not build an osquery scheduler, agent manager, distributed query engine, or enrollment service. Fleet managers are separate products with different licenses and capabilities. Start with import/replay and tested mappings for process, socket, package, and user data.

Reference: https://github.com/osquery/osquery

## Priority 4: Sigma content evaluation

Sigma is a community rule format and content ecosystem; pySigma parses and converts rules into backend queries. It is not a ready-made detection engine for ArgusProwl's event schema.

Do not import thousands of rules and claim they work. A safe first step:
1. Select a small, license-cleared or user-supplied rule subset.
2. Define explicit field mappings from supported source schemas to canonical events.
3. Convert only supported Sigma conditions into the existing rule contract, or export queries to an external supported backend.
4. Reject unsupported modifiers, data types, log sources, and conditions with actionable diagnostics.
5. Preserve rule source, license, upstream commit, UUID, references, status, and version.
6. Add positive, negative, and field-mapping tests per imported rule.
7. Never silently approximate a rule.

Rule content and parser-library licenses are separate questions. Review the license of each upstream rule repository and rule file before redistribution. Do not bulk-vendor rules into the Apache-2.0 ArgusProwl repository without compatible licensing and attribution.

References:
- https://github.com/SigmaHQ/sigma
- https://github.com/SigmaHQ/pySigma
- https://sigmahq-pysigma.readthedocs.io/en/stable/reference/backends.html

## Priority 5: external incident and timeline interoperability

ArgusProwl already has incidents, evidence, and investigation timelines. Replacing them with another platform creates migration and synchronization burden.

Add export/sync adapters only when a real workflow requires them:
- DFIR-IRIS: create/update a case and attach evidence references, alerts, IOCs, and report links. Keep ArgusProwl as the source of its event evidence. Confirm the target IRIS API version; contracts change.
- Timesketch: export a selected investigation timeline in a supported structured format with stable timestamps, source IDs, and evidence links. Avoid duplicating full event payloads unnecessarily.
- Keep both disabled by default and require explicit credentials and user actions.

References:
- https://docs.dfir-iris.org/
- https://docs.dfir-iris.org/_static/iris_api_reference_v2.0.0.html
- https://github.com/google/timesketch

## Priority 6: standard telemetry transport and operations

OpenTelemetry Collector can receive, process, and export telemetry through configurable pipelines. It may help customers who already standardize on OTLP or want a single collector distribution. It should not be mandatory: current file collectors already handle supported Zeek and Suricata sources.

Expose service metrics in a Prometheus-compatible format only if the current metrics model can do so without a heavyweight runtime. Let operators connect Prometheus/Grafana externally. Do not bundle them in product Compose.

References:
- https://opentelemetry.io/docs/collector/
- https://opentelemetry.io/docs/collector/architecture/
- https://opentelemetry.io/docs/collector/components/

## What not to add now

| Candidate | Reason to defer |
|---|---|
| OpenCTI alongside MISP | Two full CTI platforms overlap. Support OpenCTI as an alternative backend only when its knowledge-graph workflows are required. |
| Wazuh manager/indexer/dashboard in ArgusProwl Compose | Turns a small analyst application into a multi-service SIEM deployment and duplicates agents, rules, indexing, and dashboards. Integrate an existing Wazuh API instead. |
| Kafka / Redpanda / RabbitMQ | No measured distributed-ingestion requirement justifies broker operations, schema governance, delivery semantics, and deployment complexity. |
| Redis | Current default is local SQLite/single-process. Add only for a demonstrated shared-state or multi-instance requirement. |
| ClickHouse / OpenSearch / Elasticsearch | Keep SQLite for local/small deployments and PostgreSQL for supported server use. Revisit after measured retention, query latency, and ingest volume justify it. |
| Neo4j or another graph database | Current entity intelligence is a relational, indexed, evidence-backed projection. Add graph storage only if real investigation queries cannot be met efficiently with relational pivots. |
| Security Onion / Malcolm bundled services | Valuable specialist distributions, but they bring their own stack, storage, and operational assumptions. Integrate/pivot to an existing deployment instead. |
| Custom endpoint agent | Velociraptor and osquery already cover broad collection use cases. Build an agent only for a clearly scoped gap. |
| Another ML detector in the public core | Duplicates CHIMERA's purpose and creates model distribution, evaluation, and maintenance obligations. Keep proprietary model IP separate and optional. |

## Runtime dependency and code-ownership audit

The current pyproject.toml declares pandas, numpy, joblib, and scikit-learn as mandatory runtime dependencies. This is a material packaging and installation cost for a core product whose published role is telemetry normalization, evidence, hunting, and investigation.

Before removing them, audit every import and runtime path, including optional/research scripts and tests:
- If no production code imports a package, remove it from mandatory dependencies.
- A preliminary GitHub code-search audit on the current `main` snapshot found no source-code references to `pandas`, `numpy`, `joblib`, or `scikit-learn` beyond `pyproject.toml` and `uv.lock`. The PR changes only feature-provenance/evaluation code and does not add these imports. Treat these four packages as probable dead runtime dependencies, but complete a branch-pinned audit of source, scripts, tests, dynamic imports, Docker/CLI entry points, and lockfile reachability before changing the dependency set. No dependency has been removed yet.
- If only an optional feature needs it, move it into a named optional extra.
- If only benchmark/evaluation tooling needs it, move it into a development/research dependency group.
- If genuinely required by a supported core feature, document that feature and measure cold-start, install-size, and memory cost.
- Do not remove dependencies based solely on a repository-wide search that excludes dynamic imports or test/evaluation entry points.

Apply the same audit to transitive dependencies and duplicate libraries. Keep the lockfile synchronized and verify clean installation, import smoke tests, full backend tests, Docker build, and published CLI.

## Integration architecture requirements

Every new integration must:
- Be an adapter behind a narrow interface; the core domain must not import vendor SDKs.
- Be optional and disabled by default.
- Have validated configuration, connection test, health status, timeouts, retry/backoff, bounded response sizes, and rate limits.
- Use least-privilege credentials; prefer read-only identities.
- Avoid logging secrets, raw credentials, or full sensitive payloads.
- Preserve upstream identifiers, timestamps, source, license, version, and evidence provenance.
- Distinguish no-match, stale-cache, unavailable-provider, parse-failure, and authorization-failure outcomes.
- Never turn an unavailable provider into a benign verdict or fabricate enrichment.
- Have contract tests using sanitized fixtures and integration tests against disposable upstream instances where practical.
- Have a support matrix, tested versions, setup/disable/uninstall steps, and data-sharing implications.
- Not add a service to default Docker Compose.

## Licensing and supply-chain gate

Open source is not a sufficient license review. Before adding or redistributing code, rules, signatures, datasets, binaries, containers, or model assets:
- Identify the exact component and content license. Code, rules/data, documentation, binaries, and container base images can differ.
- Record required attribution and notices.
- Review copyleft/network-copyleft obligations and whether the integration is a separate process, plugin, SDK link, or derivative distribution.
- Pin tested releases or image digests; do not use floating latest tags in production integration tests.
- Track upstream security advisories and end-of-life policy.
- Do not automatically download rule packs, threat feeds, or external artifacts without source, license, checksum/signature, and update policy.

This is engineering guidance, not legal advice. Obtain legal review before redistributing third-party code or rule content in a commercial offering.

## Execution roadmap

### P0 — reduce burden without new services
- Preserve current collectors; document supported versions, configuration, replay, and failure modes.
- Audit mandatory Python dependencies and move research-only dependencies out of core if proven unused.
- Document external tool installation and connection patterns; keep product Compose minimal.
- Add a compatibility matrix and integration contract fixtures.

### P1 — first external integrations
- MISP read-only provider: IP/domain/hash lookup, warning lists, bounded cache, source provenance.
- osquery JSON event import/replay; no fleet manager.
- Sigma compatibility spike against a small, license-cleared test corpus; no bulk import.

### P2 — analyst-controlled investigation integrations
- Velociraptor artifact discovery and explicit, audited collection.
- DFIR-IRIS case export/sync if external case management is required.
- Timesketch timeline export.

### P3 — only when demanded by deployment scale
- OpenTelemetry Collector interoperability.
- Prometheus metrics endpoint.
- OpenCTI as an alternative CTI provider.
- External analytics storage after workload benchmarks establish need.

## Acceptance criteria

This strategy succeeds when:
- Default install remains a single ArgusProwl service with SQLite and no mandatory external security stack.
- Existing collectors remain supported ingestion paths for their sources.
- Integrations are optional, least-privilege, testable, and preserve evidence provenance.
- No proprietary model artifacts are in the public distribution.
- No broker, cache, graph database, search cluster, or agent is introduced without measured justification.
- License and maintenance review exists for every adopted third-party component and content source.
- The core team owns less duplicated security functionality and spends more effort on analyst workflow, evidence integrity, and interoperability.
