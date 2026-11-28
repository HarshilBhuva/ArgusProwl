# Product principles and architectural boundaries

This document is a durable product and engineering decision record. New features, dependencies, integrations, and roadmap work should be evaluated against these principles before implementation.

## Product identity

ArgusProwl is an **open-source-first threat-hunting and analyst-assistance suite**.

Its primary responsibility is to help security teams collect, normalize, search, correlate, investigate, and explain security telemetry. It should make an analyst more effective by bringing evidence and existing security capabilities into one coherent workflow.

ArgusProwl is not intended to become:
- A replacement for every EDR, NDR, IDS, SIEM, or specialist detection product.
- A collection of overlapping detectors built merely to increase the number of detection features.
- An autonomous black-box system that declares activity malicious without traceable evidence or analyst context.

The project may include native, deterministic hunting analytics and configurable rules where they provide useful cross-source context. Those capabilities support the analyst workflow; they do not redefine the product as a universal detection engine.

## Open-source-first integration policy

**Prefer integrating mature, actively maintained open-source security technology over reimplementing equivalent functionality.**

Before building a new parser, collector, protocol analyzer, detection, enrichment source, storage engine, or response capability:

1. Identify established open-source projects that already solve the problem.
2. Evaluate maintenance health, license compatibility, security posture, deployment cost, data formats, extensibility, and operational complexity.
3. Prefer a supported integration or adapter when it provides the needed capability without compromising evidence quality or user control.
4. Build a native implementation only when existing tools do not meet a documented requirement, or when a small native capability is materially simpler and safer.
5. Document why a dependency or native implementation was selected, including the trade-offs and limitations.

Do not add dependencies simply because they are popular. Avoid duplicating mature upstream functionality, and do not vendor or bundle third-party tools without checking their licenses and distribution terms.

## Models and proprietary intellectual property

Models can materially improve analyst assistance, but model ownership and distribution must remain explicit.

- ArgusProwl's open-source core may define stable interfaces for optional model-backed capabilities.
- Proprietary model weights, training data, training pipelines, private evaluation assets, and proprietary inference services must remain outside the public ArgusProwl source distribution unless their owner explicitly licenses them for redistribution.
- A public adapter or API contract does not grant access to proprietary weights or services. Access must be separately licensed and explicitly configured.
- Optional model integrations must be replaceable. The core platform must remain useful when no model is configured, the model is unavailable, or the user chooses not to use AI.
- No proprietary model weights, credentials, private datasets, or private model artifacts may be committed to the public repository, packaged in public releases, or downloaded automatically by the core application.
- Model output is advisory. It may summarize evidence, suggest pivots, explain findings, or help prioritize an investigation; it must not silently rewrite source evidence, fabricate telemetry, or turn an unverified suggestion into a confirmed fact.
- Preserve provenance: show which model or provider produced an output, the relevant evidence references, and any applicable confidence or limitations.

The intended separation is by **license and deployment boundary**, not by forcing every model-related feature into an unrelated product. A separately licensed model service or private companion package can integrate with ArgusProwl through a documented interface while the open-source core remains independently functional.

## Analyst authority and evidence

- Keep raw/source telemetry, normalized events, detection results, alerts, and analyst conclusions semantically distinct.
- Every finding should retain source-event or evidence references where available.
- Correlation and enrichment may add context but must not be represented as direct observation.
- Explain why a result appeared and expose relevant rule, source, provider, and model provenance.
- Analysts remain responsible for adjudication and response. Do not introduce autonomous containment or destructive response without an explicit, separately reviewed product decision and safeguards.

## Integration boundaries

Integrations should be modular and replaceable. Prefer documented contracts and adapters over hard dependencies on one vendor or provider.

Potential integration categories include:
- Telemetry and sensors (for example, Zeek, Suricata, Sysmon, and Linux Audit).
- Existing detection and analysis systems.
- Threat-intelligence and ATT&CK data sources.
- Case management, ticketing, alert delivery, and SOAR platforms.
- Optional local or remote model providers.

These are integration directions, not a claim that every connector is currently implemented or enabled. README capability claims and release notes must describe only what is actually shipped and validated.

## Architecture decision checklist

A proposed feature should answer:

1. Does it improve collection, normalization, evidence, correlation, investigation, explainability, or analyst workflow?
2. Is there a mature open-source tool that should be integrated instead?
3. Does it create duplicate functionality or a new operational burden?
4. Can it be isolated behind a stable interface and disabled without breaking the core?
5. Are licensing, data handling, provenance, security, and failure modes explicit?
6. Can its value be demonstrated with reproducible tests and representative data?

If these questions cannot be answered, defer implementation until the requirement is clear.

## Scope boundaries

- **ArgusProwl:** open-source-first threat hunting, analyst workflow, evidence management, correlation, integrations, and optional AI assistance.
- **PacketHawk:** a separate high-performance packet-processing project; integrate where useful rather than absorbing its implementation into ArgusProwl.
- **CHIMERA / chimera-c2-detector:** a separate model-based C2 research/detection project. Its proprietary or separately controlled model assets must not be copied into ArgusProwl's public distribution. An explicit integration may be considered later without merging repository ownership or model IP.

These boundaries are deliberate. Shared formats and integrations are welcome; accidental product and IP coupling is not.
