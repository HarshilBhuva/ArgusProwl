# Repository-wide agent and contributor instructions

Before proposing or implementing product work, read [Product principles and architectural boundaries](docs/product-principles.md) and [Open-source ecosystem and integration strategy](docs/open-source-ecosystem.md).

## Non-negotiable product boundaries

- ArgusProwl is an open-source-first **threat-hunting and analyst-assistance suite**. Do not turn it into a replacement for every EDR, NDR, IDS, SIEM, or SOAR product.
- Prefer integrating mature, maintained open-source security tools over rebuilding equivalent functionality. Document why a native implementation is necessary when no suitable integration exists.
- Keep the core useful without AI or model access. Model-backed features are optional and advisory; preserve evidence provenance and analyst authority.
- Never commit, bundle, publish, or automatically fetch proprietary model weights, private training data, credentials, or private model artifacts into this public repository. Proprietary model access must be separately licensed and explicitly configured behind a documented interface.
- Keep CHIMERA / chimera-c2-detector and its model assets separate from ArgusProwl. Do not copy its model, training pipeline, or proprietary artifacts into this repository. A future explicit integration must preserve the licensing and deployment boundary.
- Keep PacketHawk as a separate project; integrate through stable formats/interfaces where useful rather than absorbing its implementation.
- Distinguish source telemetry, normalized events, detection results, alerts, enrichment, model suggestions, and analyst conclusions. Never present inference as direct observation.
- Do not claim an integration or capability is shipped until it is implemented and validated.

## Engineering expectations

- Prefer small, replaceable adapters and explicit contracts over hard vendor dependencies.
- Evaluate license compatibility, maintenance health, security posture, operational complexity, and failure behavior before adding dependencies.
- Validate changes with reproducible tests and representative data. Report limitations and negative results honestly.
- Keep secrets and sensitive datasets out of source control.
