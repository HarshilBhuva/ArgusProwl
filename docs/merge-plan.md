# Repository consolidation plan

## Baseline

Use `argusprowl-community` `main` as the canonical code baseline. Preserve the existing source histories; do not rebase or force-reset either source branch.

## Carry forward

- Selected non-sensitive architecture and productization documentation from `Threat_Hunter`, clearly marked as historical until independently verified against this branch.
- Repository-level provenance and cleanup notes that do not disclose private implementation details.

## Explicitly exclude

- All private ML/C2 detection implementation, including TLS C2 detectors and detector-specific feature engineering.
- C2 detector tests, model artifacts, training/evaluation code, experiments, and internal research materials.
- Any import, registry entry, package export, or rule-loader allow-list entry that exposes private C2 functionality.
- The checked-in ATT&CK STIX JSON snapshot; use the community repository's pinned downloader and integrity checks instead.
- `.orig` editor backups, generated frontend build metadata, logs, local databases, and other generated runtime state.

## Product boundary

The community repository must not import or register private C2/ML components. Private code may be developed and tested only in the private repository. Any future premium product integration must use an explicitly reviewed product boundary and must not be implemented by copying private detector code into this repository.

## Validation required before release

- Confirm no C2-specific detector or TLS feature-extraction paths remain in the community tree.
- Search for private detector names and imports in source, tests, configuration, and documentation.
- Run backend tests, Ruff, compile checks, configuration validation, security checks, Docker build, and frontend tests/lint/build.
- Review README, CI path filters, license notice, and repository settings.
