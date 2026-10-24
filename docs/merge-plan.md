# Repository consolidation plan

## Baseline

Use `argusprowl-community` `main` as the canonical code baseline. It has the
more complete operational README, the Apache-2.0 license, the pinned lockfile,
and recent passing CI and Docker-build runs. `Threat_Hunter` has unrelated Git
history; do not rebase or force-reset either source branch.

## Carry forward

- TLS flow feature extraction, its unit tests, and the optional TLS C2 detector
  plus detector unit tests.
- The relevant productization and single-process architecture documentation,
  marked as historical reports until this consolidated branch is reverified.
- The detector registration/export and feature-extractor export needed to
  integrate the carried code with the current application structure.

## Exclude

- The checked-in ATT&CK STIX JSON snapshot. Use the community repository's
  pinned downloader and integrity checks instead; local data is ignored.
- `.orig` editor backups and generated frontend build metadata.
- Generated logs, local databases, model artifacts, and other local runtime
  state.

## License and provenance

Keep the community repository's Apache-2.0 license as the baseline. Verify
that all files carried from the former repository are authored by or licensed
for inclusion by the project's maintainers before redistributing. Retain both
source repositories until this branch passes CI and the canonical repository
has been established.

## Validation required before release

- Backend tests, Ruff, compile check, config validation, Bandit, Docker build,
  and frontend tests/lint/build.
- Confirm the TLS detector works with a configured ClickHouse client and real
  Zeek SSL data. The optional model artifact is not checked in.
- Review docs, README, CI path filters, license notice, and repo settings.
