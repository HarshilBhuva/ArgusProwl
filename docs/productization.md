# Productization & Verification Report

This report documents the changes made to convert argusprowl into a
single-container, Docker-ready product and the verification performed.

## 1. Single-Process Product Architecture

argusprowl runs as a single Python process that serves both the FastAPI backend
and the compiled React frontend from one port. There is no separate Vite dev
server, no npm at runtime, and no process-group management — one port, one
process, one shutdown path.

- Local developer entry point: `scripts/start` → `.venv/bin/python -m
  argusprowl start` → `Application.startup(start_api=False)` wires the DI
  container, starts the processing loop and collectors, builds the API app via
  `create_api_app()` (which validates the frontend build), then
  `Application.run_foreground(host, port)` blocks on `uvicorn.run(api_app)`.
- Route map: `/api/v1/*` and the FastAPI built-ins (`/docs`, `/redoc`,
  `/openapi.json`) route to the FastAPI table; `/assets/{path:path}` serves
  static files from the compiled bundle; a `/{path:path}` catch-all serves the
  SPA `index.html` for any unknown UI route. The catch-all never intercepts
  `/api/`, `/docs`, `/redoc`, or `/openapi.json`.

## 2. Docker Product Image

The product image is built from `Dockerfile` (multi-stage) and orchestrated by
`docker-compose.yml` (product-only).

Build invariants:
- **Deterministic frontend build** — the `frontend-builder` stage uses
  `npm ci` against the committed `package-lock.json`. No `npm install`, no
  registry drift.
- **Pinned toolchain + frozen lock** — dependencies are installed by a
  `ghcr.io/astral-sh/uv:0.7.13` build stage with `uv sync --frozen --no-dev`
  against the committed `uv.lock`. uv is a build-time tool only; it is **not
  present in the final runtime image**.
- **No uv at runtime** — the `CMD` and `HEALTHCHECK` entrypoints invoke
  `/app/.venv/bin/python` directly. The final runtime image contains no
  uv binary, no Node, no npm, and no gosu.
- **Single source of dependency truth** — `uv` + committed `uv.lock` is the
  sole authority. The parallel `requirements.txt` was deleted; consumers were
  migrated to the `uv`/`src`-layout package (Task #2).
- **No research infrastructure** — the product image ships only the compiled
  frontend and the Python service. Sensor capture, telemetry store, log
  streaming, and any ClickHouse/Zeek/Vector/Sliver components are excluded
  from the product image.
- **ML dependencies audited and confirmed in use** — `pandas`, `numpy`,
  `joblib`, and `scikit-learn` were audited and confirmed in use. They are
  retained because product code uses them, specifically the TLS C2 / TLS flow
  functionality (`tls_c2_detector.py` and `tls_flow_extractor.py`).
  `TLSC2Detector` remains registered in the detector/rule loading path, even
  though it is lazy because it is not currently present in the active YAML
  configuration. The missing `.joblib` model is handled gracefully at
  startup. `clickhouse-connect` is not part of `pyproject.toml` or `uv.lock`
  and remains outside the product dependency set.
- **Non-root, no privilege escalation** — the runtime stage declares
  `USER user` and bakes ownership of `/app/data`, `/app/logs`, and the
  virtualenv into the image layer at build time (`chown -R user:user`).
  Named-volume first-attach populates from that layer, so no runtime
  `chown` or `gosu` workaround is required.
- **No Node/npm in runtime** — the `node:22-alpine` builder stage is
  compile-only; the `python:3.13-slim` runtime contains no Node tooling.

Compose invariants:
- One service (`argusprowl`), single port mapping `8080:8080`.
- Host/port overridable via `TH_API__HOST` / `TH_API__PORT`
  (compose sets `0.0.0.0` / `8080` so the container port mapping works).
- No `user:` override to root; the container runs as the image's `USER user`.
- Named volumes `argusprowl_data` and `argusprowl_logs` persist the SQLite
  store and logs across image rebuilds. If an older root-owned volume from a
  previous build still exists, remove it once before first start:
  `docker volume rm argusprowl_data argusprowl_logs`.

## 3. Documentation Accuracy Reconciliation

All stale `app/` and `app.` module-path references were corrected to the
actual `src/argusprowl/` and `argusprowl.` package layout, and residual
"Threat Hunter" branding was replaced with "argusprowl". No `app/` or `app.`
path reference remains in `docs/*.md`.

- `docs/architecture.md` — core-box path, every layer-responsibility path,
  data-flow pipeline diagram, dotted module references
  (`argusprowl.detection.contract.DetectionRule`,
  `argusprowl.models.DetectionResult`,
  `argusprowl.collectors.{sysmon, windows_event_log, linux_audit, suricata}`),
  extension-point paths, and the dependency-graph ASCII art were all retargeted
  to `src/argusprowl/`. Duplicated layer numbering was consolidated
  (Decision Engine folded into the alert-creation / dedup / correlation /
  suppression description; the stray "Detector registry... plugin-based"
  entry removed).
- `docs/single-process.md` — `app/api/frontend_serving.py` corrected to
  `src/argusprowl/api/frontend_serving.py`.
- `docs/testing.md`, `docs/replay.md` — `app/` → `src/argusprowl/` path
  substitutions.

## 4. Test & Verification Coverage

- Static source-inspection tests in `tests/integration/`
  (`test_docker_product.py`, `test_start_script.py`) lock down the
  product-invariant invariants (compose is product-only, image is
  non-root/deterministic, startup script respects the `.venv`/`uv` contract,
  no research infra in the product image). 37 integration tests green.
- Full suite: **2555 passed** in ~130s.
- `python -m compileall` clean.

## 5. Out-of-Scope / Known Debt

Pre-existing `ruff` style debt is not introduced by the productization
changes and is intentionally left untouched; the productization work adds
no new lint violations.

## 6. Related Documents

- [[Architecture]] — `docs/architecture.md`
- [[Single-Process]] — `docs/single-process.md`
