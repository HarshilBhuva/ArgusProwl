# ArgusProwl

![Python](https://img.shields.io/badge/Python-3.13%2B-blue)
![License](https://img.shields.io/badge/License-Apache--2.0-blue)
![Status](https://img.shields.io/badge/Status-Alpha-orange)

ArgusProwl is an early-stage security monitoring and investigation platform. It provides a React web interface and FastAPI API for reviewing alerts, investigating indicators of compromise (IOCs), exploring evidence, and working with incidents and detection rules. The Python backend also includes telemetry parsers, detection logic, and offline replay.

**Project status: Alpha.** Interfaces, configuration, and operational behavior may change. Validate the platform in a test environment before relying on it for production security monitoring.

## What it includes

- **Analyst interface and API:** dashboard, alert search and details, IOC investigations, evidence search, incidents, entities, and rule management.
- **Detection pipeline:** configurable YAML rules, event normalization, detection evaluation, alert creation, deduplication, and correlation components.
- **Behavioral analysis:** bounded baselines and temporal/periodicity analysis. Behavioral scores are investigation signals, not proof of malicious activity.
- **Telemetry parsers and collectors:** support code for Zeek, Suricata, Sysmon, Windows Event Log, and Linux Audit. Availability depends on source configuration, operating system, and permissions; these sources are not all enabled by default.
- **Offline replay:** process supported historical log files through the detection pipeline.
- **Optional MITRE ATT&CK enrichment:** map supported detections and investigations to ATT&CK knowledge when a local snapshot is installed and enrichment is enabled.
- **Local persistence:** SQLite is the default configured storage backend. The Docker deployment persists application data and logs in named volumes.

ArgusProwl is not a bundled sensor-capture or full telemetry data-lake distribution. The default Docker Compose deployment runs the application UI and API in one container. Separate sensor capture, log streaming, and external telemetry-store infrastructure are outside that deployment.

## Architecture

The production Docker image uses a multi-stage build:

1. Node.js builds the React frontend into static assets.
2. Python dependencies are installed into a virtual environment.
3. A non-root runtime image serves the compiled frontend and FastAPI application from one container and port.

Main backend areas include API routes, application lifecycle and dependency injection, telemetry parsing and normalization, detection and decision logic, alert and investigation services, and storage. SQLite is the default local backend. Other adapters or references in architecture documentation may be incomplete or intended for future deployment scenarios; do not assume every documented adapter is production-ready.

The FastAPI application serves the compiled React single-page application
alongside its API. API routes and the OpenAPI documentation are handled by
FastAPI; frontend assets are served from `frontend/dist/`, with a fallback
for client-side UI routes. When running locally, build the frontend before
starting the API. A missing frontend build is a startup error, not a usable
UI-less deployment.

## Quickstart with Docker

### Prerequisites

- Docker Engine with the Docker Compose plugin.

### Run

From the repository root:

```bash
docker compose up --build
```

Open [http://localhost:8080](http://localhost:8080).

The container serves the UI and API from the same port. Compose persists application data and logs in named volumes. ATT&CK data is not included in the image and is not required for default startup.

```bash
# Follow application logs
docker compose logs -f argusprowl

# Stop without deleting persisted volumes
docker compose down

# Check API health inside the container
docker compose exec argusprowl python -m argusprowl health
```

**Warning:** `docker compose down -v` removes named volumes and their persisted data. Use it only when you intend to delete that state.

## Local development

### Prerequisites

- Python 3.13 or later
- [uv](https://docs.astral.sh/uv/)
- Node.js 22 or later and npm (for frontend build and tests)

### Install dependencies and build the frontend

```bash
uv sync

cd frontend
npm ci
npm run build
cd ..
```

The backend serves the production frontend from `frontend/dist/`. Build it before starting the API locally.

### Run the API and UI

```bash
uv run argusprowl server
```

The default API port is `8080`. Configure the host and port if you need different values. The `server` command starts the HTTP API; use `uv run argusprowl start` when you intend to start the detection engine and configured collectors as well.

Other CLI commands:

```bash
# Validate configuration
uv run argusprowl validate-config

# Check application health
uv run argusprowl health

# Replay a supported historical log file
uv run argusprowl replay /path/to/logfile
```

Use `uv run argusprowl --help` and the relevant subcommand's `--help` for available options. Replay input must match a supported source format.

## Configuration

The default configuration is `config/default.yaml`. CLI commands support `--config <path>` for an alternate configuration file.

Configuration can also be overridden with environment variables using the `TH_` prefix. Nested keys use double underscores. For example:

```bash
export TH_API__PORT=9090
```

Review the configuration before enabling a collector. Source paths, permissions, operating-system support, retention, and polling intervals depend on your environment. A parser or configuration section existing does not mean its collector is enabled.

## Optional MITRE ATT&CK dataset

ATT&CK enrichment is disabled by default. The Enterprise ATT&CK dataset is not stored in this repository or included in the Docker image.

For local development, first run `uv sync`, then execute from the repository root:

```bash
uv run python scripts/download_attck_snapshot.py
```

The installer downloads the version-tagged upstream artifact, verifies its SHA-256 digest and collection metadata, and imports it into the configured snapshot path. The default path is `data/attck_snapshot.json`; local data under `data/` is ignored by Git. If ATT&CK enrichment is enabled without a snapshot, startup reports an installation error rather than silently downloading the dataset.

For Docker deployments, install and mount/configure a snapshot separately if you choose to enable ATT&CK enrichment. The standard Compose configuration does not install it automatically.

MITRE ATT&CK is a trademark of The MITRE Corporation. ATT&CK data and related materials are subject to [MITRE's terms of use](https://attack.mitre.org/terms-of-use/). Review those terms and applicable attribution requirements before redistributing ATT&CK-derived content.

## Development and checks

### Backend tests and lint

```bash
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
```

To generate a coverage report:

```bash
uv run pytest --cov=argusprowl
```

### Frontend tests, lint, and build

```bash
cd frontend
npm ci
npx vitest run
npm run lint
npm run build
```

The frontend lint command may report existing warnings. Review its output rather than assuming a successful build means lint is clean.

### Docker validation

```bash
docker compose config -q
docker compose up --build
```

The repository's CI workflows are the authoritative source for which checks run automatically and which findings block a build.

## Security and operational notes

- **Alpha software:** evaluate the platform against your requirements and test it with representative data before operational use.
- **Network exposure:** Compose publishes the UI and API on host port `8080`. Run it only on a trusted network unless you have separately configured appropriate access controls and network restrictions. Do not assume authentication or authorization is provided without verifying the deployed configuration and routes.
- **Sensitive telemetry:** logs and investigation data can contain hostnames, usernames, IP addresses, process details, and other sensitive information. Restrict access to the service, volumes, configuration, and backups.
- **Least privilege:** the Docker runtime runs as a non-root user. Host-based collectors may require platform-specific privileges; assess the need before granting them.
- **Evidence and retention:** some processing and evidence paths use bounded in-memory state. Do not assume all raw telemetry or evidence is durably retained. Confirm persistence and retention behavior for the data you need.
- **ATT&CK terms:** the dataset is separately installed and subject to MITRE's terms. Review those terms before redistributing derived material.

## Project layout

```text
config/                  Default configuration and detection rules
docs/                    Architecture, replay, and testing guidance
frontend/                React + TypeScript application
scripts/                 ATT&CK installation and development utilities
src/argusprowl/          Python backend
tests/                   Backend unit and integration tests
Dockerfile               Multi-stage application image
docker-compose.yml       Single-container UI/API deployment
pyproject.toml           Python package, dependencies, and tooling
uv.lock                  Locked Python dependency versions
```

Further implementation details:

- [Architecture](docs/architecture.md)
- [Replay](docs/replay.md)
- [Testing](docs/testing.md)
- [Contributing](CONTRIBUTING.md)

## Contributing

Contributions and bug reports are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), run relevant tests and checks, and do not include secrets, production telemetry, or local ATT&CK datasets in commits.

## License

ArgusProwl is licensed under Apache-2.0. See [LICENSE](LICENSE) for the full license text.


## Unified repository provenance

This repository consolidates the maintained ArgusProwl application with selected
components and documentation from the earlier `Threat_Hunter` codebase. The
community application's current deployment model, dependency lock, security
guidance, and Apache-2.0 license remain authoritative.

Selected carry-forwards are the optional TLS C2 flow feature extractor and
detector with unit tests, plus productization and single-process architecture
notes. The bundled ATT&CK JSON and editor backup files are not copied; use
`scripts/download_attck_snapshot.py` to fetch and verify the pinned snapshot
into ignored local data storage.

The source repositories remain historical references until this unified branch
passes CI and the final repository location has been established.
