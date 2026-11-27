"""Tests for Docker product packaging.

These are fast static source-inspection tests (no Docker daemon required) that enforce
the invariants the product image depends on:

- Dockerfile determinism: ``npm ci`` (no ``npm install``), pinned uv,
  frozen lockfile, non-root user, port 8080, static assets copied to
  ``/app/static``.
- Compose product-only: exactly one service (argusprowl), port 8080,
  no research infrastructure (clickhouse/zeek/vector/sliver).
- The CLI ``server`` subcommand is what the container runs.

Runtime image assertions live in ``scripts/smoke_docker_image.sh`` and run
once against the already-built image in the Docker workflow. This avoids
rebuilding the image inside the general pytest suite.

Run with:  uv run pytest tests/integration/test_docker_product.py -v
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"


def _dockerfile_text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _compose() -> dict:
    return yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Dockerfile invariants
# ---------------------------------------------------------------------------


def test_dockerfile_uses_npm_ci_not_npm_install():
    """Frontend build must be deterministic (locked package-lock.json)."""
    text = _dockerfile_text()
    assert "npm ci" in text
    assert "npm install" not in text


def test_dockerfile_pins_uv_version():
    """uv must be pinned to a specific version, not 'latest'."""
    text = _dockerfile_text()
    assert "UV_VERSION" in text
    # uv is installed via pip with a pinned version, not a floating tag.
    assert "uv==${UV_VERSION}" in text
    assert "uv:latest" not in text


def test_dockerfile_uses_frozen_lockfile():
    """Backend deps must come from the committed uv.lock, not be re-resolved."""
    text = _dockerfile_text()
    assert "uv.lock" in text
    assert "uv sync --frozen" in text
    assert "--no-dev" in text


def test_dockerfile_runs_non_root():
    """Product container must not run as root."""
    text = _dockerfile_text()
    assert "USER user" in text
    assert "USER root" not in text


def test_dockerfile_exposes_8080():
    text = _dockerfile_text()
    assert "EXPOSE 8080" in text
    assert "EXPOSE 8000" not in text


def test_dockerfile_copies_frontend_dist_to_app_static():
    """Compiled frontend must land at /app/static (resolved by _static_dir)."""
    text = _dockerfile_text()
    assert "COPY --from=frontend-builder /build/dist/ ./static/" in text


def test_dockerfile_copies_config_for_detection_rules():
    """Detection rules under config/rules must ship in the image."""
    text = _dockerfile_text()
    assert "COPY config/ ./config/" in text
    assert "COPY src/ ./src/" in text


def test_dockerfile_runs_server_subcommand():
    """The image must run the API server, not the full telemetry pipeline."""
    text = _dockerfile_text()
    # CMD runs the venv interpreter directly: /app/.venv/bin/python -m argusprowl server
    assert '"argusprowl"' in text and '"server"' in text
    assert '"start"' not in text
    assert "uv run" not in text, "uv must not be needed at runtime"


def test_dockerfile_uses_venv_interpreter_not_uv_at_runtime():
    """Runtime entrypoints must use the installed virtualenv, not uv."""
    text = _dockerfile_text()
    assert "/app/.venv/bin/python" in text
    assert "/usr/local/bin/uv" not in text


def test_dockerfile_does_not_install_gosu():
    """No privilege-escalation helper is needed in the runtime image."""
    text = _dockerfile_text()
    assert "gosu" not in text


def test_dockerfile_has_healthcheck():
    text = _dockerfile_text()
    assert "HEALTHCHECK" in text
    assert "/health" in text


# ---------------------------------------------------------------------------
# Compose product-only invariants
# ---------------------------------------------------------------------------


def test_compose_has_exactly_one_service():
    """Product deployment is a single container — no research services."""
    services = _compose().get("services", {})
    assert set(services) == {"argusprowl"}


def test_compose_exposes_8080_on_loopback_only():
    """The default product deployment must not publish the API on all interfaces."""
    services = _compose()["services"]
    ports = services["argusprowl"]["ports"]
    assert "127.0.0.1:8080:8080" in ports


def test_compose_no_research_infrastructure():
    """ClickHouse/Zeek/Vector/Sliver must not be part of the product."""
    text = COMPOSE_FILE.read_text(encoding="utf-8").lower()
    for banned in ("clickhouse", "zeek", "vector:", "sliver"):
        assert banned not in text, f"research infra '{banned}' leaked into product compose"


def test_compose_builds_image_from_repo_context():
    service = _compose()["services"]["argusprowl"]
    assert service["build"]["context"] == "."


def test_compose_persists_storage_on_volumes():
    service = _compose()["services"]["argusprowl"]
    volumes = service.get("volumes", [])
    assert any("/app/data" in v for v in volumes)
    assert any("/app/logs" in v for v in volumes)


def test_compose_sets_api_host_for_container_binding():
    service = _compose()["services"]["argusprowl"]
    env = service.get("environment", [])
    assert "TH_API__HOST=0.0.0.0" in env
    assert "TH_API__PORT=8080" in env


def test_compose_does_not_override_to_root_user():
    """Compose must not override the image's non-root USER directive.

    The image declares ``USER user``; overriding it to root at the
    compose level (with a runtime chown/gosu workaround) defeats the
    build-time ownership model and must not be present.
    """
    service = _compose()["services"]["argusprowl"]
    user = service.get("user")
    assert user in (None, "user"), f"compose must not run the service as root, got user={user!r}"


def test_compose_does_not_use_gosu_or_runtime_chown():
    """No privilege-escalation workaround in the compose service definition."""
    text = COMPOSE_FILE.read_text(encoding="utf-8").lower()
    assert "gosu" not in text, "compose must not invoke gosu (no root entrypoint)"
    assert "chown" not in text, "compose must not chown at runtime (baked into image)"


# ---------------------------------------------------------------------------
# Build context hygiene
# ---------------------------------------------------------------------------


def test_dockerignore_excludes_dev_only_paths():
    """Dev-only and research infra must not leak into the image context."""
    text = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    for banned in (
        ".venv",
        ".git",
        "tests/",
        "scripts/",
        "deploy/",
        "logs/",
        "data/",
        "node_modules",
    ):
        assert banned in text, f".dockerignore must exclude '{banned}'"


def test_dockerignore_does_not_require_removed_requirements_txt():
    text = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "requirements.txt" not in text


def test_cli_server_subcommand_exists():
    """The image CMD must match a real subcommand of the argusprowl CLI."""
    import importlib

    main_mod = importlib.import_module("argusprowl.__main__")
    parser = main_mod.create_parser()
    parser.parse_args(["server", "--config", "/app/config/default.yaml"])  # must not raise
    parser.parse_args(["validate-config"])  # sanity


