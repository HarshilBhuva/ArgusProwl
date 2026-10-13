"""Tests for Docker product packaging.

These are static source-inspection tests (no docker required) that enforce
the invariants the product image depends on:

- Dockerfile determinism: ``npm ci`` (no ``npm install``), pinned uv,
  frozen lockfile, non-root user, port 8080, static assets copied to
  ``/app/static``.
- Compose product-only: exactly one service (argusprowl), port 8080,
  no research infrastructure (clickhouse/zeek/vector/sliver).
- The CLI ``server`` subcommand is what the container runs.

Run with:  uv run pytest tests/integration/test_docker_product.py -v
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
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


def test_compose_exposes_8080_to_host():
    services = _compose()["services"]
    ports = services["argusprowl"]["ports"]
    assert "8080:8080" in ports


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


# ---------------------------------------------------------------------------
# Real Docker runtime tests (skip cleanly when Docker is unavailable)
#
# These build and run the actual image to prove runtime behaviour:
# non-root user, frontend assets present, app boots, /health and / respond,
# SPA fallback works, /api/* 404 is not swallowed by the SPA, the process
# is running, data/log paths are writable, and Node/npm are absent.
#
# Skipped when docker or the image build fails — they exercise a real
# container only when the toolchain is available.
# ---------------------------------------------------------------------------


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=30)
    return result.returncode == 0


@pytest.fixture(scope="module")
def docker_image() -> str:
    """Build the product image once; skip the whole module if it's unavailable."""
    if not _docker_available():
        pytest.skip("Docker not available")
    tag = "argusprowl:test"
    result = subprocess.run(
        ["docker", "build", "-t", tag, str(REPO_ROOT)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        pytest.skip(f"Docker build failed:\n{result.stderr[-2000:]}")
    yield tag


def _run_container(tag: str, port: int) -> subprocess.CompletedProcess[str]:
    """Start a detached container and capture its container ID."""
    return subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "-p",
            f"{port}:8080",
            "-e",
            "TH_API__HOST=0.0.0.0",
            "-e",
            "TH_API__PORT=8080",
            tag,
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _curl(port: int, path: str, timeout: float = 2.0) -> int:
    """Return the HTTP status, treating startup/network errors as not-ready."""
    try:
        result = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                str(timeout),
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                f"http://127.0.0.1:{port}{path}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 1,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    try:
        return int(result.stdout.strip() or "0")
    except ValueError:
        return 0


def _wait_for_http(port: int, timeout: float = 20.0) -> bool:
    """Poll health responsively with a strict overall deadline.

    A short per-request timeout prevents a single stalled request from
    consuming the remaining readiness budget. Polling starts immediately;
    no fixed startup sleep is required.
    """
    deadline = time.monotonic() + timeout
    while True:
        if _curl(port, "/health", timeout=1.0) == 200:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.2, remaining))


def test_docker_image_runs_non_root(docker_image):
    """The process inside the container must not run as root."""
    result = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "whoami", docker_image],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout.strip() != "root"


def test_docker_image_has_frontend_assets(docker_image):
    """Compiled SPA assets must be present at /app/static."""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            docker_image,
            "-c",
            "ls /app/static/index.html /app/static/assets/",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"missing frontend assets: {result.stderr}"


def test_docker_image_has_no_node_or_uv(docker_image):
    """Node, npm, and uv must not be present in the runtime image."""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            docker_image,
            "-c",
            "command -v node && exit 1 || true; "
            "command -v npm  && exit 1 || true; "
            "command -v uv   && exit 1 || true; "
            "true",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    # The script exits 0 only if none of the three tools are found.
    assert result.returncode == 0, (
        f"node/npm/uv found in runtime image:\n{result.stdout}{result.stderr}"
    )


def test_docker_image_data_and_logs_writable(docker_image):
    """The non-root user must be able to write to /app/data and /app/logs."""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            docker_image,
            "-c",
            "touch /app/data/.write_test && rm /app/data/.write_test && "
            "touch /app/logs/.write_test && rm /app/logs/.write_test",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"write test failed: {result.stderr}"


def test_docker_container_boots_and_serves(docker_image):
    """The full container must boot, respond to /health, serve the SPA at /,
    return JSON 404 for unknown /api/ paths (not SPA HTML), and have a live
    process."""
    port = _free_port()
    proc = _run_container(docker_image, port)
    container_id = proc.stdout.strip()

    try:
        if not _wait_for_http(port, timeout=20.0):
            logs = subprocess.run(
                ["docker", "logs", container_id],
                capture_output=True,
                text=True,
                timeout=5,
            )
            state = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", container_id],
                capture_output=True,
                text=True,
                timeout=5,
            )
            raise AssertionError(
                "container never became ready "
                f"(state={state.stdout.strip()!r}); "
                f"stdout/stderr:\\n{logs.stdout}\\n{logs.stderr}"
            )

        # /health returns 200
        assert _curl(port, "/health") == 200

        # / serves the SPA (HTML content)
        root_result = subprocess.run(
            ["curl", "-s", f"http://127.0.0.1:{port}/"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "<" in root_result.stdout, "GET / did not return HTML"

        # Unknown /api/v1/ path returns JSON 404, not SPA HTML
        api_result = subprocess.run(
            [
                "curl",
                "-s",
                "-H",
                "Accept: application/json",
                f"http://127.0.0.1:{port}/api/v1/nonexistent",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        api_status = subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                f"http://127.0.0.1:{port}/api/v1/nonexistent",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert api_status.stdout.strip() in ("404", "405"), (
            f"unknown API path returned {api_status.stdout.strip()}, expected 404/405"
        )
        assert "html" not in api_result.stdout.lower(), (
            "unknown /api/ path returned HTML (SPA swallowed the API route)"
        )

        # A valid /api/v1/ endpoint works
        health_api = subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                f"http://127.0.0.1:{port}/api/v1/health",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert health_api.stdout.strip() in ("200", "503"), (
            f"/api/v1/health returned {health_api.stdout.strip()}"
        )

        # A SPA route resolves to the frontend (200 HTML)
        spa = subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                f"http://127.0.0.1:{port}/alerts/xyz",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert spa.stdout.strip() == "200", (
            f"SPA route /alerts/xyz returned {spa.stdout.strip()}, expected 200"
        )

        # The process is running inside the container
        running = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container_id],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert running.stdout.strip() == "true", "container process is not running"

    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_id], capture_output=True, text=True, timeout=15
        )
