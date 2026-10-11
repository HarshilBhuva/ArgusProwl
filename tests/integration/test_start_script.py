"""Tests for the one-command local frontend+backend entry point.

The single-process layout uses one OS process on a single port (default
``127.0.0.1:8080``) to serve both the FastAPI backend and the React frontend
(production build from ``frontend/dist/``). There is no Vite/npm, no separate
backend process, and no process-group cleanup.

Tests here cover:
1. **Source inspection** — launcher invariants without launching any process.
2. **Venv check** — running from a tree without ``.venv`` must fail closed.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
START_SCRIPT = REPO_ROOT / "scripts" / "start"
SERVER_SCRIPT = REPO_ROOT / "scripts" / "server"
WRAPPER_SCRIPTS = (
    REPO_ROOT / "scripts" / "test",
    REPO_ROOT / "scripts" / "server",
    REPO_ROOT / "scripts" / "health",
    REPO_ROOT / "scripts" / "validate",
)
DEFAULT_PORT = 8080
INSTALL_HINT = "uv sync --group dev"


def _read_start_script() -> str:
    return START_SCRIPT.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Source-inspection tests (no live processes)
# ---------------------------------------------------------------------------


def test_start_script_exists_and_is_executable():
    """The one-command entry point must exist and be executable."""
    assert START_SCRIPT.is_file(), f"missing {START_SCRIPT}"
    mode = START_SCRIPT.stat().st_mode
    assert mode & stat.S_IXUSR, f"{START_SCRIPT} must be executable"


@pytest.mark.parametrize("wrapper", WRAPPER_SCRIPTS, ids=lambda p: p.name)
def test_wrapper_scripts_exist_and_use_repo_venv(wrapper: Path):
    """Thin wrappers must exist, be executable, and exec the repo-local .venv."""
    assert wrapper.is_file(), f"missing {wrapper}"
    mode = wrapper.stat().st_mode
    assert mode & stat.S_IXUSR, f"{wrapper} must be executable"
    source = wrapper.read_text(encoding="utf-8")
    assert ".venv" in source
    assert "python3" not in source.split("exec", 1)[-1] or ".venv/bin/" in source
    assert INSTALL_HINT in source
    assert "system python" not in source.lower()


def test_start_script_fails_closed_when_venv_missing():
    """Missing .venv must print the install hint and never fall back to system Python."""
    source = _read_start_script()
    assert ".venv" in source
    assert INSTALL_HINT in source
    assert "exit 1" in source
    after_venv_check = source.split('if [ ! -d "$REPO_ROOT/.venv" ]', 1)[-1]
    assert not re.search(r"\npython3?\s", after_venv_check)


def test_start_script_uses_repo_venv_and_main_py_start():
    """Product launch must execute the repo-local Python interpreter through -m argusprowl start."""
    source = _read_start_script()
    assert ".venv/bin/python" in source
    assert "-m argusprowl" in source
    assert "start" in source


def test_start_script_uses_single_port():
    """Product mode is single-process: one port (8080) serves API and UI."""
    source = _read_start_script()
    assert str(DEFAULT_PORT) in source
    # Single-process mode must not advertise a second frontend port.
    assert "5173" not in source


def test_start_script_no_vite_or_npm_in_product_path():
    """Product launch must not invoke Vite or npm; they remain dev-only."""
    source = _read_start_script()
    assert "npm" not in source
    assert "vite" not in source
    assert "run dev" not in source


def test_start_script_no_setsid_or_dual_pid_tracking():
    """Single-process mode must not fork backend/frontend nor track PIDs."""
    source = _read_start_script()
    assert "setsid" not in source
    assert "BACKEND_PID" not in source
    assert "FRONTEND_PID" not in source


def test_start_script_no_process_group_kill():
    """Must not use kill -- - (process-group kill) or broad kill commands."""
    source = _read_start_script()
    assert "kill -- -" not in source
    assert "pkill" not in source
    assert "killall" not in source
    assert "kill 0" not in source


def test_start_script_port_preflight_on_single_port():
    """The launcher must check the port before starting and report conflicts."""
    source = _read_start_script()
    assert "check_port" in source or "port" in source.lower()
    assert "already in use" in source or "port conflict" in source, (
        "scripts/start must report a clear error when a port is occupied"
    )


def test_start_script_prints_dashboard_url_on_success():
    """Successful startup must print the UI/API dashboard URL on the single port."""
    source = _read_start_script()
    assert "8080" in source
    assert "127.0.0.1" in source
    assert (
        "Frontend" in source
        or "dashboard" in source.lower()
        or "UI" in source
        or "http" in source.lower()
    )


def test_start_script_no_lan_binding():
    """Local-first: do not advertise or bind 0.0.0.0."""
    source = _read_start_script()
    assert "0.0.0.0" not in source


def test_start_script_no_frontend_port_fallback():
    """Must not silently fall back to alternate frontend ports."""
    source = _read_start_script()
    for port in ("5173", "5174", "5175", "5176"):
        assert port not in source, f"scripts/start must not reference port {port}"


# ---------------------------------------------------------------------------
# Runtime tests
# ---------------------------------------------------------------------------


def test_missing_venv_runtime_exits_nonzero(tmp_path, monkeypatch):
    """Executing the start script from a tree without .venv must fail closed."""
    import stat as statmod

    work = tmp_path / "tree"
    scripts_dir = work / "scripts"
    scripts_dir.mkdir(parents=True)
    shutil.copy(START_SCRIPT, scripts_dir / "start")
    os.chmod(scripts_dir / "start", statmod.S_IRWXU)
    result = subprocess.run(
        [str(scripts_dir / "start")],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert ".venv" in combined
    assert "uv sync" in combined


def test_script_args_passthrough():
    """Extra args (e.g. --config) must be passed through to main.py."""
    source = _read_start_script()
    assert "ARGS=()" in source
    assert "${ARGS[@]}" in source


def test_sigint_and_sigterm_traps():
    """Script must trap SIGINT and SIGTERM to exit cleanly."""
    source = _read_start_script()
    assert "trap" in source
    assert "SIGINT" in source and "SIGTERM" in source


def test_single_process_lifecycle_with_ephemeral_port(tmp_path, monkeypatch):
    """Start the real single-process app on an OS-assigned port, confirm it serves, then shut down cleanly."""
    import signal
    import socket
    import subprocess
    import time

    # Pick an ephemeral port so the test is deterministic and never skips.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    cfg_file = tmp_path / "ephemeral.yaml"
    cfg_file.write_text(f"api:\n  enabled: true\n  port: {port}\n")

    proc = subprocess.Popen(
        [
            str(REPO_ROOT / ".venv" / "bin" / "python"),
            "-m",
            "argusprowl",
            "start",
            "--config",
            str(cfg_file),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(REPO_ROOT),
    )

    def _wait_for_port(timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.connect(("127.0.0.1", port))
                    return True
                except OSError:
                    time.sleep(0.1)
        return False

    try:
        assert _wait_for_port(), "Server never became ready"
        assert proc.poll() is None, "Process exited before we could verify"

        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5.0)

        assert proc.returncode == 0, f"Process exited with code {proc.returncode}"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))  # must immediately rebind

    finally:
        if proc.poll() is None:
            proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5.0)
