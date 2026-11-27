"""Tests for the restic off-host backup runner."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "argusprowl-backup-restic.sh"


def _runner_environment(tmp_path: Path, *, fail_on: str = "") -> dict[str, str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    command_log = tmp_path / "commands.log"
    python_runner = fake_bin / "argusprowl-python"
    python_runner.write_text(
        "#!/usr/bin/env bash\n"
        "if [[ \"$1\" == \"-c\" ]]; then echo 0.1.0; exit 0; fi\n"
        "if [[ \"$1\" == \"-m\" ]]; then "
        "printf 'app %s\\n' \"$*\" >> \"$COMMAND_LOG\"; shift 2; "
        "while (($#)); do if [[ \"$1\" == \"--output-dir\" ]]; then mkdir -p \"$2\"; break; fi; shift; done; exit 0; fi\n"
        "printf 'app %s\\n' \"$*\" >> \"$COMMAND_LOG\"\n"
        "exit 0\n",
        encoding="utf-8",
    )
    restic = fake_bin / "restic"
    restic.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'restic %s\\n' \"$*\" >> \"$COMMAND_LOG\"\n"
        "if [[ \"${FAIL_ON:-}\" == \"$1\" ]]; then exit 23; fi\n"
        "if [[ \"$1\" == backup ]]; then "
        "echo '{\"message_type\":\"summary\",\"snapshot_id\":\"snapshot-123\"}'; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    python_runner.chmod(0o755)
    restic.chmod(0o755)
    config = tmp_path / "config.yaml"
    config.write_text("storage: {backend: sqlite}\n", encoding="utf-8")
    password = tmp_path / "restic-password"
    password.write_text("test-only-secret\n", encoding="utf-8")
    backup_root = tmp_path / "backups"
    backup_root.mkdir()
    for stamp in ("20200101T000000Z", "20200102T000000Z", "20200103T000000Z"):
        generation = backup_root / f"argusprowl-{stamp}"
        generation.mkdir()
        (generation / "backup-set.json").write_text("{}", encoding="utf-8")
    return {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "COMMAND_LOG": str(command_log),
        "ARGUSPROWL_PYTHON": str(python_runner),
        "ARGUSPROWL_CONFIG": str(config),
        "ARGUSPROWL_BACKUP_ROOT": str(backup_root),
        "RESTIC_CACHE_DIR": str(tmp_path / "restic-cache"),
        "RESTIC_REPOSITORY": "s3:https://s3.example.invalid/argusprowl/test",
        "RESTIC_PASSWORD_FILE": str(password),
        "RESTIC_HOST": "argusprowl-test-host",
        "RESTIC_CHECK_DATA_PERCENT": "5",
        "ARGUSPROWL_LOCAL_KEEP": "2",
        "FAIL_ON": fail_on,
    }


def test_restic_runner_verifies_snapshot_before_retention_and_records_success(tmp_path):
    env = _runner_environment(tmp_path)
    result = subprocess.run(
        ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8").splitlines()
    assert any("backup set-create" in item for item in commands)
    assert any("backup set-verify" in item for item in commands)
    backup_command = next(item for item in commands if item.startswith("restic backup"))
    assert "--host argusprowl-test-host" in backup_command
    check_index = next(i for i, item in enumerate(commands) if item.startswith("restic check"))
    ls_index = next(i for i, item in enumerate(commands) if item.startswith("restic ls snapshot-123"))
    forget_index = next(i for i, item in enumerate(commands) if item.startswith("restic forget"))
    assert check_index < ls_index < forget_index
    assert "--group-by host" in commands[forget_index]
    status = json.loads((tmp_path / "backups" / "backup-status.json").read_text())
    assert status["state"] == "success"
    assert status["last_snapshot_id"] == "snapshot-123"
    assert status["last_success_at"]
    assert Path(status["last_generation"]).is_dir()
    local_sets = sorted(
        path.name for path in (tmp_path / "backups").glob("argusprowl-*") if path.is_dir()
    )
    assert len(local_sets) == 2
    assert Path(status["last_generation"]).name in local_sets


def test_restic_runner_does_not_prune_after_repository_verification_failure(tmp_path):
    env = _runner_environment(tmp_path, fail_on="check")
    result = subprocess.run(
        ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, check=False
    )

    assert result.returncode == 23
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8").splitlines()
    assert not any(item.startswith("restic forget") for item in commands)
    assert len(list((tmp_path / "backups").glob("argusprowl-*"))) == 4
    status = json.loads((tmp_path / "backups" / "backup-status.json").read_text())
    assert status["state"] == "failed"
    assert status["last_failure_at"]
    assert "status 23" in status["last_error"]


def test_restic_runner_rejects_password_inside_backup_root(tmp_path):
    env = _runner_environment(tmp_path)
    backup_root = Path(env["ARGUSPROWL_BACKUP_ROOT"])
    backup_root.mkdir(exist_ok=True)
    password = backup_root / "password"
    password.write_text("bad-placement")
    env["RESTIC_PASSWORD_FILE"] = str(password)

    result = subprocess.run(
        ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, check=False
    )
    assert result.returncode != 0
    assert "outside the backup directory" in result.stderr
    status = json.loads((backup_root / "backup-status.json").read_text())
    assert status["state"] == "failed"


def test_restic_runner_has_valid_bash_syntax():
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
