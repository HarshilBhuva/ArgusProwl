"""Focused tests for API startup lifecycle and dependency contract.

These tests cover:
- The project's declared runtime dependency contract contains the
  packages required by the API (verified against pyproject.toml,
  NOT against the current virtualenv).
- _run_api_server invokes Uvicorn with the actual FastAPI application
  instance (not an import string) and preserves host/port/log-level/
  access-log arguments.
- Uvicorn startup failure is surfaced and never reported as successful
  startup.
- A disabled API does not start and does not log startup success.
"""

import logging
import tomllib
from pathlib import Path
from threading import Event
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argusprowl.config.config_loader import ConfigLoader
from argusprowl.core import application as application_mod
from argusprowl.core.application import Application
from argusprowl.exceptions.exceptions import LifecycleError
from argusprowl.models.api_config import ApiConfig
from argusprowl.models.configuration import AppConfiguration


def _normalize_dependency_name(name: str) -> str:
    """Normalize a dependency declaration to its base package name.

    Handles PEP 508 version specifiers and optional extras, e.g.
    ``uvicorn[standard]>=0.30.0`` → ``uvicorn``.
    """
    # Strip extras (e.g. "[standard]")
    if "[" in name:
        name = name.split("[", 1)[0]
    # Strip version specifiers
    for sep in (">", "<", "=", "!", "~"):
        if sep in name:
            name = name.split(sep, 1)[0]
    return name.strip().lower()


def _project_runtime_dependencies() -> set[str]:
    """Read the project's declared runtime dependencies from pyproject.toml.

    Asserts the project's authoritative dependency contract, not the
    current state of the virtualenv.
    """
    pyproject = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as fh:
        data = tomllib.load(fh)
    return {_normalize_dependency_name(dep) for dep in data["project"]["dependencies"]}


# ---------------------------------------------------------------------------
# Dependency contract tests
# ---------------------------------------------------------------------------


def test_runtime_dependency_contract_includes_api_packages():
    """fastapi and uvicorn must be declared runtime dependencies.

    The API is enabled by default, so the packages required to run it
    must be part of the project's normal installation path.
    """
    deps = _project_runtime_dependencies()
    assert "fastapi" in deps, (
        "fastapi must be a declared runtime dependency (API enabled by default)"
    )
    assert "uvicorn" in deps, (
        "uvicorn must be a declared runtime dependency (API enabled by default)"
    )


def test_api_dependencies_are_not_dev_or_optional():
    """fastapi/uvicorn must not live behind optional/dev dependency groups."""
    pyproject = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as fh:
        data = tomllib.load(fh)
    optional = data.get("project", {}).get("optional-dependencies", {})
    for group, packages in optional.items():
        for package in packages:
            name = _normalize_dependency_name(package)
            assert name not in ("fastapi", "uvicorn"), (
                f"fastapi/uvicorn must not be in {group} dependency group"
            )


# ---------------------------------------------------------------------------
# Uvicorn invocation tests
# ---------------------------------------------------------------------------


def test_run_api_server_passes_app_instance():
    """_run_api_server must call uvicorn.run with the FastAPI app instance."""
    app_instance = Application()
    mock_fastapi_app = MagicMock()
    app_instance._api_server = mock_fastapi_app
    app_instance._api_startup_event = Event()

    mock_config = MagicMock()
    mock_config.load = MagicMock()
    mock_config.lifespan_class = MagicMock(return_value=MagicMock())
    mock_server = MagicMock()
    mock_server.started = False
    mock_server.should_exit = False

    def _fake_asyncio_run(coro):
        import asyncio

        asyncio.get_event_loop().run_until_complete(coro)

    with (
        patch("uvicorn.Config", return_value=mock_config) as mock_config_cls,
        patch("uvicorn.Server", return_value=mock_server) as mock_server_cls,
        patch("asyncio.run", _fake_asyncio_run),
    ):
        app_instance._run_api_server("127.0.0.1", 8080)
        mock_config_cls.assert_called_once_with(
            app=mock_fastapi_app,
            host="127.0.0.1",
            port=8080,
            log_level="warning",
            access_log=False,
        )
        mock_config.load.assert_called_once()
        mock_server_cls.assert_called_once_with(mock_config)
        mock_config.lifespan_class.assert_called_once_with(mock_config)


def test_run_api_server_preserves_host_port_logging_accesslog():
    """_run_api_server passes host/port/log-level/access-log to uvicorn.Config."""
    app_instance = Application()
    app_instance._api_server = MagicMock()
    app_instance._api_startup_event = Event()

    mock_config = MagicMock()
    mock_config.load = MagicMock()
    mock_config.lifespan_class = MagicMock(return_value=MagicMock())
    mock_server = MagicMock()
    mock_server.started = False
    mock_server.should_exit = False

    def _fake_asyncio_run(coro):
        import asyncio

        asyncio.get_event_loop().run_until_complete(coro)

    with (
        patch("uvicorn.Config", return_value=mock_config) as mock_config_cls,
        patch("uvicorn.Server", return_value=mock_server),
    ):
        app_instance._run_api_server("127.0.0.1", 8080)
        _, kwargs = mock_config_cls.call_args
        assert kwargs["host"] == "127.0.0.1"
        assert kwargs["port"] == 8080
        assert kwargs["log_level"] == "warning"
        assert kwargs["access_log"] is False


def test_run_api_server_records_error_without_reraise():
    """A uvicorn Config construction failure must be recorded and not re-raised."""
    app_instance = Application()
    app_instance._api_server = MagicMock()
    app_instance._api_startup_event = Event()

    with patch("uvicorn.Config", side_effect=RuntimeError("simulated config failure")):
        app_instance._run_api_server("127.0.0.1", 8080)

    assert isinstance(app_instance._api_startup_error, RuntimeError)
    assert "simulated config failure" in str(app_instance._api_startup_error)
    assert app_instance._api_startup_event.is_set()


# ---------------------------------------------------------------------------
# Startup failure tests (regression for "API started" logged despite failure)
# ---------------------------------------------------------------------------


def test_application_api_startup_failure_not_reported_as_success(temp_dir, caplog, recwarn):
    """A uvicorn startup failure must NOT be reported as successful startup."""
    cfg_file = temp_dir / "failed_api.yaml"
    cfg_file.write_text("api:\n  enabled: true\n")

    app_instance = Application(config_path=cfg_file)

    with (
        patch("asyncio.run", side_effect=RuntimeError("simulated uvicorn startup failure")),
        caplog.at_level(logging.INFO),
    ):
        with pytest.raises(LifecycleError):
            app_instance.startup()

        assert not any("API server started" in record.getMessage() for record in caplog.records), (
            "API start must not be logged on startup failure"
        )

        unhandled = [
            warning
            for warning in recwarn.list
            if "unhandled" in str(warning.message).lower()
            or "UnhandledThreadException" in getattr(warning.category, "__name__", "")
        ]
        assert unhandled == [], f"daemon thread leaked unhandled exceptions: {unhandled}"

        app_instance.shutdown()


def test_application_api_startup_timeout_not_reported_as_success(temp_dir, caplog):
    """A startup wait timeout must never produce a false 'API server started' log.

    If the ready event is not set before the wait times out, startup must fail closed.
    """
    cfg_file = temp_dir / "timeout_api.yaml"
    cfg_file.write_text("api:\n  enabled: true\n")

    app_instance = Application(config_path=cfg_file)
    app_instance._config = app_instance._config_manager.load(cfg_file)

    mock_event = MagicMock()
    mock_event.wait.return_value = False

    def _fake_asyncio_run(coro):
        import asyncio

        asyncio.get_event_loop().run_until_complete(coro)

    with (
        patch("argusprowl.api.app.create_api_app", return_value=MagicMock()),
        patch("asyncio.run", side_effect=_fake_asyncio_run),
        patch.object(application_mod, "Event", return_value=mock_event),
        caplog.at_level(logging.INFO),
        pytest.raises(LifecycleError) as exc_info,
    ):
        app_instance._start_api_server()

    message = str(exc_info.value).lower()
    assert "timeout" in message or "timed out" in message
    assert not any("API server started" in record.getMessage() for record in caplog.records), (
        "API start must not be logged when readiness times out"
    )


def test_application_logs_api_started_when_uvicorn_succeeds(temp_dir, caplog):
    """The 'API server started' log is emitted once uvicorn has been launched."""
    cfg_file = temp_dir / "success_api.yaml"
    cfg_file.write_text("api:\n  enabled: true\n")

    app_instance = Application(config_path=cfg_file)
    app_instance._config = app_instance._config_manager.load(cfg_file)

    mock_config = MagicMock()
    mock_config.load = MagicMock()
    mock_config.lifespan_class = MagicMock(return_value=MagicMock())
    mock_server = MagicMock()
    mock_server.started = True
    mock_server.should_exit = False
    mock_server.startup = AsyncMock()
    mock_server.main_loop = AsyncMock()
    mock_server.shutdown = AsyncMock()

    def _fake_asyncio_run(coro):
        import asyncio

        asyncio.get_event_loop().run_until_complete(coro)

    with (
        patch("uvicorn.Config", return_value=mock_config),
        patch("uvicorn.Server", return_value=mock_server),
        caplog.at_level(logging.INFO),
    ):
        with patch("argusprowl.api.app.create_api_app") as mock_create:
            mock_create.return_value = MagicMock()
            app_instance.startup()
            app_instance.shutdown()

        assert any("API server started" in record.getMessage() for record in caplog.records), (
            "Expected 'API server started' to be logged on success"
        )


# ---------------------------------------------------------------------------
# Disabled API tests
# ---------------------------------------------------------------------------


def test_application_does_not_start_api_if_disabled(temp_dir):
    """When api.enabled is False, uvicorn.run must never be called."""
    cfg_file = temp_dir / "disabled_api.yaml"
    cfg_file.write_text("api:\n  enabled: false\n")

    app_instance = Application(config_path=cfg_file)

    with patch("uvicorn.run") as mock_uvicorn:
        app_instance.startup()
        mock_uvicorn.assert_not_called()
        app_instance.shutdown()


def test_application_does_not_log_api_started_when_disabled(temp_dir):
    """API startup success log must not appear when API is disabled."""
    cfg_file = temp_dir / "disabled_api.yaml"
    cfg_file.write_text("api:\n  enabled: false\n")

    app_instance = Application(config_path=cfg_file)

    with (
        patch("uvicorn.run") as mock_uvicorn,
        patch.object(app_instance._logger, "info") as mock_info,
    ):
        app_instance.startup()
        mock_uvicorn.assert_not_called()
        for call in mock_info.call_args_list:
            for arg in call.args:
                if isinstance(arg, str):
                    assert "API server started" not in arg
        app_instance.shutdown()


def test_application_api_startup_event_is_none_when_disabled(temp_dir):
    """When API is disabled, no startup event/thread should be created."""
    cfg_file = temp_dir / "disabled_api.yaml"
    cfg_file.write_text("api:\n  enabled: false\n")

    app_instance = Application(config_path=cfg_file)

    with patch("uvicorn.run"):
        app_instance.startup()
        assert app_instance._api_thread is None
        assert app_instance._api_startup_event is None
        assert app_instance._api_startup_error is None
        app_instance.shutdown()


# ---------------------------------------------------------------------------
# Default configuration tests
# ---------------------------------------------------------------------------


def test_api_enabled_by_default():
    """Verify API is enabled by default in ApiConfig."""
    cfg = ApiConfig()
    assert cfg.enabled is True


def test_config_loader_defaults_api_enabled(temp_dir):
    """ConfigLoader.get_default_config() has api.enabled=True."""
    loader = ConfigLoader()
    default_cfg = loader.get_default_config()
    assert default_cfg["api"]["enabled"] is True


def test_application_config_api_enabled_default_is_true():
    """AppConfiguration's default ApiConfig has enabled=True."""
    cfg = AppConfiguration()
    assert cfg.api.enabled is True
