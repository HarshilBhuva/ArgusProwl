"""Tests for HealthService and Application."""

import socket
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))
from argusprowl.config.config_manager import ConfigManager
from argusprowl.core.application import Application
from argusprowl.models.system_status import HealthStatus
from argusprowl.services.health_service import HealthService


def _free_port() -> int:
    """Return a randomly available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_health_service_unloaded():
    hs = HealthService()
    status = hs.check_health()
    assert status.status == HealthStatus.UNHEALTHY
    assert any(c.name == "config" and c.status == HealthStatus.UNHEALTHY for c in status.components)


def test_health_service_loaded(temp_dir: Path):
    cfg_file = temp_dir / "test_config.yaml"
    cfg_file.write_text("app_name: 'Test App'\n")
    ConfigManager.get_instance().load(cfg_file)

    hs = HealthService()
    status = hs.check_health()
    assert status.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)
    assert len(status.components) >= 4


def test_application_lifecycle(temp_dir: Path):
    cfg_file = temp_dir / "app_config.yaml"
    cfg_file.write_text(f"app_name: 'Test App'\napi:\n  enabled: true\n  port: {_free_port()}\n")

    app_instance = Application(config_path=cfg_file)
    assert app_instance.is_running is False

    app_instance.startup()
    assert app_instance.is_running is True
    assert app_instance.config.app_name == "Test App"

    health = app_instance.health_check()
    assert health.status == HealthStatus.HEALTHY

    app_instance.shutdown()
    assert app_instance.is_running is False
