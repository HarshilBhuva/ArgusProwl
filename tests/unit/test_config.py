"""Tests for configuration subsystem."""

from pathlib import Path

import pytest

from argusprowl.config.config_loader import ConfigLoader
from argusprowl.config.config_manager import ConfigManager
from argusprowl.config.config_validator import ConfigValidator
from argusprowl.exceptions.exceptions import ValidationError


def test_config_loader_defaults():
    loader = ConfigLoader()
    defaults = loader.get_default_config()
    assert defaults["app_name"] == "argusprowl"
    assert defaults["logging"]["level"] == "INFO"


def test_config_loader_env_overrides(monkeypatch):
    monkeypatch.setenv("TH_APP_NAME", "Custom argusprowl")
    monkeypatch.setenv("TH_DEBUG", "true")
    monkeypatch.setenv("TH_LOGGING__LEVEL", "DEBUG")

    loader = ConfigLoader()
    config = loader.load_config()

    assert config["app_name"] == "Custom argusprowl"
    assert config["debug"] is True
    assert config["logging"]["level"] == "DEBUG"


def test_config_validator_invalid_level():
    validator = ConfigValidator()
    invalid_cfg = {
        "app_name": "Test",
        "debug": False,
        "environment": "test",
        "logging": {"level": "INVALID_LEVEL"},
    }
    with pytest.raises(ValidationError, match="Invalid log level"):
        validator.validate(invalid_cfg)


def test_config_manager_singleton(temp_dir: Path):
    yaml_content = "app_name: 'YAML App'\ndebug: true\n"
    yaml_file = temp_dir / "test_config.yaml"
    yaml_file.write_text(yaml_content)

    cm = ConfigManager.get_instance()
    cfg = cm.load(yaml_file)

    assert cfg.app_name == "YAML App"
    assert cfg.debug is True
    assert cm.is_loaded is True
