"""Regression tests for API authentication configuration loading."""

from argusprowl.config.config_manager import ConfigManager


def test_api_auth_settings_are_loaded_from_yaml(tmp_path) -> None:
    config_file = tmp_path / "app.yaml"
    config_file.write_text(
        "app_name: TestApp\n"
        "api:\n"
        "  enabled: true\n"
        "  auth_enabled: true\n"
        "  auth_header_name: X-Custom-Argus-Key\n",
        encoding="utf-8",
    )

    config = ConfigManager().load(config_file)

    assert config.api.auth_enabled is True
    assert config.api.auth_header_name == "X-Custom-Argus-Key"


def test_api_auth_remains_disabled_when_explicitly_configured(tmp_path) -> None:
    config_file = tmp_path / "app.yaml"
    config_file.write_text(
        "app_name: TestApp\napi:\n  auth_enabled: false\n",
        encoding="utf-8",
    )

    config = ConfigManager().load(config_file)

    assert config.api.auth_enabled is False
