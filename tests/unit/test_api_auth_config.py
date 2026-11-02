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


def test_api_auth_settings_can_be_overridden_by_deployment_environment(
    tmp_path, monkeypatch
) -> None:
    config_file = tmp_path / "app.yaml"
    config_file.write_text(
        "app_name: TestApp\napi:\n  auth_enabled: false\n", encoding="utf-8"
    )
    monkeypatch.setenv("TH_API__HOST", "0.0.0.0")
    monkeypatch.setenv("TH_API__PORT", "8181")
    monkeypatch.setenv("TH_API__AUTH_ENABLED", "true")
    monkeypatch.setenv("TH_API__AUTH_HEADER_NAME", "X-Deployment-Key")

    config = ConfigManager().load(config_file)

    assert config.api.host == "0.0.0.0"
    assert config.api.port == 8181
    assert config.api.auth_enabled is True
    assert config.api.auth_header_name == "X-Deployment-Key"


def test_named_api_keys_are_loaded_from_environment_json(tmp_path, monkeypatch) -> None:
    import json

    config_file = tmp_path / "app.yaml"
    config_file.write_text("app_name: TestApp\napi:\n  auth_enabled: true\n", encoding="utf-8")
    definitions = {
        "analyst-1": {
            "secret": "a-random-secret-value-longer-than-32-characters",
            "subject": "analyst@example.test",
            "role": "analyst",
        }
    }
    monkeypatch.setenv("ARGUSPROWL_API_KEYS", json.dumps(definitions))

    config = ConfigManager().load(config_file)

    assert config.api.api_keys == definitions
    assert config.api.audit_db_path == "data/audit.db"


def test_named_api_keys_reject_short_secrets_and_unknown_roles(tmp_path, monkeypatch) -> None:
    import json

    import pytest

    from argusprowl.exceptions.exceptions import ValidationError

    config_file = tmp_path / "app.yaml"
    config_file.write_text("app_name: TestApp\napi:\n  auth_enabled: true\n", encoding="utf-8")
    monkeypatch.setenv(
        "ARGUSPROWL_API_KEYS",
        json.dumps({
            "bad-key": {"secret": "too-short", "subject": "operator", "role": "superuser"}
        }),
    )

    with pytest.raises(ValidationError):
        ConfigManager().load(config_file)


def test_empty_named_api_keys_environment_is_ignored(tmp_path, monkeypatch) -> None:
    config_file = tmp_path / "app.yaml"
    config_file.write_text("app_name: TestApp\napi:\n  auth_enabled: false\n", encoding="utf-8")
    monkeypatch.setenv("ARGUSPROWL_API_KEYS", "")

    config = ConfigManager().load(config_file)

    assert config.api.api_keys == {}
