"""Security regression tests for remotely reachable API listeners."""

from __future__ import annotations

import copy

import pytest

from argusprowl.config.config_loader import ConfigLoader
from argusprowl.config.config_validator import ConfigValidator
from argusprowl.exceptions.exceptions import ValidationError


def _config() -> dict:
    return copy.deepcopy(ConfigLoader().get_default_config())


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.10", "::", "api.example.test"])
def test_enabled_remote_api_requires_authentication(host: str) -> None:
    config = _config()
    config["api"]["host"] = host
    config["api"]["auth_enabled"] = False

    with pytest.raises(ValidationError, match="auth_enabled must be true"):
        ConfigValidator().validate(config)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_loopback_api_can_remain_unauthenticated(host: str) -> None:
    config = _config()
    config["api"]["host"] = host
    config["api"]["auth_enabled"] = False

    ConfigValidator().validate(config)


def test_remote_api_requires_a_credential_even_when_auth_is_enabled() -> None:
    config = _config()
    config["api"]["host"] = "0.0.0.0"
    config["api"]["auth_enabled"] = True

    with pytest.raises(ValidationError, match="requires at least one credential"):
        ConfigValidator().validate(config)


def test_remote_api_accepts_strong_legacy_key() -> None:
    config = _config()
    config["api"]["host"] = "0.0.0.0"
    config["api"]["auth_enabled"] = True
    config["api"]["api_key"] = "legacy-api-key-that-is-at-least-32-characters"

    ConfigValidator().validate(config)


def test_remote_api_rejects_weak_legacy_key() -> None:
    config = _config()
    config["api"]["host"] = "0.0.0.0"
    config["api"]["auth_enabled"] = True
    config["api"]["api_key"] = "short"

    with pytest.raises(ValidationError, match="at least 32 ASCII characters"):
        ConfigValidator().validate(config)


def test_remote_api_accepts_named_role_credentials() -> None:
    config = _config()
    config["api"]["host"] = "0.0.0.0"
    config["api"]["auth_enabled"] = True
    config["api"]["api_keys"] = {
        "analyst": {
            "secret": "named-analyst-key-with-at-least-32-characters",
            "subject": "analyst-1",
            "role": "analyst",
        }
    }

    ConfigValidator().validate(config)


def test_remote_api_accepts_legacy_environment_key(monkeypatch) -> None:
    config = _config()
    config["api"]["host"] = "0.0.0.0"
    config["api"]["auth_enabled"] = True
    monkeypatch.setenv("ARGUSPROWL_API_KEY", "environment-key-with-at-least-32-characters")

    ConfigValidator().validate(config)


def test_disabled_remote_api_does_not_require_authentication() -> None:
    config = _config()
    config["api"]["enabled"] = False
    config["api"]["host"] = "0.0.0.0"
    config["api"]["auth_enabled"] = False

    ConfigValidator().validate(config)
