"""Configuration validation for PostgreSQL storage."""

import pytest

from argusprowl.config.config_loader import ConfigLoader
from argusprowl.config.config_manager import ConfigManager
from argusprowl.config.config_validator import ConfigValidator
from argusprowl.exceptions.exceptions import ValidationError


def _postgres_config() -> dict:
    config = ConfigLoader().get_default_config()
    config["storage"].update(
        backend="postgresql",
        connection_string="postgresql://argusprowl:secret@localhost:5432/argusprowl",
    )
    return config


def test_postgresql_storage_configuration_is_accepted() -> None:
    ConfigValidator().validate(_postgres_config())


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("connection_string", ""),
        ("pool_min_size", 0),
        ("pool_min_size", True),
        ("pool_max_size", 0),
        ("pool_max_size", 0.5),
        ("pool_timeout_seconds", 0),
        ("connect_timeout_seconds", -1),
    ],
)
def test_invalid_postgresql_storage_configuration_is_rejected(key, value) -> None:
    config = _postgres_config()
    config["storage"][key] = value
    with pytest.raises(ValidationError, match=r"storage|PostgreSQL"):
        ConfigValidator().validate(config)


def test_database_url_environment_override(monkeypatch, tmp_path) -> None:
    config_file = tmp_path / "postgres.yaml"
    config_file.write_text(
        "storage:\n"
        "  backend: postgresql\n"
        "  connection_string: postgresql://yaml:secret@localhost/db\n"
    )
    monkeypatch.setenv(
        "ARGUSPROWL_DATABASE_URL",
        "postgresql://environment:secret@localhost/db",
    )

    config = ConfigManager().load(config_file)

    assert config.storage.connection_string == (
        "postgresql://environment:secret@localhost/db"
    )
