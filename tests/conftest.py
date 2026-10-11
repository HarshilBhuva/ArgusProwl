"""Pytest shared fixtures and setup/teardown hooks."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from argusprowl.config.config_manager import ConfigManager
from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.logging.logger_factory import LoggerFactory


@pytest.fixture(autouse=True)
def reset_singletons() -> Generator[None]:
    """Reset all singleton instances before and after every test."""
    ConfigManager.reset_instance()
    ServiceContainer.reset_instance()
    LoggerFactory.reset()
    yield
    ConfigManager.reset_instance()
    ServiceContainer.reset_instance()
    LoggerFactory.reset()


@pytest.fixture
def temp_dir() -> Generator[Path]:
    """Provide a temporary directory for file-based test isolation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)
