"""Tests for logging subsystem."""

import logging
from pathlib import Path

from argusprowl.logging.formatters import ColoredConsoleFormatter, JsonFormatter
from argusprowl.logging.logger_factory import LoggerFactory
from argusprowl.models.configuration import LoggingConfig


def test_colored_console_formatter():
    formatter = ColoredConsoleFormatter(fmt="%(levelname)s - %(message)s")
    record = logging.LogRecord("test", logging.INFO, "path", 10, "Test message", (), None)
    output = formatter.format(record)
    assert "INFO" in output
    assert "Test message" in output


def test_json_formatter():
    formatter = JsonFormatter()
    record = logging.LogRecord("test", logging.ERROR, "path", 10, "Error msg", (), None)
    output = formatter.format(record)
    assert '"level": "ERROR"' in output
    assert '"message": "Error msg"' in output


def test_logger_factory(temp_dir: Path):
    log_file = temp_dir / "test.log"
    cfg = LoggingConfig(log_file=str(log_file), console_enabled=False, file_enabled=True)
    LoggerFactory.setup_logging(cfg)

    logger = LoggerFactory.get_logger("test_module")
    logger.info("Test log line")

    assert log_file.exists()
    content = log_file.read_text()
    assert "Test log line" in content
