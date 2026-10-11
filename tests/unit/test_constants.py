"""Tests for constants module."""

import pytest

from argusprowl.constants.exit_codes import ExitCode
from argusprowl.constants.paths import ProjectPath
from argusprowl.constants.severity import Severity


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH < Severity.CRITICAL


def test_severity_from_string():
    assert Severity.from_string("high") == Severity.HIGH
    assert Severity.from_string("CRITICAL") == Severity.CRITICAL
    with pytest.raises(ValueError, match="Unknown severity"):
        Severity.from_string("invalid_severity")


def test_project_paths():
    assert ProjectPath.ROOT.exists()
    assert ProjectPath.APP.exists()


def test_exit_codes():
    assert ExitCode.SUCCESS == 0
    assert ExitCode.CONFIG_ERROR == 2
