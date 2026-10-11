"""Tests for utility helpers."""

from pathlib import Path

from argusprowl.utils.file_helpers import atomic_write, read_text_file, write_text_file
from argusprowl.utils.json_helpers import json_dumps, json_loads
from argusprowl.utils.path_helpers import is_safe_path
from argusprowl.utils.time_utils import elapsed_seconds, iso_format, parse_iso, utc_now
from argusprowl.utils.validation_helpers import (
    is_non_empty_string,
    is_valid_hostname,
    is_valid_ipv4,
    is_valid_port,
)


def test_file_helpers(temp_dir: Path):
    target = temp_dir / "sub" / "test.txt"
    write_text_file(target, "Hello World")
    assert target.exists()
    assert read_text_file(target) == "Hello World"

    atomic_write(target, "Updated Content")
    assert read_text_file(target) == "Updated Content"


def test_time_utils():
    now = utc_now()
    iso_str = iso_format(now)
    assert "Z" in iso_str
    parsed = parse_iso(iso_str)
    assert parsed.year == now.year
    assert elapsed_seconds(now) >= 0.0


def test_json_helpers():
    data = {"now": utc_now(), "path": Path("/tmp")}
    serialized = json_dumps(data)
    deserialized = json_loads(serialized)
    assert "now" in deserialized
    assert deserialized["path"] == "/tmp"


def test_validation_helpers():
    assert is_valid_ipv4("192.168.1.1") is True
    assert is_valid_ipv4("999.1.1.1") is False

    assert is_valid_port(8080) is True
    assert is_valid_port(70000) is False

    assert is_valid_hostname("argusprowl.local") is True
    assert is_non_empty_string("  valid  ") is True
    assert is_non_empty_string("   ") is False


def test_path_helpers(temp_dir: Path):
    safe_target = temp_dir / "nested" / "file.txt"
    assert is_safe_path(safe_target, temp_dir) is True
    unsafe_target = temp_dir / ".." / "outside.txt"
    assert is_safe_path(unsafe_target, temp_dir) is False
