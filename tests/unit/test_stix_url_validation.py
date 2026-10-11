"""Security tests for remote STIX URL validation."""

from __future__ import annotations

import pytest

from argusprowl.__main__ import _validate_stix_url


@pytest.mark.parametrize(
    "url",
    [
        "https://raw.githubusercontent.com/mitre/cti/main/enterprise-attack.json",
        "https://example.org/stix/bundle.json?version=1",
    ],
)
def test_accepts_valid_https_stix_urls(url: str) -> None:
    assert _validate_stix_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://example.org/bundle.json",
        "file:///etc/passwd",
        "ftp://example.org/bundle.json",
        "//example.org/bundle.json",
        "https:///bundle.json",
        "https://user:password@example.org/bundle.json",
        "https://example.org:invalid/bundle.json",
    ],
)
def test_rejects_unsafe_or_malformed_stix_urls(url: str) -> None:
    with pytest.raises(ValueError):
        _validate_stix_url(url)
