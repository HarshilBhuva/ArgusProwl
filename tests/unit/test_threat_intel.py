"""Unit tests for Threat Intelligence Provider (Phase 4.6B)."""

import pytest

from argusprowl.intelligence.threat_intel import InMemoryThreatIntelProvider
from argusprowl.models.context import ThreatIntelReputation, ThreatIntelVerdict


def test_known_malicious_ip() -> None:
    """Verify known malicious IP returns MALICIOUS verdict and attributes."""
    rep = ThreatIntelReputation(
        indicator="203.0.113.50",
        verdict=ThreatIntelVerdict.MALICIOUS,
        confidence=0.95,
        categories=("c2", "botnet"),
        source="local-test-feed",
    )
    provider = InMemoryThreatIntelProvider(ip_reputations={"203.0.113.50": rep})

    result = provider.lookup_ip("203.0.113.50")
    assert result.verdict == ThreatIntelVerdict.MALICIOUS
    assert result.confidence == 0.95
    assert result.categories == ("c2", "botnet")
    assert result.source == "local-test-feed"


def test_known_benign_domain() -> None:
    """Verify known benign domain returns BENIGN verdict."""
    rep = ThreatIntelReputation(
        indicator="updates.microsoft.com",
        verdict=ThreatIntelVerdict.BENIGN,
        confidence=0.9,
        categories=("cdn", "os_updates"),
        source="allowlist",
    )
    provider = InMemoryThreatIntelProvider(domain_reputations={"updates.microsoft.com": rep})

    result = provider.lookup_domain("updates.microsoft.com")
    assert result.verdict == ThreatIntelVerdict.BENIGN
    assert result.confidence == 0.9
    assert result.categories == ("cdn", "os_updates")


def test_suspicious_verdict() -> None:
    """Verify SUSPICIOUS verdict lookup."""
    rep = ThreatIntelReputation(
        indicator="198.51.100.20",
        verdict=ThreatIntelVerdict.SUSPICIOUS,
        confidence=0.6,
        categories=("scanner",),
        source="feed_b",
    )
    provider = InMemoryThreatIntelProvider(ip_reputations={"198.51.100.20": rep})

    result = provider.lookup_ip("198.51.100.20")
    assert result.verdict == ThreatIntelVerdict.SUSPICIOUS
    assert result.confidence == 0.6


def test_unknown_indicator() -> None:
    """Verify missing indicators return UNKNOWN verdict without error."""
    provider = InMemoryThreatIntelProvider()

    res_ip = provider.lookup_ip("192.0.2.100")
    assert res_ip.verdict == ThreatIntelVerdict.UNKNOWN
    assert res_ip.confidence == 0.0

    res_dom = provider.lookup_domain("unknown.example.org")
    assert res_dom.verdict == ThreatIntelVerdict.UNKNOWN
    assert res_dom.confidence == 0.0


def test_case_and_whitespace_normalization() -> None:
    """Verify domain lookups normalize case, whitespace, and trailing dots."""
    rep = ThreatIntelReputation(
        indicator="bad-domain.com",
        verdict=ThreatIntelVerdict.MALICIOUS,
        confidence=0.8,
        categories=("phishing",),
        source="test",
    )
    provider = InMemoryThreatIntelProvider(domain_reputations={"BAD-DOMAIN.COM.": rep})

    res1 = provider.lookup_domain("bad-domain.com")
    assert res1.verdict == ThreatIntelVerdict.MALICIOUS

    res2 = provider.lookup_domain("  BAD-DOMAIN.COM.  ")
    assert res2.verdict == ThreatIntelVerdict.MALICIOUS


def test_no_network_local_only() -> None:
    """Verify lookups are strictly local in-memory lookups."""
    provider = InMemoryThreatIntelProvider()
    # Invalid IP string or unreachable address should return UNKNOWN gracefully without network timeout or error
    res = provider.lookup_ip("invalid-ip-string")
    assert res.verdict == ThreatIntelVerdict.UNKNOWN
    assert res.confidence == 0.0


def test_immutability_of_returned_reputation() -> None:
    """Verify returned reputation instances are frozen immutable objects."""
    rep = ThreatIntelReputation(
        indicator="10.0.0.1",
        verdict=ThreatIntelVerdict.BENIGN,
        confidence=1.0,
    )
    provider = InMemoryThreatIntelProvider(ip_reputations={"10.0.0.1": rep})
    result = provider.lookup_ip("10.0.0.1")

    with pytest.raises(AttributeError):
        result.verdict = ThreatIntelVerdict.MALICIOUS  # type: ignore[misc]


def test_add_reputation_validation() -> None:
    """Verify validation when adding IP or domain reputations."""
    provider = InMemoryThreatIntelProvider()

    rep = ThreatIntelReputation(indicator="1.1.1.1", verdict=ThreatIntelVerdict.BENIGN)

    with pytest.raises(ValueError, match="Invalid IP address format"):
        provider.add_ip_reputation("not-an-ip", rep)

    with pytest.raises(ValueError, match="reputation must be a ThreatIntelReputation"):
        provider.add_domain_reputation("example.com", "not-a-reputation")  # type: ignore[arg-type]
