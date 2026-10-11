"""Threat intelligence provider interfaces and in-memory implementations (Phase 4.6B).

Provides bounded, offline lookups for IP addresses and domain reputations.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Protocol

from argusprowl.models.context import ThreatIntelReputation, ThreatIntelVerdict


class ThreatIntelProvider(Protocol):
    """Protocol defining threat intelligence lookup capabilities."""

    def lookup_ip(self, ip: str) -> ThreatIntelReputation:
        """Lookup threat intelligence reputation for an IP address.

        Args:
            ip: IP address string.

        Returns:
            ThreatIntelReputation instance.
        """
        ...

    def lookup_domain(self, domain: str) -> ThreatIntelReputation:
        """Lookup threat intelligence reputation for a domain name.

        Args:
            domain: Domain name string.

        Returns:
            ThreatIntelReputation instance.
        """
        ...


class InMemoryThreatIntelProvider:
    """In-memory, offline-first threat intelligence provider.

    Performs fast local lookups against explicitly supplied reputation records.
    Returns UNKNOWN reputation when an indicator is not found. Does NOT perform
    any network calls.
    """

    def __init__(
        self,
        ip_reputations: dict[str, ThreatIntelReputation] | None = None,
        domain_reputations: dict[str, ThreatIntelReputation] | None = None,
    ) -> None:
        """Initialize in-memory threat intel provider.

        Args:
            ip_reputations: Dictionary mapping IP strings to ThreatIntelReputation.
            domain_reputations: Dictionary mapping domain strings to ThreatIntelReputation.
        """
        self._ip_map: dict[str, ThreatIntelReputation] = {}
        self._domain_map: dict[str, ThreatIntelReputation] = {}

        if ip_reputations:
            for ip, rep in ip_reputations.items():
                self.add_ip_reputation(ip, rep)
        if domain_reputations:
            for domain, rep in domain_reputations.items():
                self.add_domain_reputation(domain, rep)

    def _normalize_ip(self, ip: str) -> str:
        """Validate and normalize an IP address string."""
        if not isinstance(ip, str) or not ip.strip():
            raise ValueError("IP address must be a non-empty string.")
        cleaned = ip.strip()
        try:
            return str(ip_address(cleaned))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address format '{ip}'.") from exc

    def _normalize_domain(self, domain: str) -> str:
        """Normalize a domain string (lowercased, stripped of whitespace and trailing dots)."""
        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("Domain must be a non-empty string.")
        return domain.strip().lower().rstrip(".")

    def add_ip_reputation(self, ip: str, reputation: ThreatIntelReputation) -> None:
        """Add or update an IP reputation record."""
        if not isinstance(reputation, ThreatIntelReputation):
            raise ValueError("reputation must be a ThreatIntelReputation instance.")
        norm_ip = self._normalize_ip(ip)
        self._ip_map[norm_ip] = reputation

    def add_domain_reputation(self, domain: str, reputation: ThreatIntelReputation) -> None:
        """Add or update a domain reputation record."""
        if not isinstance(reputation, ThreatIntelReputation):
            raise ValueError("reputation must be a ThreatIntelReputation instance.")
        norm_domain = self._normalize_domain(domain)
        self._domain_map[norm_domain] = reputation

    def lookup_ip(self, ip: str) -> ThreatIntelReputation:
        """Lookup reputation for an IP address.

        Returns UNKNOWN verdict if indicator is not found or invalid format.
        """
        try:
            norm_ip = self._normalize_ip(ip)
        except ValueError:
            return ThreatIntelReputation(
                indicator=str(ip),
                verdict=ThreatIntelVerdict.UNKNOWN,
                confidence=0.0,
                categories=(),
                source="in_memory_provider",
            )

        if norm_ip in self._ip_map:
            return self._ip_map[norm_ip]

        return ThreatIntelReputation(
            indicator=norm_ip,
            verdict=ThreatIntelVerdict.UNKNOWN,
            confidence=0.0,
            categories=(),
            source="in_memory_provider",
        )

    def lookup_domain(self, domain: str) -> ThreatIntelReputation:
        """Lookup reputation for a domain name.

        Returns UNKNOWN verdict if indicator is not found or invalid format.
        """
        try:
            norm_domain = self._normalize_domain(domain)
        except ValueError:
            return ThreatIntelReputation(
                indicator=str(domain),
                verdict=ThreatIntelVerdict.UNKNOWN,
                confidence=0.0,
                categories=(),
                source="in_memory_provider",
            )

        if norm_domain in self._domain_map:
            return self._domain_map[norm_domain]

        return ThreatIntelReputation(
            indicator=norm_domain,
            verdict=ThreatIntelVerdict.UNKNOWN,
            confidence=0.0,
            categories=(),
            source="in_memory_provider",
        )
