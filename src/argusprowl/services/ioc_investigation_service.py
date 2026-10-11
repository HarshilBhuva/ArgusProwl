"""IOC investigation service (Phase 7.6).

Read-only analyst investigation of IPs and domains against retained alert
evidence and offline threat intelligence. Does NOT mutate detection,
correlation, incidents, or persistence state.
"""

from __future__ import annotations

import logging
from ipaddress import ip_address
from typing import Any
from uuid import uuid4

from argusprowl.models.context import PrevalenceResult, ThreatIntelReputation
from argusprowl.models.ioc_investigation import (
    IocInvestigationResult,
    IocInvestigationStatus,
    IocObservation,
    IocTimelineItem,
    IocType,
    RelatedIoc,
)
from argusprowl.services.alert_search_service import AlertSearchService

logger = logging.getLogger(__name__)

_MAX_INDICATOR_LENGTH = 256
_MAX_INSPECTED_ALERTS = 200
_MAX_OBSERVATIONS = 100
_MAX_RELATED_IOCS = 50
_MAX_TIMELINE_ITEMS = 100
_IOC_FIELDS = frozenset({"src_ip", "dst_ip", "domain"})
_DEFAULT_OBSERVATION_NOTE = "first observed in retained alert evidence"


def _is_valid_domain(domain: str) -> bool:
    """Return True for a plausible DNS name.

    Rules are conservative: no wildcards, no slashes/colons (rejects URLs),
    at least one dot, ASCII-safe after normalization.
    """
    if not domain or len(domain) > 253:
        return False
    # Reject obviously non-domain inputs.
    if "/" in domain or ":" in domain or " " in domain:
        return False
    if "*" in domain or "?" in domain:
        return False
    # Must contain at least one dot for a domain (not bare IP).
    if "." not in domain:
        return False
    try:
        # ip_address will reject true domains; if it parses as an IP we reject.
        ip_address(domain)
        return False
    except ValueError:
        pass

    # Reject if it looks like an invalid IP (e.g., 192.168.1.256)
    # A domain must not consist of exactly 4 numeric octets.
    parts = domain.split(".")
    return not (len(parts) == 4 and all(part.isdigit() for part in parts))


def _normalize_indicator(indicator: str) -> tuple[str, IocType]:
    """Validate and classify an indicator into (normalized, ioc_type)."""
    indicator = indicator.strip()
    if not indicator:
        raise ValueError("Indicator must be a non-empty string.")
    if len(indicator) > _MAX_INDICATOR_LENGTH:
        raise ValueError(f"Indicator must be at most {_MAX_INDICATOR_LENGTH} characters.")

    # Try IP first.
    try:
        return str(ip_address(indicator)), IocType.IP
    except ValueError:
        pass

    # Then domain.
    norm_domain = indicator.lower().rstrip(".")
    if _is_valid_domain(norm_domain):
        return norm_domain, IocType.DOMAIN

    raise ValueError(f"Unsupported or invalid indicator type: {indicator!r}")


class IocInvestigationService:
    """IOC investigation against AlertSearchService + offline TI."""

    def __init__(
        self,
        alert_search_service: AlertSearchService,
        intelligence_service: Any,  # ContextualIntelligenceService
    ) -> None:
        self._search = alert_search_service
        self._intelligence = intelligence_service

    def investigate(self, indicator: str) -> IocInvestigationResult:
        """Investigate a single IP or domain indicator.

        Returns a bounded, read-only result. Observation provenance is retained
        alert evidence. No detection, correlation, or persistence is mutated.
        """
        norm_indicator, ioc_type = _normalize_indicator(indicator)

        # Threat intelligence lookup via the existing provider.
        if ioc_type == IocType.IP:
            reputation: ThreatIntelReputation = self._intelligence.threat_intel_provider.lookup_ip(
                norm_indicator
            )
        else:
            reputation = self._intelligence.threat_intel_provider.lookup_domain(norm_indicator)

        # Alert evidence scan via AlertSearchService.
        try:
            search_result = self._search.search(limit=_MAX_INSPECTED_ALERTS)
        except ValueError as exc:
            logger.warning("Alert search validation failed during IOC investigation: %s", exc)
            search_result = self._search.search(limit=1)

        alerts = search_result.alerts
        truncated = len(alerts) >= _MAX_INSPECTED_ALERTS

        observations: list[IocObservation] = []
        related_iocs_dict: dict[str, RelatedIoc] = {}
        alert_ids: set[str] = set()
        hosts: set[str] = set()
        rule_ids: set[str] = set()
        matched_timestamps: list[Any] = []
        # Track destination fields for prevalence attribution.
        destination_values: set[str] = set()

        for alert in alerts:
            ctx: dict[str, Any] | None = alert.entity_context
            if not isinstance(ctx, dict):
                continue

            matched = False
            for field_name in ("src_ip", "dst_ip", "domain"):
                raw = ctx.get(field_name)
                if raw is None or not isinstance(raw, str) or not raw.strip():
                    continue
                norm = raw.strip()
                if ioc_type == IocType.IP:
                    try:
                        norm = str(ip_address(norm))
                    except ValueError:
                        continue
                    if norm != norm_indicator:
                        continue
                else:
                    norm = norm.lower().rstrip(".")
                    if norm != norm_indicator:
                        continue

                matched = True
                ts = alert.created_at
                observations.append(
                    IocObservation(
                        alert_id=str(alert.alert_id),
                        timestamp=ts,
                        field=field_name,
                        value=norm,
                        host=ctx.get("host"),
                        rule_id=alert.metadata.get("rule_id")
                        if isinstance(alert.metadata, dict)
                        else None,
                        severity=alert.severity.name
                        if hasattr(alert.severity, "name")
                        else str(alert.severity),
                    )
                )
                alert_ids.add(str(alert.alert_id))
                if ctx.get("host"):
                    hosts.add(str(ctx["host"]))
                if isinstance(alert.metadata, dict) and alert.metadata.get("rule_id"):
                    rule_ids.add(str(alert.metadata["rule_id"]))
                matched_timestamps.append(ts)
                if field_name in ("dst_ip", "domain"):
                    destination_values.add(norm)

            if matched:
                for field_name in ("src_ip", "dst_ip", "domain"):
                    raw = ctx.get(field_name)
                    if raw is None or not isinstance(raw, str) or not raw.strip():
                        continue
                    other_norm = raw.strip()
                    if field_name == "domain":
                        other_norm = other_norm.lower().rstrip(".")
                        other_type = IocType.DOMAIN
                    else:
                        try:
                            other_norm = str(ip_address(other_norm))
                        except ValueError:
                            continue
                        other_type = IocType.IP

                    if other_norm == norm_indicator:
                        continue
                    key = f"{other_type.value}:{other_norm}:{alert.alert_id!s}"
                    if key not in related_iocs_dict:
                        related_iocs_dict[key] = RelatedIoc(
                            indicator=other_norm,
                            ioc_type=other_type,
                            field=field_name,
                            co_observed_in_alert_id=str(alert.alert_id),
                        )

        # Deduplicate and bound observations/timeline/related IOCs.
        observations = observations[:_MAX_OBSERVATIONS]
        related_iocs = tuple(related_iocs_dict.values())[:_MAX_RELATED_IOCS]

        first_observed = min(matched_timestamps) if matched_timestamps else None
        last_observed = max(matched_timestamps) if matched_timestamps else None

        # Build timeline: observations first (newest), then reputation context.
        timeline_items: list[IocTimelineItem] = []
        # Observation events.
        for obs in sorted(
            observations, key=lambda o: (o.timestamp, o.field, o.alert_id), reverse=True
        )[:_MAX_TIMELINE_ITEMS]:
            timeline_items.append(
                IocTimelineItem(
                    timeline_item_id=str(uuid4()),
                    timestamp=obs.timestamp.isoformat(),
                    item_type="OBSERVATION",
                    title=f"IOC observed as {obs.field}",
                    summary=f"Alert {obs.alert_id} referenced {obs.field}={obs.value} on {obs.timestamp.isoformat()}",
                    source_id=obs.alert_id,
                    metadata={
                        "field": obs.field,
                        "severity": obs.severity or "",
                        "host": obs.host or "",
                    },
                )
            )

        # Reputation context as static intelligence entry (no invented timestamp).
        timeline_items.append(
            IocTimelineItem(
                timeline_item_id=str(uuid4()),
                timestamp=None,
                item_type="INTELLIGENCE",
                title="Threat intelligence reputation",
                summary=(
                    f"{reputation.verdict.value} (confidence {reputation.confidence}) "
                    f"from {reputation.source}"
                ),
                source_id=None,
                metadata={
                    "verdict": reputation.verdict.value,
                    "confidence": str(reputation.confidence),
                    "categories": ",".join(reputation.categories) or "",
                    "source": reputation.source,
                },
            )
        )

        # Related IOC pivots as timeline items (no invented timestamp).
        for rel in related_iocs[: _MAX_TIMELINE_ITEMS - len(timeline_items)]:
            timeline_items.append(
                IocTimelineItem(
                    timeline_item_id=str(uuid4()),
                    timestamp=None,
                    item_type="RELATED_IOC",
                    title=f"Related IOC: {rel.indicator}",
                    summary=f"Co-observed as {rel.field} in alert {rel.co_observed_in_alert_id}",
                    source_id=rel.co_observed_in_alert_id,
                    metadata={"field": rel.field, "ioc_type": rel.ioc_type.value},
                )
            )

        # Already bounded above.
        timeline = tuple(timeline_items[:_MAX_TIMELINE_ITEMS])

        # Prevalence only for destination-attributable queries.
        prevalence: PrevalenceResult | None = None
        if ioc_type == IocType.IP and destination_values:
            for dst in destination_values:
                try:
                    prevalence = self._intelligence.prevalence_tracker.get_prevalence(dst_ip=dst)
                    break
                except Exception as exc:
                    logger.debug("Prevalence lookup skipped: %s", exc)
        elif ioc_type == IocType.DOMAIN and destination_values:
            for dom in destination_values:
                try:
                    prevalence = self._intelligence.prevalence_tracker.get_prevalence(domain=dom)
                    break
                except Exception as exc:
                    logger.debug("Prevalence lookup skipped: %s", exc)

        status = IocInvestigationStatus.AVAILABLE
        reason: str | None = None
        if search_result.status.value == "DEGRADED":
            status = IocInvestigationStatus.DEGRADED
            reason = search_result.reason

        return IocInvestigationResult(
            indicator=norm_indicator,
            ioc_type=ioc_type,
            reputation=reputation,
            observations=tuple(observations),
            first_observed=first_observed,
            last_observed=last_observed,
            associated_alert_ids=tuple(sorted(alert_ids)),
            associated_hosts=tuple(sorted(hosts)),
            associated_rule_ids=tuple(sorted(rule_ids)),
            related_iocs=related_iocs,
            timeline=timeline,
            prevalence=prevalence,
            status=status,
            reason=reason,
            truncated=truncated or len(observations) >= _MAX_OBSERVATIONS,
            inspected_alert_count=len(alerts),
            observation_note=_DEFAULT_OBSERVATION_NOTE,
        )
