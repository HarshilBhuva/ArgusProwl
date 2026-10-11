"""Entity-centric alert correlation service.

Provides deterministic grouping of alerts by entity dimensions
(host, process, destination) for incident aggregation.
"""

from __future__ import annotations

from collections.abc import Iterable

from argusprowl.models.alert import Alert


class EntityCorrelationService:
    """Deterministic entity correlation service.

    Groups alerts by entity dimensions in a stable, reproducible manner.
    The grouping key precedence is:
    1. host + process_name
    2. host + dst_ip
    3. host alone
    4. dst_ip alone
    5. stable fallback for alerts without entity context
    """

    def group_alerts_by_entity(
        self,
        alerts: Iterable[Alert],
    ) -> dict[str, list[Alert]]:
        """Group alerts by entity key.

        Args:
            alerts: Iterable of alerts to group.

        Returns:
            Dictionary mapping entity key to list of alerts.
        """
        groups: dict[str, list[Alert]] = {}
        for alert in alerts:
            key = self._compute_entity_key(alert)
            if key not in groups:
                groups[key] = []
            groups[key].append(alert)
        # Sort alerts within each group by alert_id for determinism
        for key in groups:
            groups[key].sort(key=lambda a: str(a.alert_id))
        return groups

    def compute_entity_key(self, alert: Alert) -> str:
        """Compute deterministic entity key from alert.

        This is the public canonical entity-key algorithm used by both
        incident correlation and queue entity queries. It must remain the
        single source of truth for entity identity.

        Precedence:
        1. host + process_name
        2. host + dst_ip
        3. host alone
        4. dst_ip alone
        5. stable fallback

        Args:
            alert: The alert to compute the entity key for.

        Returns:
            Deterministic entity key string.
        """
        return self._compute_entity_key(alert)

    @staticmethod
    def _compute_entity_key(alert: Alert) -> str:
        """Compute deterministic entity key from alert.

        Precedence:
        1. host + process_name
        2. host + dst_ip
        3. host alone
        4. dst_ip alone
        5. stable fallback
        """
        entity_context = alert.entity_context or {}

        host = entity_context.get("host")
        process_name = entity_context.get("process_name")
        dst_ip = entity_context.get("dst_ip")

        # Priority 1: host + process
        if host and process_name:
            return f"{host}:{process_name}"

        # Priority 2: host + destination
        if host and dst_ip:
            return f"{host}:{dst_ip}"

        # Priority 3: host alone
        if host:
            return f"{host}:*"

        # Priority 4: destination alone
        if dst_ip:
            return f"*:{dst_ip}"

        # Priority 5: stable fallback
        return f"unknown:{alert.alert_id}"
