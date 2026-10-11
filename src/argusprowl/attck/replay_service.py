"""ATT&CK replay service.

Provides deterministic replay semantics for ATT&CK-enriched alerts.

Two explicit replay modes:

1. Historical replay
   Reproduces the semantic ATT&CK context that was recorded with the
   original alert. Uses the ATT&CK version recorded in the alert's
   attck_observations. Does NOT silently substitute the current
   ATT&CK snapshot. Returns explicit degraded/unavailable indication
   when the required historical ATT&CK knowledge is unavailable.

2. Current-semantic replay
   Evaluates/re-enriches using the currently active ATT&CK knowledge
   snapshot. Explicitly identifies this as current-semantic replay.
   Records the active ATT&CK snapshot version used. Does not mutate
   the original stored alert.

Degraded/fallback behavior:
- Historical replay with unavailable version → explicit DEGRADED status
- Current-semantic replay with unavailable snapshot → explicit UNAVAILABLE status
- No silent fallback from historical to current semantics
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from argusprowl.attck.knowledge_service import AttckKnowledgeService, AttckKnowledgeStatus
from argusprowl.attck.mapping_registry import AttckMappingRegistry, MappingType

if TYPE_CHECKING:
    from argusprowl.models.alert import Alert

logger = logging.getLogger(__name__)


class ReplayMode(StrEnum):
    """Explicit replay mode."""

    HISTORICAL = "historical"
    CURRENT_SEMANTIC = "current_semantic"


class ReplayStatus(StrEnum):
    """Status of a replay operation."""

    # Successful replay
    HISTORICAL_REPLAYED = "historical_replayed"
    CURRENT_SEMANTIC_REPLAYED = "current_semantic_replayed"

    # Degraded/fallback
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    EMPTY = "empty"


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Result of an ATT&CK replay operation.

    Attributes:
        mode: The replay mode used.
        status: The status of the replay operation.
        observations: The replayed ATT&CK observations.
        version: The ATT&CK version used for replay.
        degraded_reason: Reason for degraded status, if applicable.
        original_alert_id: The alert ID that was replayed.
    """

    mode: ReplayMode
    status: ReplayStatus
    observations: tuple[dict[str, Any], ...]
    version: str | None
    degraded_reason: str | None = None
    original_alert_id: str | None = None

    @property
    def is_successful(self) -> bool:
        """Whether the replay was successful."""
        return self.status in (
            ReplayStatus.HISTORICAL_REPLAYED,
            ReplayStatus.CURRENT_SEMANTIC_REPLAYED,
        )

    @property
    def is_degraded(self) -> bool:
        """Whether the replay was degraded."""
        return self.status == ReplayStatus.DEGRADED

    @property
    def is_unavailable(self) -> bool:
        """Whether the replay is unavailable."""
        return self.status == ReplayStatus.UNAVAILABLE


@dataclass(frozen=True, slots=True)
class ReplayReport:
    """Report of a replay operation on multiple alerts.

    Attributes:
        results: List of individual replay results.
        mode: The replay mode used.
        total: Total number of alerts replayed.
        successful: Number of successful replays.
        degraded: Number of degraded replays.
        unavailable: Number of unavailable replays.
    """

    results: tuple[ReplayResult, ...]
    mode: ReplayMode
    total: int = 0
    successful: int = 0
    degraded: int = 0
    unavailable: int = 0

    def __post_init__(self) -> None:
        """Compute summary statistics."""
        object.__setattr__(self, "total", len(self.results))
        object.__setattr__(
            self,
            "successful",
            sum(1 for r in self.results if r.is_successful),
        )
        object.__setattr__(
            self,
            "degraded",
            sum(1 for r in self.results if r.is_degraded),
        )
        object.__setattr__(
            self,
            "unavailable",
            sum(1 for r in self.results if r.is_unavailable),
        )


class AttckReplayService:
    """Service for deterministic ATT&CK replay of alerts.

    Supports two explicit replay modes:
    - Historical: Replay using the ATT&CK version recorded with the alert
    - Current-semantic: Replay using the currently active ATT&CK snapshot

    Never mutates the original alert.
    """

    def __init__(
        self,
        knowledge_service: AttckKnowledgeService,
        mapping_registry: AttckMappingRegistry,
    ) -> None:
        """Initialize replay service.

        Args:
            knowledge_service: The ATT&CK knowledge service.
            mapping_registry: The authoritative mapping registry.
        """
        self._knowledge_service = knowledge_service
        self._mapping_registry = mapping_registry

    def replay(
        self,
        alert: Alert,
        mode: ReplayMode = ReplayMode.HISTORICAL,
    ) -> ReplayResult:
        """Replay ATT&CK observations for an alert.

        Args:
            alert: The alert to replay.
            mode: The replay mode (historical or current_semantic).

        Returns:
            ReplayResult with observations and status.
        """
        if mode == ReplayMode.HISTORICAL:
            return self._replay_historical(alert)
        elif mode == ReplayMode.CURRENT_SEMANTIC:
            return self._replay_current_semantic(alert)
        else:
            raise ValueError(f"Unknown replay mode: {mode!r}")

    def replay_batch(
        self,
        alerts: tuple[Alert, ...],
        mode: ReplayMode = ReplayMode.HISTORICAL,
    ) -> ReplayReport:
        """Replay ATT&CK observations for multiple alerts.

        Args:
            alerts: Tuple of alerts to replay.
            mode: The replay mode.

        Returns:
            ReplayReport with summary statistics.
        """
        results = tuple(self.replay(alert, mode) for alert in alerts)
        return ReplayReport(results=results, mode=mode)

    def _replay_historical(self, alert: Alert) -> ReplayResult:
        """Replay using the ATT&CK version recorded with the alert.

        Uses the version from the alert's stored attck_observations.
        Does NOT silently substitute the current snapshot.
        Does NOT reinterpret stored observations against current ATT&CK content.
        Returns explicit degraded/unavailable indication when
        historical knowledge is unavailable.
        """
        observations = alert.metadata.get("attck_observations")
        if not observations or not isinstance(observations, list):
            return ReplayResult(
                mode=ReplayMode.HISTORICAL,
                status=ReplayStatus.EMPTY,
                observations=(),
                version=None,
                degraded_reason="No attck_observations in alert metadata",
                original_alert_id=str(alert.alert_id),
            )

        stored = self._normalize_observations(observations)
        version = self._extract_version(observations)

        if version is None:
            return ReplayResult(
                mode=ReplayMode.HISTORICAL,
                status=ReplayStatus.DEGRADED,
                observations=stored,
                version=None,
                degraded_reason="No version recorded in attck_observations",
                original_alert_id=str(alert.alert_id),
            )

        knowledge_status = self._knowledge_service.get_status()
        current_version = self._knowledge_service.get_version()

        # Fail-closed: historical success requires the recorded version to be
        # the currently loaded AVAILABLE snapshot. Any mismatch, missing
        # snapshot, or degraded knowledge is explicit — never silent fallback.
        if knowledge_status != AttckKnowledgeStatus.AVAILABLE:
            return ReplayResult(
                mode=ReplayMode.HISTORICAL,
                status=ReplayStatus.DEGRADED,
                observations=stored,
                version=version,
                degraded_reason=(
                    f"Historical version {version!r} cannot be confirmed; "
                    f"knowledge status is {knowledge_status.value}. "
                    f"Returning stored observations without re-interpretation."
                ),
                original_alert_id=str(alert.alert_id),
            )

        if current_version != version:
            return ReplayResult(
                mode=ReplayMode.HISTORICAL,
                status=ReplayStatus.DEGRADED,
                observations=stored,
                version=version,
                degraded_reason=(
                    f"Historical version {version!r} unavailable; "
                    f"current snapshot is {current_version!r}. "
                    f"Returning stored observations without re-interpretation."
                ),
                original_alert_id=str(alert.alert_id),
            )

        return ReplayResult(
            mode=ReplayMode.HISTORICAL,
            status=ReplayStatus.HISTORICAL_REPLAYED,
            observations=stored,
            version=version,
            original_alert_id=str(alert.alert_id),
        )

    def _replay_current_semantic(self, alert: Alert) -> ReplayResult:
        """Replay using the currently active ATT&CK snapshot.

        Explicitly identifies this as current-semantic replay.
        Records the active ATT&CK snapshot version used.
        Does not mutate the original stored alert.
        """
        status = self._knowledge_service.get_status()

        if status in (AttckKnowledgeStatus.EMPTY, AttckKnowledgeStatus.UNAVAILABLE):
            return ReplayResult(
                mode=ReplayMode.CURRENT_SEMANTIC,
                status=ReplayStatus.UNAVAILABLE,
                observations=(),
                version=None,
                degraded_reason=f"ATT&CK knowledge status: {status.value}",
                original_alert_id=str(alert.alert_id),
            )

        version = self._knowledge_service.get_version()
        if version is None:
            return ReplayResult(
                mode=ReplayMode.CURRENT_SEMANTIC,
                status=ReplayStatus.UNAVAILABLE,
                observations=(),
                version=None,
                degraded_reason="Knowledge service has no active version",
                original_alert_id=str(alert.alert_id),
            )

        observations = self._re_enrich_with_current(alert, version)

        if status == AttckKnowledgeStatus.DEGRADED:
            return ReplayResult(
                mode=ReplayMode.CURRENT_SEMANTIC,
                status=ReplayStatus.DEGRADED,
                observations=tuple(observations),
                version=version,
                degraded_reason=(
                    "Current snapshot unavailable; using previous known-good "
                    "snapshot. Replay is current-semantic but degraded."
                ),
                original_alert_id=str(alert.alert_id),
            )

        return ReplayResult(
            mode=ReplayMode.CURRENT_SEMANTIC,
            status=ReplayStatus.CURRENT_SEMANTIC_REPLAYED,
            observations=tuple(observations),
            version=version,
            original_alert_id=str(alert.alert_id),
        )

    def _extract_version(self, observations: list[dict[str, Any]]) -> str | None:
        """Extract the ATT&CK version from observations."""
        for obs in observations:
            if isinstance(obs, dict):
                version = obs.get("version")
                if isinstance(version, str) and version:
                    return version
        return None

    def _normalize_observations(
        self, observations: list[dict[str, Any]]
    ) -> tuple[dict[str, Any], ...]:
        """Normalize observations to a deterministic tuple."""
        normalized = []
        for obs in observations:
            if isinstance(obs, dict):
                normalized.append(self._normalize_observation(obs))
        return tuple(normalized)

    def _normalize_observation(self, obs: dict[str, Any]) -> dict[str, Any]:
        """Normalize a single observation for deterministic comparison."""
        return {
            "technique_id": obs.get("technique_id", ""),
            "mapping_type": obs.get("mapping_type", ""),
            "version": obs.get("version", ""),
            "technique_name": obs.get("technique_name", ""),
            "tactic": obs.get("tactic", ""),
        }

    def _re_enrich_with_current(
        self,
        alert: Alert,
        version: str,
    ) -> list[dict[str, Any]]:
        """Re-enrich an alert using the current ATT&CK snapshot.

        Creates a new set of observations based on the current snapshot
        without mutating the original alert.
        """
        rule_id = alert.source
        mappings = self._mapping_registry.get_for_rule(rule_id)

        if not mappings:
            return []

        observations = []
        for mapping in mappings:
            if mapping.mapping_type == MappingType.NONE:
                continue

            technique = self._knowledge_service.get_technique(mapping.technique_id)
            if not technique:
                continue

            observation: dict[str, Any] = {
                "technique_id": mapping.technique_id,
                "mapping_type": mapping.mapping_type.value,
                "technique_name": technique.name,
                "version": version,
            }
            if mapping.subtechnique_id:
                observation["subtechnique_id"] = mapping.subtechnique_id
            if technique.tactic:
                observation["tactic"] = technique.tactic
            if mapping.rationale:
                observation["rationale"] = mapping.rationale

            observations.append(observation)

        return observations
