"""Entity behavior service implementation.

Owns and manages entity behavior profiles with bounded state.
Thread-safe profile storage and lookup.

Phase 5.1.5: Adds baseline classification for behavioral state management.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Lock
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from argusprowl.metrics.collector import MetricsCollector

from argusprowl.behavior.baseline import (
    BaselineClassification,
    BaselineClassificationResult,
    BaselineMaturityState,
)
from argusprowl.behavior.baseline_evidence import (
    BaselineEvidence,
    BaselineReasonCode,
)
from argusprowl.behavior.bounded_value_set import BoundedValueSet
from argusprowl.behavior.entity_behavior_persistence import EntityBehaviorPersistence
from argusprowl.behavior.entity_behavior_profile import EntityBehaviorProfile, ProfileMaturity
from argusprowl.behavior.entity_behavior_summary import EntityBehaviorSummary


class EntityBehaviorService:
    """Owns entity behavior profile state.

    Manages bounded profiles for entity+dimension combinations with LRU eviction.
    Profiles store the set of observed dimension values per entity, enabling
    first-seen detection.

    Thread-safe for concurrent access.

    Phase 5.1.5 Baseline State:
        This service also owns baseline classification state. Classification
        is computed BEFORE the current observation is recorded, and the result
        is returned atomically along with the classification.

    TTL Semantics:
        TTL is defined as a FRESHNESS concept, not a retention guarantee.
        Profiles are NOT automatically expired and removed after TTL.
        Instead:
        - TTL defines when a profile is considered STALE (not current)
        - Stale profiles still participate in detection
        - Stale profiles are evicted via LRU when the service is at capacity
        - New observations on stale profiles transition them back to WARMING

    Baseline Maturity:
        A profile is MATURE when:
        1. observation_count >= maturity_min_observations (default: 20)
        2. last_seen - first_seen >= maturity_window (default: 1 hour)
        Both conditions are required.

        A profile is STALE when:
        - No events for stale_after duration (default: 24 hours)
        - First event after stale → WARMING (not directly to MATURE)

    Attributes:
        max_profiles: Maximum number of profiles to store.
        max_values_per_profile: Maximum distinct values per profile.
        max_value_length: Maximum length of value strings.
        stale_timeout: Duration after which a profile is considered stale.
    """

    # Saturating counter maximum to prevent overflow
    _SATURATING_COUNTER_MAX: int = 1_000_000

    def __init__(
        self,
        max_profiles: int = 100000,
        max_values_per_profile: int = 1000,
        max_value_length: int = 256,
        stale_timeout: timedelta = timedelta(hours=24),
        rare_threshold: int = 3,
        rare_min_observations: int = 5,
        # Baseline-specific parameters
        maturity_min_observations: int = 20,
        maturity_window_seconds: float = 3600.0,
        baseline_rare_threshold: int = 5,
        future_skew_threshold_seconds: float = 60.0,
        baseline_stale_after_seconds: float = 86400.0,
        is_replay_mode: bool = False,
        metrics_collector: MetricsCollector | None = None,
        persistence: EntityBehaviorPersistence | None = None,
    ) -> None:
        """Initialize entity behavior service.

        Args:
            max_profiles: Maximum number of profiles to store.
            max_values_per_profile: Maximum distinct values per profile.
            max_value_length: Maximum length of value strings.
            stale_timeout: Duration after which a profile is considered stale.
            rare_threshold: Threshold for rare value detection.
            rare_min_observations: Minimum observations for rare detection.
            maturity_min_observations: Minimum observation count for MATURE baseline.
            maturity_window_seconds: Minimum wall-clock age for MATURE baseline.
            baseline_rare_threshold: Count > this → ESTABLISHED baseline.
            future_skew_threshold_seconds: Clamp timestamps beyond this from clock.
            baseline_stale_after_seconds: No event for this → STALE baseline.
            is_replay_mode: If True, use event timestamps directly (no clamping).
            metrics_collector: Optional MetricsCollector for telemetry.
            persistence: Optional persistence layer for state durability.
        """
        if max_profiles <= 0:
            raise ValueError(f"max_profiles must be positive, got {max_profiles}")
        if max_values_per_profile <= 0:
            raise ValueError(
                f"max_values_per_profile must be positive, got {max_values_per_profile}"
            )
        if max_value_length <= 0:
            raise ValueError(f"max_value_length must be positive, got {max_value_length}")
        if rare_threshold <= 0:
            raise ValueError(f"rare_threshold must be positive, got {rare_threshold}")
        if rare_min_observations <= 0:
            raise ValueError(f"rare_min_observations must be positive, got {rare_min_observations}")
        if maturity_min_observations <= 0:
            raise ValueError(
                f"maturity_min_observations must be positive, got {maturity_min_observations}"
            )
        if maturity_window_seconds <= 0:
            raise ValueError(
                f"maturity_window_seconds must be positive, got {maturity_window_seconds}"
            )
        if baseline_rare_threshold <= 0:
            raise ValueError(
                f"baseline_rare_threshold must be positive, got {baseline_rare_threshold}"
            )
        if future_skew_threshold_seconds < 0:
            raise ValueError(
                f"future_skew_threshold_seconds must be non-negative, got {future_skew_threshold_seconds}"
            )
        if baseline_stale_after_seconds <= 0:
            raise ValueError(
                f"baseline_stale_after_seconds must be positive, got {baseline_stale_after_seconds}"
            )

        self._max_profiles = max_profiles
        self._max_values_per_profile = max_values_per_profile
        self._max_value_length = max_value_length
        self._stale_timeout = stale_timeout
        self._rare_threshold = rare_threshold
        self._rare_min_observations = rare_min_observations

        # Baseline configuration
        self._maturity_min_observations = maturity_min_observations
        self._maturity_window = timedelta(seconds=maturity_window_seconds)
        self._baseline_rare_threshold = baseline_rare_threshold
        self._future_skew_threshold = timedelta(seconds=future_skew_threshold_seconds)
        self._baseline_stale_after = timedelta(seconds=baseline_stale_after_seconds)
        self._is_replay_mode = is_replay_mode
        self._metrics_collector = metrics_collector
        self._persistence = persistence
        self._last_save_time: datetime | None = None

        # Register counters
        self._summary_queries_counter = self._register_counter(
            "entity_behavior_summary_queries_total"
        )
        self._summary_generated_counter = self._register_counter(
            "entity_behavior_summary_generated_total"
        )
        self._summary_missing_counter = self._register_counter(
            "entity_behavior_summary_missing_total"
        )
        self._baseline_classifications_counter = self._register_counter(
            "baseline_classifications_total"
        )

        # Profile storage: profile_key -> EntityBehaviorProfile
        self._profiles: OrderedDict[str, EntityBehaviorProfile] = OrderedDict()

        # Value storage per profile: profile_key -> BoundedValueSet
        self._value_sets: OrderedDict[str, BoundedValueSet] = OrderedDict()

        # Value counts per profile: profile_key -> {value: count}
        self._value_counts: dict[str, dict[str, int]] = {}

        self._lock = Lock()

        # Load persisted state if persistence is enabled
        if persistence is not None and not is_replay_mode:
            self._load_persisted_state()

    def _register_counter(self, name: str) -> Any:
        """Register or retrieve a counter metric."""
        if self._metrics_collector is None:
            from argusprowl.metrics.metrics import Counter

            return Counter(name)
        try:
            return self._metrics_collector.get_counter(name)
        except KeyError:
            return self._metrics_collector.register_counter(name)

    @property
    def max_profiles(self) -> int:
        """Return the maximum number of profiles."""
        return self._max_profiles

    @property
    def profile_count(self) -> int:
        """Return the current number of profiles."""
        with self._lock:
            return len(self._profiles)

    @property
    def max_values_per_profile(self) -> int:
        """Return the maximum values per profile."""
        return self._max_values_per_profile

    @property
    def max_value_length(self) -> int:
        """Return the maximum value length."""
        return self._max_value_length

    @property
    def stale_timeout(self) -> timedelta:
        """Return the stale timeout duration."""
        return self._stale_timeout

    def _build_profile_key(self, entity_type: str, entity_id: str, dimension: str) -> str:
        """Build a profile key from entity and dimension.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.

        Returns:
            Profile key string.
        """
        return f"{entity_type}:{entity_id}|dimension:{dimension}"

    def get_profile(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
    ) -> EntityBehaviorProfile | None:
        """Get a profile by entity and dimension.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.

        Returns:
            The profile if it exists, None otherwise.
        """
        profile_key = self._build_profile_key(entity_type, entity_id, dimension)
        with self._lock:
            profile = self._profiles.get(profile_key)
            if profile is not None:
                self._profiles.move_to_end(profile_key)
            return profile

    def _evict_profile(self) -> None:
        """Evict the oldest profile from memory and persistence."""
        if not self._profiles:
            return
        evicted_key, _ = self._profiles.popitem(last=False)
        self._value_sets.pop(evicted_key, None)
        self._value_counts.pop(evicted_key, None)
        if self._persistence is not None:
            self._persistence.delete_profile(evicted_key)

    def get_or_create_profile(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        timestamp: datetime,
    ) -> EntityBehaviorProfile:
        """Get an existing profile or create a new one.

        If the profile exists, it is moved to the end (most recently used).
        If the profile does not exist, a new one is created.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            timestamp: UTC timestamp for the observation.

        Returns:
            The existing or newly created profile.
        """
        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            # Check if profile exists
            if profile_key in self._profiles:
                profile = self._profiles[profile_key]
                self._profiles.move_to_end(profile_key)
                return profile

            # Create new profile with LRU eviction if at capacity
            if len(self._profiles) >= self._max_profiles:
                self._evict_profile()

            profile = EntityBehaviorProfile.create(
                entity_type=entity_type,
                entity_id=entity_id,
                dimension=dimension,
                timestamp=timestamp,
            )
            self._profiles[profile_key] = profile
            self._value_sets[profile_key] = BoundedValueSet(
                max_values=self._max_values_per_profile,
                max_value_length=self._max_value_length,
            )
            return profile

    def get_summary(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        max_top_values: int = 10,
    ) -> EntityBehaviorSummary | None:
        """Get a descriptive summary of an entity's behavior.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            max_top_values: Maximum number of top values to include.

        Returns:
            The summary if the profile exists, None otherwise.
        """
        if self._summary_queries_counter is not None:
            self._summary_queries_counter.increment()

        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            profile = self._profiles.get(profile_key)
            if profile is None:
                if self._summary_missing_counter is not None:
                    self._summary_missing_counter.increment()
                return None

            value_counts = self._value_counts.get(profile_key, {})

            # Convert keys to hash representation if they are oversized
            def get_key(value: str) -> str:
                if len(value) > self._max_value_length:
                    return sha256(value.encode("utf-8")).hexdigest()
                return value

            # Aggregate counts by key (to handle collisions if any, though unlikely)
            aggregated_counts: dict[str, int] = {}
            for value, count in value_counts.items():
                key = get_key(value)
                aggregated_counts[key] = aggregated_counts.get(key, 0) + count

            # Sort top values: count (desc), then value (asc)
            sorted_values = sorted(aggregated_counts.items(), key=lambda item: (-item[1], item[0]))

            top_values = sorted_values[:max_top_values]

            summary = EntityBehaviorSummary(
                entity_type=profile.entity_type,
                entity_id=profile.entity_id,
                dimension=profile.dimension,
                observation_count=profile.observation_count,
                distinct_value_count=profile.distinct_value_count,
                first_seen=profile.first_seen,
                last_seen=profile.last_seen,
                maturity=profile.maturity,
                top_values=top_values,
            )

            if self._summary_generated_counter is not None:
                self._summary_generated_counter.increment()

            return summary

    def record_observation(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        dimension_value: str,
        timestamp: datetime,
    ) -> tuple[EntityBehaviorProfile, bool]:
        """Record an observation and check if it's a first-seen value.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            dimension_value: The observed dimension value.
            timestamp: UTC timestamp of the observation.

        Returns:
            Tuple of (updated_profile, is_first_seen) where is_first_seen
            indicates whether this was a new distinct value for the profile.
        """
        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            # Get or create profile
            if profile_key not in self._profiles:
                if len(self._profiles) >= self._max_profiles:
                    evicted_key = self._profiles.popitem(last=False)
                    self._value_sets.pop(evicted_key[0], None)
                    self._value_counts.pop(evicted_key[0], None)

                profile = EntityBehaviorProfile.create(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    dimension=dimension,
                    timestamp=timestamp,
                )
                self._profiles[profile_key] = profile
                self._value_sets[profile_key] = BoundedValueSet(
                    max_values=self._max_values_per_profile,
                    max_value_length=self._max_value_length,
                )
                # New profile: value_set.add() hasn't been called yet, do it now
                value_set = self._value_sets[profile_key]
                is_new, _ = value_set.add(dimension_value)
                # Initialize and increment value count
                if profile_key not in self._value_counts:
                    self._value_counts[profile_key] = {}
                self._value_counts[profile_key][dimension_value] = (
                    self._value_counts[profile_key].get(dimension_value, 0) + 1
                )
                return profile, is_new

            # Existing profile
            profile = self._profiles[profile_key]
            self._profiles.move_to_end(profile_key)

            # Record value observation
            value_set = self._value_sets[profile_key]
            is_new, _ = value_set.add(dimension_value)

            # Update value count atomically
            if profile_key not in self._value_counts:
                self._value_counts[profile_key] = {}
            self._value_counts[profile_key][dimension_value] = (
                self._value_counts[profile_key].get(dimension_value, 0) + 1
            )

            # Update profile with observation
            updated_profile = profile.with_observation(timestamp, is_new)

            # Check maturity based on stale timeout
            maturity = updated_profile.maturity
            if updated_profile.last_seen is not None:
                age = datetime.now(UTC) - updated_profile.last_seen
                if age > self._stale_timeout:
                    maturity = ProfileMaturity.STALE

            if maturity != updated_profile.maturity:
                updated_profile = updated_profile.with_maturity(maturity)

            self._profiles[profile_key] = updated_profile
            return updated_profile, is_new

    def get_value_count(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        dimension_value: str,
    ) -> int:
        """Get the count for a specific value in a profile.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            dimension_value: The value to get the count for.

        Returns:
            The count of the value, or 0 if not found.
        """
        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            if profile_key not in self._value_counts:
                return 0
            return self._value_counts[profile_key].get(dimension_value, 0)

    def clear_value_counts(self, profile_key: str) -> None:
        """Clear all value counts for a profile.

        Args:
            profile_key: The profile key to clear counts for.
        """
        with self._lock:
            if profile_key in self._value_counts:
                self._value_counts[profile_key].clear()

    def has_value(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        dimension_value: str,
    ) -> bool:
        """Check if a value has been observed for an entity+dimension.

        This method only checks without modifying state.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            dimension_value: The value to check.

        Returns:
            True if the value has been observed, False otherwise.
        """
        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            value_set = self._value_sets.get(profile_key)
            if value_set is None:
                return False
            return dimension_value in value_set

    def check_and_record_first_seen(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        dimension_value: str,
        timestamp: datetime,
    ) -> tuple[EntityBehaviorProfile | None, bool]:
        """Check if value is first-seen and record it atomically.

        This method combines the check-and-record operation atomically. It checks
        if the value has been seen, and if not, records it and returns first-seen=True.
        This is the preferred method for first-seen detection.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            dimension_value: The observed dimension value.
            timestamp: UTC timestamp of the observation.

        Returns:
            Tuple of (profile, is_first_seen) where is_first_seen indicates
            whether this was a new distinct value. Profile is None if entity/dimension
            values are missing.
        """
        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            # Get or create profile if needed
            if profile_key not in self._profiles:
                if len(self._profiles) >= self._max_profiles:
                    evicted_key = self._profiles.popitem(last=False)
                    self._value_sets.pop(evicted_key[0], None)
                    self._value_counts.pop(evicted_key[0], None)

                profile = EntityBehaviorProfile.create(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    dimension=dimension,
                    timestamp=timestamp,
                )
                self._profiles[profile_key] = profile
                self._value_sets[profile_key] = BoundedValueSet(
                    max_values=self._max_values_per_profile,
                    max_value_length=self._max_value_length,
                )
            else:
                profile = self._profiles[profile_key]
                self._profiles.move_to_end(profile_key)

            # Check and record value atomically
            value_set = self._value_sets[profile_key]
            is_new, _ = value_set.add(dimension_value)

            # Update value count atomically
            if profile_key not in self._value_counts:
                self._value_counts[profile_key] = {}
            self._value_counts[profile_key][dimension_value] = (
                self._value_counts[profile_key].get(dimension_value, 0) + 1
            )

            # Update profile with observation
            updated_profile = profile.with_observation(timestamp, is_new)

            # Check maturity based on stale timeout
            maturity = updated_profile.maturity
            if updated_profile.last_seen is not None:
                age = datetime.now(UTC) - updated_profile.last_seen
                if age > self._stale_timeout:
                    maturity = ProfileMaturity.STALE

            if maturity != updated_profile.maturity:
                updated_profile = updated_profile.with_maturity(maturity)

            self._profiles[profile_key] = updated_profile
            return updated_profile, is_new

    def get_profile_maturity(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
    ) -> ProfileMaturity:
        """Get the maturity of a profile.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.

        Returns:
            The profile's maturity state.
        """
        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            profile = self._profiles.get(profile_key)
            if profile is None:
                return ProfileMaturity.EMPTY

            # Check stale timeout
            if profile.last_seen is not None:
                age = datetime.now(UTC) - profile.last_seen
                if age > self._stale_timeout:
                    return ProfileMaturity.STALE

            return profile.maturity

    def get_all_profiles(self) -> list[EntityBehaviorProfile]:
        """Get all profiles (for testing/debugging).

        Returns:
            List of all profiles.
        """
        with self._lock:
            return list(self._profiles.values())

    def get_profile_values(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
    ) -> list[str]:
        """Get all observed values for an entity+dimension.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.

        Returns:
            List of observed dimension values.
        """
        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            value_set = self._value_sets.get(profile_key)
            if value_set is None:
                return []
            return value_set.get_all()

    def clear(self) -> None:
        """Remove all profiles and values (for testing)."""
        with self._lock:
            self._profiles.clear()
            self._value_sets.clear()
            self._value_counts.clear()

    # =========================================================================
    # Persistence Methods (Phase 5.1.8)
    # =========================================================================

    def _load_persisted_state(self) -> None:
        """Load persisted profiles and value counts from storage."""
        if self._persistence is None:
            return
        try:
            profiles, value_counts = self._persistence.load_profiles(
                max_profiles=self._max_profiles
            )
            with self._lock:
                self._profiles = OrderedDict(profiles)
                self._value_counts = value_counts
                # Rebuild value sets from loaded data
                self._value_sets = OrderedDict()
                for profile_key in self._profiles:
                    value_set = BoundedValueSet(
                        max_values=self._max_values_per_profile,
                        max_value_length=self._max_value_length,
                    )
                    for value in self._value_counts.get(profile_key, {}):
                        value_set.add(value)
                    self._value_sets[profile_key] = value_set
            logger = __import__("logging").getLogger(__name__)
            logger.info("Loaded %d persisted profiles", len(self._profiles))
        except Exception as exc:
            logger = __import__("logging").getLogger(__name__)
            logger.warning("Failed to load persisted state: %s", exc)

    def persist_state(self) -> None:
        """Persist current state to storage."""
        if self._persistence is None:
            return
        try:
            with self._lock:
                self._persistence.save_all(dict(self._profiles), dict(self._value_counts))
            self._last_save_time = datetime.now(UTC)
        except Exception as exc:
            logger = __import__("logging").getLogger(__name__)
            logger.warning("Failed to persist state: %s", exc)

    def should_persist(self) -> bool:
        """Check if state should be persisted based on save interval."""
        if self._persistence is None:
            return False
        if self._last_save_time is None:
            return True
        # Persist if more than 60 seconds since last save
        return (datetime.now(UTC) - self._last_save_time).total_seconds() >= 60.0

    def __len__(self) -> int:
        """Return the number of profiles."""
        with self._lock:
            return len(self._profiles)

    def __bool__(self) -> bool:
        """Return True - the service object is always truthy, even when empty.

        This prevents Python's default behavior of treating objects with __len__
        as falsy when len() returns 0, which would cause `service or default`
        to incorrectly evaluate to `default`.
        """
        return True

    # =========================================================================
    # Baseline Classification Methods (Phase 5.1.5)
    # =========================================================================

    @property
    def maturity_min_observations(self) -> int:
        """Return the minimum observation count for maturity."""
        return self._maturity_min_observations

    @property
    def baseline_rare_threshold(self) -> int:
        """Return the rare threshold for baseline classification."""
        return self._baseline_rare_threshold

    def _clamp_timestamp(
        self,
        timestamp: datetime,
        processing_time: datetime,
    ) -> datetime:
        """Clamp a timestamp to prevent future-skew abuse.

        If the timestamp exceeds processing_time + future_skew_threshold,
        clamp it to that maximum.

        Args:
            timestamp: The event timestamp to potentially clamp.
            processing_time: The current processing clock time.

        Returns:
            The clamped (or unchanged) timestamp.
        """
        max_timestamp = processing_time + self._future_skew_threshold
        if timestamp > max_timestamp:
            return max_timestamp
        return timestamp

    def _compute_maturity_state(
        self,
        profile: EntityBehaviorProfile,
        effective_time: datetime,
        processing_time: datetime | None = None,
    ) -> BaselineMaturityState:
        """Compute the baseline maturity state for a profile.

        Args:
            profile: The profile to evaluate.
            effective_time: The effective current time for calculations.
            processing_time: The processing clock time (for stale detection).
                If None, uses effective_time.

        Returns:
            The baseline maturity state.
        """
        if processing_time is None:
            processing_time = effective_time

        if profile.first_seen is None or profile.last_seen is None:
            return BaselineMaturityState.WARMING

        # Check stale based on processing_time (how long since we last processed)
        # This determines if the profile has gone stale between events
        if processing_time - profile.last_seen > self._baseline_stale_after:
            return BaselineMaturityState.STALE

        # Check maturity conditions
        age = profile.last_seen - profile.first_seen
        has_enough_observations = profile.observation_count >= self._maturity_min_observations
        has_enough_age = age >= self._maturity_window

        if has_enough_observations and has_enough_age:
            return BaselineMaturityState.MATURE

        return BaselineMaturityState.WARMING

    def _classify_value(
        self,
        value: str,
        value_counts: dict[str, int],
        maturity_state: BaselineMaturityState,
    ) -> BaselineClassification:
        """Classify a value against the profile state.

        Classification is based on the state BEFORE the current observation
        is recorded.

        Args:
            value: The value to classify.
            value_counts: Current value counts (before recording).
            maturity_state: The profile's maturity state.

        Returns:
            The baseline classification.
        """
        # If profile is warming or stale, classify based on maturity
        if maturity_state in (BaselineMaturityState.WARMING, BaselineMaturityState.STALE):
            return BaselineClassification.BASELINE_WARMING

        # Profile is MATURE
        count_before = value_counts.get(value, 0)

        if count_before == 0:
            return BaselineClassification.BASELINE_NEW_VALUE

        if count_before <= self._baseline_rare_threshold:
            return BaselineClassification.BASELINE_RARE_VALUE

        return BaselineClassification.BASELINE_ESTABLISHED

    def classify_and_record(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        dimension_value: str,
        timestamp: datetime,
        processing_time: datetime | None = None,
    ) -> tuple[BaselineClassificationResult, EntityBehaviorProfile]:
        """Classify and record an observation atomically.

        This is the primary method for baseline classification. It:
        1. Computes the classification BEFORE recording
        2. Records the observation
        3. Returns the immutable classification result

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            dimension_value: The observed dimension value.
            timestamp: Event timestamp (may be clamped for live processing).
            processing_time: Current processing clock (defaults to now for live).

        Returns:
            Tuple of (BaselineClassificationResult, updated_profile).
        """
        if processing_time is None:
            processing_time = datetime.now(UTC)

        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            # Get or create profile
            if profile_key not in self._profiles:
                # No profile exists - UNAVAILABLE classification for first observation
                if len(self._profiles) >= self._max_profiles:
                    self._evict_profile()

                # Clamp timestamp for profile creation
                effective_ts = self._clamp_timestamp(timestamp, processing_time)
                profile = EntityBehaviorProfile.create(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    dimension=dimension,
                    timestamp=effective_ts,
                )
                self._profiles[profile_key] = profile
                self._value_sets[profile_key] = BoundedValueSet(
                    max_values=self._max_values_per_profile,
                    max_value_length=self._max_value_length,
                )
                self._value_counts[profile_key] = {}

                # Classification: UNAVAILABLE for first observation on new profile
                maturity_state = BaselineMaturityState.WARMING
                classification = BaselineClassification.BASELINE_UNAVAILABLE

                # Record the value (add to value set and update count)
                value_set = self._value_sets[profile_key]
                is_new, _ = value_set.add(dimension_value)

                # Update value count (saturating)
                # Note: For first observation, profile already has observation_count=1
                # from EntityBehaviorProfile.create(), so we only update value count
                current_count = self._value_counts[profile_key].get(dimension_value, 0)
                new_count = min(current_count + 1, self._SATURATING_COUNTER_MAX)
                self._value_counts[profile_key][dimension_value] = new_count

                # Profile already has correct observation_count=1 from create()
                # Just update maturity state
                updated_profile = self._update_maturity_state(
                    profile, effective_ts, processing_time
                )
                self._profiles[profile_key] = updated_profile

                # Map to BaselineMaturityState for result
                result_maturity = self._profile_maturity_to_baseline(updated_profile.maturity)

                result = BaselineClassificationResult(
                    entity_id=entity_id,
                    field=dimension,
                    value=dimension_value,
                    classification=classification,
                    profile_maturity=result_maturity,
                    pre_observation_value_count=0,
                    observation_count=updated_profile.observation_count,
                    first_seen=updated_profile.first_seen,
                    last_seen=updated_profile.last_seen,
                )

                return result, updated_profile

            # Existing profile
            profile = self._profiles[profile_key]
            self._profiles.move_to_end(profile_key)

            # Clamp timestamp
            effective_ts = self._clamp_timestamp(timestamp, processing_time)
            value_counts = self._value_counts.get(profile_key, {}).copy()

            # Compute maturity state BEFORE recording
            maturity_state = self._compute_maturity_state(profile, effective_ts, processing_time)

            # Handle STALE -> WARMING transition
            if maturity_state == BaselineMaturityState.STALE:
                maturity_state = BaselineMaturityState.WARMING

            # Classify value BEFORE recording
            classification = self._classify_value(
                dimension_value,
                value_counts,
                maturity_state,
            )

            # Record the observation
            value_set = self._value_sets[profile_key]
            is_new, _ = value_set.add(dimension_value)

            # Update value count (saturating)
            if profile_key not in self._value_counts:
                self._value_counts[profile_key] = {}
            current_count = self._value_counts[profile_key].get(dimension_value, 0)
            new_count = min(current_count + 1, self._SATURATING_COUNTER_MAX)
            self._value_counts[profile_key][dimension_value] = new_count

            # Update profile - increment observation count
            updated_profile = profile.with_observation(effective_ts, is_new)
            updated_profile = self._update_maturity_state(
                updated_profile, effective_ts, processing_time
            )
            self._profiles[profile_key] = updated_profile

            # Map updated profile maturity to BaselineMaturityState for result
            result_maturity = self._profile_maturity_to_baseline(updated_profile.maturity)

            # Apply STALE → WARMING transition for the result if profile went stale
            if result_maturity == BaselineMaturityState.STALE:
                result_maturity = BaselineMaturityState.WARMING

            # Build result (with classification from BEFORE recording, but maturity AFTER)
            result = BaselineClassificationResult(
                entity_id=entity_id,
                field=dimension,
                value=dimension_value,
                classification=classification,
                profile_maturity=result_maturity,
                pre_observation_value_count=current_count,
                observation_count=updated_profile.observation_count,
                first_seen=updated_profile.first_seen,
                last_seen=updated_profile.last_seen,
            )

            if self._baseline_classifications_counter is not None:
                self._baseline_classifications_counter.increment()

            return result, updated_profile

    def _update_maturity_state(
        self,
        profile: EntityBehaviorProfile,
        effective_time: datetime,
        processing_time: datetime | None = None,
    ) -> EntityBehaviorProfile:
        """Update the profile's maturity state based on current conditions.

        Args:
            profile: The profile to update.
            effective_time: The effective current time.
            processing_time: The processing clock time (for stale detection).

        Returns:
            Updated profile with correct maturity state.
        """
        new_state = self._compute_maturity_state(profile, effective_time, processing_time)

        # Map BaselineMaturityState to ProfileMaturity
        profile_maturity_map = {
            BaselineMaturityState.EMPTY: ProfileMaturity.EMPTY,
            BaselineMaturityState.WARMING: ProfileMaturity.WARMING,
            BaselineMaturityState.MATURE: ProfileMaturity.MATURE,
            BaselineMaturityState.STALE: ProfileMaturity.STALE,
        }

        new_maturity = profile_maturity_map.get(new_state, profile.maturity)

        if new_maturity != profile.maturity:
            return profile.with_maturity(new_maturity)

        return profile

    def _profile_maturity_to_baseline(
        self,
        maturity: ProfileMaturity,
    ) -> BaselineMaturityState:
        """Convert ProfileMaturity to BaselineMaturityState.

        Args:
            maturity: The ProfileMaturity to convert.

        Returns:
            The equivalent BaselineMaturityState.
        """
        mapping = {
            ProfileMaturity.EMPTY: BaselineMaturityState.EMPTY,
            ProfileMaturity.WARMING: BaselineMaturityState.WARMING,
            ProfileMaturity.MATURE: BaselineMaturityState.MATURE,
            ProfileMaturity.STALE: BaselineMaturityState.STALE,
        }
        return mapping.get(maturity, BaselineMaturityState.WARMING)

    def get_baseline_classification(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        dimension_value: str,
        processing_time: datetime | None = None,
    ) -> BaselineClassification | None:
        """Get the current baseline classification for a value without recording.

        This is a query-only method that does not modify state.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            dimension_value: The value to classify.
            processing_time: Optional processing time for stale calculation.

        Returns:
            The baseline classification, or None if no profile exists.
        """
        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            profile = self._profiles.get(profile_key)
            if profile is None:
                return None

            if processing_time is None:
                processing_time = datetime.now(UTC)

            value_counts = self._value_counts.get(profile_key, {})
            effective_time = processing_time
            maturity_state = self._compute_maturity_state(profile, effective_time, processing_time)

            # Handle STALE → WARMING transition for queries
            if maturity_state == BaselineMaturityState.STALE:
                maturity_state = BaselineMaturityState.WARMING

            return self._classify_value(dimension_value, value_counts, maturity_state)

    def get_baseline_profile_summary(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
    ) -> dict | None:
        """Get a summary of the baseline profile state.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.

        Returns:
            Dict with profile summary, or None if no profile exists.
        """
        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            profile = self._profiles.get(profile_key)
            if profile is None:
                return None

            value_counts = self._value_counts.get(profile_key, {})

            # Build top comparison values (bounded)
            sorted_values = sorted(value_counts.items(), key=lambda item: (-item[1], item[0]))
            top_comparison = tuple(sorted_values[:5])

            return {
                "entity_type": profile.entity_type,
                "entity_id": profile.entity_id,
                "dimension": profile.dimension,
                "observation_count": profile.observation_count,
                "distinct_value_count": profile.distinct_value_count,
                "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
                "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
                "maturity": profile.maturity.value,
                "top_comparison_values": top_comparison,
            }

    # =========================================================================
    # Analyst Query Interface (Phase 5.1.9)
    # =========================================================================

    _MAX_QUERY_RESULTS: int = 100
    _MAX_TOP_VALUES_QUERY: int = 10
    _MAX_ENTITY_TYPE_LENGTH: int = 64
    _MAX_ENTITY_ID_LENGTH: int = 256
    _MAX_DIMENSION_LENGTH: int = 64

    def _validate_query_input(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str | None = None,
    ) -> None:
        """Validate analyst query inputs.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field (optional for list queries).

        Raises:
            ValueError: If any input is invalid.
        """
        if not isinstance(entity_type, str) or not entity_type:
            raise ValueError("entity_type must be a non-empty string.")
        if len(entity_type) > self._MAX_ENTITY_TYPE_LENGTH:
            raise ValueError(
                f"entity_type exceeds maximum length of {self._MAX_ENTITY_TYPE_LENGTH}."
            )
        if not isinstance(entity_id, str) or not entity_id:
            raise ValueError("entity_id must be a non-empty string.")
        if len(entity_id) > self._MAX_ENTITY_ID_LENGTH:
            raise ValueError(f"entity_id exceeds maximum length of {self._MAX_ENTITY_ID_LENGTH}.")
        if dimension is not None:
            if not isinstance(dimension, str) or not dimension:
                raise ValueError("dimension must be a non-empty string.")
            if len(dimension) > self._MAX_DIMENSION_LENGTH:
                raise ValueError(
                    f"dimension exceeds maximum length of {self._MAX_DIMENSION_LENGTH}."
                )

    def get_entity_behavior(
        self,
        entity_type: str,
        entity_id: str,
    ) -> list[dict]:
        """Get all behavior profiles for an entity.

        This is a read-only query that does not modify state.

        Args:
            entity_type: Type of entity (e.g., 'hostname', 'src_ip').
            entity_id: Unique identifier of the entity.

        Returns:
            List of behavior summaries for all dimensions of this entity,
            ordered deterministically by dimension name.
        """
        self._validate_query_input(entity_type, entity_id)

        results: list[dict] = []
        with self._lock:
            for profile_key, profile in self._profiles.items():
                if profile.entity_type == entity_type and profile.entity_id == entity_id:
                    value_counts = self._value_counts.get(profile_key, {})

                    # Build top values (bounded)
                    sorted_values = sorted(
                        value_counts.items(), key=lambda item: (-item[1], item[0])
                    )
                    top_values = sorted_values[: self._MAX_TOP_VALUES_QUERY]

                    results.append(
                        {
                            "entity_type": profile.entity_type,
                            "entity_id": profile.entity_id,
                            "dimension": profile.dimension,
                            "observation_count": profile.observation_count,
                            "distinct_value_count": profile.distinct_value_count,
                            "first_seen": profile.first_seen.isoformat()
                            if profile.first_seen
                            else None,
                            "last_seen": profile.last_seen.isoformat()
                            if profile.last_seen
                            else None,
                            "maturity": profile.maturity.value,
                            "top_values": top_values,
                        }
                    )

        # Deterministic ordering by dimension
        results.sort(key=lambda x: x["dimension"])
        return results

    def list_entity_behavior(
        self,
        entity_type: str | None = None,
        max_results: int = 50,
        maturity_filter: str | None = None,
    ) -> list[dict]:
        """List behavior profiles with optional filtering.

        This is a read-only query that does not modify state.

        Args:
            entity_type: Optional entity type filter.
            max_results: Maximum number of results to return (bounded to 100).
            maturity_filter: Optional maturity state filter ('empty', 'warming',
                'mature', 'stale').

        Returns:
            List of behavior summaries, ordered deterministically by
            (entity_type, entity_id, dimension).
        """
        # Bound max_results
        if not isinstance(max_results, int) or max_results <= 0:
            raise ValueError("max_results must be a positive integer.")
        bounded_max = min(max_results, self._MAX_QUERY_RESULTS)

        if entity_type is not None:
            self._validate_query_input(entity_type, "placeholder")

        valid_maturities = {
            "empty",
            "warming",
            "mature",
            "stale",
            ProfileMaturity.EMPTY.value,
            ProfileMaturity.WARMING.value,
            ProfileMaturity.MATURE.value,
            ProfileMaturity.STALE.value,
        }
        if maturity_filter is not None and maturity_filter not in valid_maturities:
            raise ValueError(f"maturity_filter must be one of: {sorted(valid_maturities)}")

        results: list[dict] = []
        with self._lock:
            for profile_key, profile in self._profiles.items():
                # Apply entity_type filter
                if entity_type is not None and profile.entity_type != entity_type:
                    continue

                # Apply maturity filter
                if maturity_filter is not None:
                    filter_val = maturity_filter.lower()
                    if profile.maturity.value != filter_val:
                        continue

                value_counts = self._value_counts.get(profile_key, {})

                # Build top values (bounded)
                sorted_values = sorted(value_counts.items(), key=lambda item: (-item[1], item[0]))
                top_values = sorted_values[: self._MAX_TOP_VALUES_QUERY]

                results.append(
                    {
                        "entity_type": profile.entity_type,
                        "entity_id": profile.entity_id,
                        "dimension": profile.dimension,
                        "observation_count": profile.observation_count,
                        "distinct_value_count": profile.distinct_value_count,
                        "first_seen": profile.first_seen.isoformat()
                        if profile.first_seen
                        else None,
                        "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
                        "maturity": profile.maturity.value,
                        "top_values": top_values,
                    }
                )

                if len(results) >= bounded_max:
                    break

        # Deterministic ordering
        results.sort(key=lambda x: (x["entity_type"], x["entity_id"], x["dimension"]))
        return results

    def get_behavior_summary(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        max_top_values: int = 10,
    ) -> EntityBehaviorSummary | None:
        """Get a descriptive summary of an entity's behavior for a dimension.

        This is a read-only query that does not modify state.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            max_top_values: Maximum number of top values to include (bounded to 10).

        Returns:
            The summary if the profile exists, None otherwise.
        """
        self._validate_query_input(entity_type, entity_id, dimension)

        # Bound max_top_values
        bounded_max = min(max(max_top_values, 1), self._MAX_TOP_VALUES_QUERY)

        return self.get_summary(entity_type, entity_id, dimension, max_top_values=bounded_max)

    def get_baseline_evidence(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        dimension_value: str,
    ) -> BaselineEvidence | None:
        """Get baseline evidence for a value without recording.

        This is a read-only query that does not modify state.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            dimension_value: The value to get evidence for.

        Returns:
            BaselineEvidence if a profile exists, None otherwise.
        """
        self._validate_query_input(entity_type, entity_id, dimension)
        if not isinstance(dimension_value, str) or not dimension_value:
            raise ValueError("dimension_value must be a non-empty string.")

        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            profile = self._profiles.get(profile_key)
            if profile is None:
                return None

            value_counts = self._value_counts.get(profile_key, {})
            value_count = value_counts.get(dimension_value, 0)

            # Build top comparison values
            sorted_values = sorted(value_counts.items(), key=lambda item: (-item[1], item[0]))
            top_comparison = tuple(sorted_values[:5])

            # Determine classification and reason code
            maturity_state = self._compute_maturity_state(
                profile, datetime.now(UTC), datetime.now(UTC)
            )
            classification = self._classify_value(dimension_value, value_counts, maturity_state)

            # Map to reason code
            reason_code_map = {
                BaselineClassification.BASELINE_UNAVAILABLE: BaselineReasonCode.NO_PROFILE,
                BaselineClassification.BASELINE_WARMING: BaselineReasonCode.PROFILE_WARMING,
                BaselineClassification.BASELINE_NEW_VALUE: BaselineReasonCode.VALUE_NEW,
                BaselineClassification.BASELINE_RARE_VALUE: BaselineReasonCode.VALUE_COUNT_BELOW_THRESHOLD,
                BaselineClassification.BASELINE_ESTABLISHED: BaselineReasonCode.VALUE_ESTABLISHED,
            }
            reason_code = reason_code_map.get(
                classification, BaselineReasonCode.VALUE_COUNT_BELOW_THRESHOLD
            )

            # Build explanation
            explanation = (
                f"Value '{dimension_value[:50]}' has count {value_count} "
                f"in profile for {dimension} on {entity_id}. "
                f"Profile maturity: {profile.maturity.value}."
            )

            return BaselineEvidence(
                reason_code=reason_code,
                classification=classification.value,
                profile_maturity=maturity_state.value,
                value_count=value_count,
                rare_threshold=self._baseline_rare_threshold,
                observation_count=profile.observation_count,
                maturity_min_observations=self._maturity_min_observations,
                maturity_window_seconds=self._maturity_window.total_seconds(),
                first_seen=profile.first_seen,
                last_seen=profile.last_seen,
                top_comparison_values=top_comparison,
                explanation=explanation,
            )
            profile = self._profiles.get(profile_key)
            if profile is None:
                return None

            effective_time = datetime.now(UTC)
            maturity_state = self._compute_maturity_state(profile, effective_time)

            value_counts = self._value_counts.get(profile_key, {})

            return {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "dimension": dimension,
                "maturity_state": maturity_state.value,
                "observation_count": profile.observation_count,
                "distinct_value_count": len(value_counts),
                "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
                "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
                "value_counts": dict(value_counts),
            }

    def generate_evidence(
        self,
        result: BaselineClassificationResult,
    ) -> BaselineEvidence | None:
        """Generate bounded evidence explaining a baseline classification.

        This method creates deterministic, auditable evidence that explains
        WHY a particular classification was assigned. The evidence is derived
        entirely from structured profile state — no free-form text generation.

        Args:
            result: The baseline classification result.

        Returns:
            BaselineEvidence explaining the classification, or None if
            the result has no profile context (e.g., no profile exists).
        """
        profile_key = self._build_profile_key("hostname", result.entity_id, result.field)

        with self._lock:
            profile = self._profiles.get(profile_key)
            if profile is None:
                # No profile exists - create evidence for unavailable
                return BaselineEvidence.for_unavailable(
                    entity_id=result.entity_id,
                    field=result.field,
                    value=result.value,
                    observation_count=result.observation_count,
                    first_seen=result.first_seen,
                    last_seen=result.last_seen,
                    maturity_min_observations=self._maturity_min_observations,
                    maturity_window_seconds=self._maturity_window.total_seconds(),
                )

            value_counts = self._value_counts.get(profile_key, {})
            value_count = result.pre_observation_value_count

            # Get top comparison values (bounded)
            sorted_values = sorted(
                value_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )
            top_comparison = tuple(sorted_values[:5])

            # Determine if profile was stale
            effective_time = datetime.now(UTC)
            maturity_state = self._compute_maturity_state(profile, effective_time)
            is_stale = maturity_state == BaselineMaturityState.STALE

            # Generate evidence based on classification
            classification = result.classification
            if classification == BaselineClassification.BASELINE_UNAVAILABLE:
                return BaselineEvidence.for_unavailable(
                    entity_id=result.entity_id,
                    field=result.field,
                    value=result.value,
                    observation_count=result.observation_count,
                    first_seen=result.first_seen,
                    last_seen=result.last_seen,
                    maturity_min_observations=self._maturity_min_observations,
                    maturity_window_seconds=self._maturity_window.total_seconds(),
                )
            elif classification == BaselineClassification.BASELINE_WARMING:
                return BaselineEvidence.for_warming(
                    entity_id=result.entity_id,
                    field=result.field,
                    value=result.value,
                    value_count=value_count,
                    observation_count=result.observation_count,
                    first_seen=result.first_seen,
                    last_seen=result.last_seen,
                    maturity_min_observations=self._maturity_min_observations,
                    maturity_window_seconds=self._maturity_window.total_seconds(),
                    top_comparison_values=top_comparison,
                    is_stale=is_stale,
                )
            elif classification == BaselineClassification.BASELINE_NEW_VALUE:
                return BaselineEvidence.for_new_value(
                    entity_id=result.entity_id,
                    field=result.field,
                    value=result.value,
                    observation_count=result.observation_count,
                    first_seen=result.first_seen,
                    last_seen=result.last_seen,
                    maturity_min_observations=self._maturity_min_observations,
                    maturity_window_seconds=self._maturity_window.total_seconds(),
                    top_comparison_values=top_comparison,
                )
            elif classification == BaselineClassification.BASELINE_RARE_VALUE:
                return BaselineEvidence.for_rare_value(
                    entity_id=result.entity_id,
                    field=result.field,
                    value=result.value,
                    value_count=value_count,
                    rare_threshold=self._baseline_rare_threshold,
                    observation_count=result.observation_count,
                    first_seen=result.first_seen,
                    last_seen=result.last_seen,
                    maturity_min_observations=self._maturity_min_observations,
                    maturity_window_seconds=self._maturity_window.total_seconds(),
                    top_comparison_values=top_comparison,
                )
            elif classification == BaselineClassification.BASELINE_ESTABLISHED:
                return BaselineEvidence.for_established(
                    entity_id=result.entity_id,
                    field=result.field,
                    value=result.value,
                    value_count=value_count,
                    rare_threshold=self._baseline_rare_threshold,
                    observation_count=result.observation_count,
                    first_seen=result.first_seen,
                    last_seen=result.last_seen,
                    maturity_min_observations=self._maturity_min_observations,
                    maturity_window_seconds=self._maturity_window.total_seconds(),
                    top_comparison_values=top_comparison,
                )

        return None

    def generate_evidence_for_classification(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        dimension_value: str,
        processing_time: datetime | None = None,
    ) -> BaselineEvidence | None:
        """Generate evidence for a classification query without recording.

        This is a query-only method that does not modify state.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of entity.
            dimension: Behavioral dimension field.
            dimension_value: The value to classify.
            processing_time: Optional processing time for stale calculation.

        Returns:
            BaselineEvidence explaining the classification, or None if
            no profile exists.
        """
        if processing_time is None:
            processing_time = datetime.now(UTC)

        profile_key = self._build_profile_key(entity_type, entity_id, dimension)

        with self._lock:
            profile = self._profiles.get(profile_key)
            if profile is None:
                return None

            value_counts = self._value_counts.get(profile_key, {})
            value_count = value_counts.get(dimension_value, 0)

            # Get top comparison values (bounded)
            sorted_values = sorted(
                value_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )
            top_comparison = tuple(sorted_values[:5])

            # Compute maturity state
            maturity_state = self._compute_maturity_state(profile, processing_time, processing_time)

            # Handle STALE -> WARMING transition
            if maturity_state == BaselineMaturityState.STALE:
                maturity_state = BaselineMaturityState.WARMING

            # Classify value
            classification = self._classify_value(dimension_value, value_counts, maturity_state)

            # Generate evidence based on classification
            if classification == BaselineClassification.BASELINE_WARMING:
                return BaselineEvidence.for_warming(
                    entity_id=entity_id,
                    field=dimension,
                    value=dimension_value,
                    value_count=value_count,
                    observation_count=profile.observation_count,
                    first_seen=profile.first_seen,
                    last_seen=profile.last_seen,
                    maturity_min_observations=self._maturity_min_observations,
                    maturity_window_seconds=self._maturity_window.total_seconds(),
                    top_comparison_values=top_comparison,
                    is_stale=(
                        maturity_state == BaselineMaturityState.WARMING
                        and profile.maturity == ProfileMaturity.STALE
                    ),
                )
            elif classification == BaselineClassification.BASELINE_NEW_VALUE:
                return BaselineEvidence.for_new_value(
                    entity_id=entity_id,
                    field=dimension,
                    value=dimension_value,
                    observation_count=profile.observation_count,
                    first_seen=profile.first_seen,
                    last_seen=profile.last_seen,
                    maturity_min_observations=self._maturity_min_observations,
                    maturity_window_seconds=self._maturity_window.total_seconds(),
                    top_comparison_values=top_comparison,
                )
            elif classification == BaselineClassification.BASELINE_RARE_VALUE:
                return BaselineEvidence.for_rare_value(
                    entity_id=entity_id,
                    field=dimension,
                    value=dimension_value,
                    value_count=value_count,
                    rare_threshold=self._baseline_rare_threshold,
                    observation_count=profile.observation_count,
                    first_seen=profile.first_seen,
                    last_seen=profile.last_seen,
                    maturity_min_observations=self._maturity_min_observations,
                    maturity_window_seconds=self._maturity_window.total_seconds(),
                    top_comparison_values=top_comparison,
                )
            elif classification == BaselineClassification.BASELINE_ESTABLISHED:
                return BaselineEvidence.for_established(
                    entity_id=entity_id,
                    field=dimension,
                    value=dimension_value,
                    value_count=value_count,
                    rare_threshold=self._baseline_rare_threshold,
                    observation_count=profile.observation_count,
                    first_seen=profile.first_seen,
                    last_seen=profile.last_seen,
                    maturity_min_observations=self._maturity_min_observations,
                    maturity_window_seconds=self._maturity_window.total_seconds(),
                    top_comparison_values=top_comparison,
                )

        return None
