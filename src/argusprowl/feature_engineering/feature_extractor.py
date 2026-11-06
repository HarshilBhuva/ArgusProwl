"""Feature extraction orchestrator.

Extracts feature vectors from NormalizedEvents using sliding windows
and aggregation functions.
"""

from dataclasses import fields
from collections import OrderedDict
from datetime import timedelta
from threading import Lock

from argusprowl.feature_engineering.aggregators import aggregate_connection_features
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.feature_engineering.sliding_window import SlidingWindow
from argusprowl.models.normalized_event import NormalizedEvent


_FEATURE_VECTOR_FIELDS = frozenset(field.name for field in fields(FeatureVector))


class FeatureExtractor:
    """Extracts feature vectors from network connection events.

    Uses sliding windows to aggregate events and compute features
    suitable for threat detection.

    Accepts :class:`NormalizedEvent` instances.

    Attributes:
        window_size_seconds: Time window duration for feature extraction.
        max_events_per_window: Maximum events to consider per window.
    """

    def __init__(
        self,
        window_size_seconds: float = 60.0,
        max_events_per_window: int = 1000,
        max_active_windows: int = 10000,
    ) -> None:
        """Initialize feature extractor.

        Args:
            window_size_seconds: Time window in seconds.
            max_events_per_window: Maximum events per window (0 = unlimited).
            max_active_windows: Maximum source-IP windows retained (LRU eviction).
        """
        if max_active_windows < 1:
            raise ValueError("max_active_windows must be positive")
        self._window_size_seconds = window_size_seconds
        self._max_events_per_window = max_events_per_window
        self._max_active_windows = max_active_windows
        self._windows: OrderedDict[str, SlidingWindow] = OrderedDict()
        self._lock = Lock()

    def extract(self, event: NormalizedEvent) -> FeatureVector | None:
        """Extract features from a single event.

        Maintains per-source-IP sliding windows and generates
        a FeatureVector when sufficient data is available.

        Args:
            event: Event to extract features from.

        Returns:
            FeatureVector if window has events, else None.
        """
        src_ip = event.src_ip

        # Per-source-IP stateful aggregation requires a stable identity.
        # ``None`` here can occur for telemetry that lacks endpoint information
        # (DNS queries, ARP events, partial sysmon records), where using ``None``
        # as a dict key would silently collapse every anonymous observation into a
        # single global window and distort feature vectors.  Skip such events
        # here; protocol-specific detectors can still inspect the raw envelope
        # via ``DetectionRule`` conditions or dedicated detectors.
        if src_ip is None:
            return None

        # Bound per-source state and protect registry mutation. Keep expensive
        # aggregation outside the registry lock so different sources do not
        # serialize on feature computation.
        with self._lock:
            window = self._windows.get(src_ip)
            if window is None:
                if len(self._windows) >= self._max_active_windows:
                    self._windows.popitem(last=False)
                window = SlidingWindow(
                    window_size_seconds=self._window_size_seconds,
                    max_events=self._max_events_per_window,
                )
                self._windows[src_ip] = window
            else:
                self._windows.move_to_end(src_ip)
            window.add(event)

        # One snapshot serves both aggregation and window-boundary calculation.
        events = window.get_events(event.timestamp)
        if not events:
            return None
        features_dict = aggregate_connection_features(events)

        # Calculate window timing
        window_end = events[-1].timestamp
        if len(events) == 1 or events[0].timestamp == window_end:
            window_start = window_end - timedelta(seconds=self._window_size_seconds)
        else:
            window_start = events[0].timestamp

        main_features = {
            key: value
            for key, value in features_dict.items()
            if key in _FEATURE_VECTOR_FIELDS and key != "features"
        }
        extra_features = {
            key: value for key, value in features_dict.items() if key not in _FEATURE_VECTOR_FIELDS
        }

        # Create and return FeatureVector
        return FeatureVector(
            event_id=event.event_id,
            window_start=window_start,
            window_end=window_end,
            features=extra_features,
            **main_features,
        )

    def extract_batch(self, events: list[NormalizedEvent]) -> list[FeatureVector]:
        """Extract features from a batch of events.

        Args:
            events: List of events.

        Returns:
            List of FeatureVectors (one per event with sufficient context).
        """
        vectors = []
        for event in events:
            vector = self.extract(event)
            if vector is not None:
                vectors.append(vector)
        return vectors

    def get_window(self, src_ip: str) -> SlidingWindow | None:
        """Get the sliding window for a specific source IP.

        Args:
            src_ip: Source IP address.

        Returns:
            SlidingWindow if exists, else None.
        """
        with self._lock:
            return self._windows.get(src_ip)

    def clear_window(self, src_ip: str) -> None:
        """Clear the sliding window for a specific source IP.

        Args:
            src_ip: Source IP address.
        """
        with self._lock:
            window = self._windows.get(src_ip)
            if window is not None:
                window.clear()

    def clear_all_windows(self) -> None:
        """Clear all sliding windows."""
        with self._lock:
            for window in self._windows.values():
                window.clear()

    def get_active_windows(self) -> list[str]:
        """Get list of source IPs with non-empty windows.

        Returns:
            List of source IP addresses.
        """
        with self._lock:
            windows = list(self._windows.items())
        return [ip for ip, window in windows if not window.is_empty]

    @property
    def window_size_seconds(self) -> float:
        """Get window size in seconds."""
        return self._window_size_seconds

    @property
    def active_window_count(self) -> int:
        """Get number of active (non-empty) windows."""
        with self._lock:
            windows = list(self._windows.values())
        return sum(1 for window in windows if not window.is_empty)

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"FeatureExtractor(window_size={self._window_size_seconds}s, "
            f"active_windows={self.active_window_count})"
        )
