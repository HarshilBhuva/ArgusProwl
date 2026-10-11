"""Environmental prevalence tracking for contextual intelligence (Phase 4.6B).

Tracks observation frequency and source host counts for network destinations
(IPs, ports, domains) and process-destination pairs within a bounded
sliding window.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from uuid import UUID

from argusprowl.models.context import PrevalenceResult
from argusprowl.models.normalized_event import NormalizedEvent


@dataclass(frozen=True, slots=True)
class PrevalenceObservation:
    """Internal record of a connection observation for prevalence tracking."""

    src_host: str
    timestamp: datetime
    event_id: str | None = None
    source_record_id: str | None = None


class EnvironmentPrevalenceTracker:
    """Bounded, thread-safe environmental prevalence tracker.

    Answers how common a destination (or process+destination pair) is across
    monitored hosts within a sliding time window.

    This is NOT a threat detector; it produces contextual metrics only.
    """

    def __init__(
        self,
        max_destinations: int = 10000,
        max_process_destinations: int = 10000,
        max_hosts_per_key: int = 1000,
        window_duration: timedelta = timedelta(hours=1),
        rare_threshold: int = 3,
        environment_wide_threshold: int = 50,
        min_observations: int = 10,
    ) -> None:
        """Initialize prevalence tracker.

        Args:
            max_destinations: Max unique destination keys to track (LRU evicted).
            max_process_destinations: Max unique (process, destination) keys to track.
            max_hosts_per_key: Max observations per tracked key.
            window_duration: Sliding window duration for observations.
            rare_threshold: Host count below which a destination is considered rare.
            environment_wide_threshold: Host count at or above which a destination is considered widespread.
            min_observations: Minimum total recorded observations before rarity classification is enabled (cold-start protection).
        """
        if max_destinations <= 0 or max_process_destinations <= 0 or max_hosts_per_key <= 0:
            raise ValueError("Capacity limits must be positive integers.")
        if rare_threshold <= 0 or environment_wide_threshold <= 0:
            raise ValueError("Thresholds must be positive integers.")
        if min_observations < 0:
            raise ValueError("min_observations must be non-negative.")

        self._max_destinations = max_destinations
        self._max_process_destinations = max_process_destinations
        self._max_hosts_per_key = max_hosts_per_key
        self._window_duration = window_duration
        self._rare_threshold = rare_threshold
        self._environment_wide_threshold = environment_wide_threshold
        self._min_observations = min_observations

        self._destinations: OrderedDict[str, deque[PrevalenceObservation]] = OrderedDict()
        self._process_destinations: OrderedDict[tuple[str, str], deque[PrevalenceObservation]] = (
            OrderedDict()
        )

        self._total_observations = 0
        self._lock = Lock()

    @property
    def total_observations(self) -> int:
        """Return total number of connection observations recorded."""
        with self._lock:
            return self._total_observations

    def __len__(self) -> int:
        """Return number of tracked destination keys."""
        with self._lock:
            return len(self._destinations)

    def clear(self) -> None:
        """Reset all internal state."""
        with self._lock:
            self._destinations.clear()
            self._process_destinations.clear()
            self._total_observations = 0

    def _format_dest_key(
        self, dst_ip: str | None, dst_port: int | None, domain: str | None
    ) -> str | None:
        """Format a canonical destination key."""
        if dst_ip and dst_ip.strip():
            ip_str = dst_ip.strip()
            if dst_port is not None and dst_port > 0:
                return f"{ip_str}:{dst_port}"
            return ip_str
        if domain and domain.strip():
            dom_str = domain.strip().lower().rstrip(".")
            if dst_port is not None and dst_port > 0:
                return f"{dom_str}:{dst_port}"
            return dom_str
        return None

    def record_connection(
        self,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        dst_port: int | None = None,
        domain: str | None = None,
        process_name: str | None = None,
        hostname: str | None = None,
        timestamp: datetime | None = None,
        event_id: UUID | str | None = None,
        source_record_id: str | None = None,
    ) -> None:
        """Record a network connection observation into prevalence state.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            dst_port: Destination port.
            domain: Domain name.
            process_name: Process name.
            hostname: Source hostname.
            timestamp: Event timestamp (defaults to current UTC time).
            event_id: Event UUID or string ID.
            source_record_id: Native source record ID (e.g. Zeek uid).
        """
        src_host = hostname or src_ip
        if not src_host or not src_host.strip():
            return

        ts = timestamp or datetime.now(UTC)
        ts = ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)

        eid_str = str(event_id) if event_id is not None else None
        srec_str = str(source_record_id) if source_record_id is not None else None

        obs = PrevalenceObservation(
            src_host=src_host.strip(),
            timestamp=ts,
            event_id=eid_str,
            source_record_id=srec_str,
        )

        keys_to_record: list[str] = []
        if dst_ip:
            ip_key = self._format_dest_key(dst_ip, dst_port, None)
            if ip_key:
                keys_to_record.append(ip_key)
        if domain:
            dom_key = self._format_dest_key(None, dst_port, domain)
            if dom_key and dom_key not in keys_to_record:
                keys_to_record.append(dom_key)

        if not keys_to_record:
            return

        with self._lock:
            self._total_observations += 1
            for dest_key in keys_to_record:
                self._record_key_obs_unlocked(dest_key, obs)
                if process_name and process_name.strip():
                    p_name = process_name.strip().lower()
                    self._record_proc_key_obs_unlocked((p_name, dest_key), obs)

    def record_event(self, event: NormalizedEvent) -> None:
        """Convenience method to record connection telemetry from NormalizedEvent."""
        domain = None
        if event.attributes:
            domain = (
                event.attributes.get("domain")
                or event.attributes.get("query")
                or event.attributes.get("host")
                or event.attributes.get("server_name")
            )
        self.record_connection(
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            domain=domain,
            process_name=event.process_name,
            hostname=event.hostname,
            timestamp=event.timestamp,
            event_id=event.event_id,
            source_record_id=event.source_record_id,
        )

    def _record_key_obs_unlocked(self, dest_key: str, obs: PrevalenceObservation) -> None:
        cutoff = obs.timestamp - self._window_duration

        if dest_key in self._destinations:
            bucket = self._destinations[dest_key]
            while bucket and bucket[0].timestamp < cutoff:
                bucket.popleft()
            if self._is_duplicate_unlocked(bucket, obs):
                self._destinations.move_to_end(dest_key)
                return
            bucket.append(obs)
            while len(bucket) > self._max_hosts_per_key:
                bucket.popleft()
            self._destinations.move_to_end(dest_key)
        else:
            if len(self._destinations) >= self._max_destinations:
                self._destinations.popitem(last=False)
            bucket = deque([obs])
            self._destinations[dest_key] = bucket

    def _record_proc_key_obs_unlocked(
        self, key: tuple[str, str], obs: PrevalenceObservation
    ) -> None:
        cutoff = obs.timestamp - self._window_duration

        if key in self._process_destinations:
            bucket = self._process_destinations[key]
            while bucket and bucket[0].timestamp < cutoff:
                bucket.popleft()
            if self._is_duplicate_unlocked(bucket, obs):
                self._process_destinations.move_to_end(key)
                return
            bucket.append(obs)
            while len(bucket) > self._max_hosts_per_key:
                bucket.popleft()
            self._process_destinations.move_to_end(key)
        else:
            if len(self._process_destinations) >= self._max_process_destinations:
                self._process_destinations.popitem(last=False)
            bucket = deque([obs])
            self._process_destinations[key] = bucket

    def _is_duplicate_unlocked(
        self, bucket: deque[PrevalenceObservation], obs: PrevalenceObservation
    ) -> bool:
        for existing in bucket:
            if obs.source_record_id and obs.source_record_id == existing.source_record_id:
                return True
            if obs.event_id and existing.event_id and obs.event_id == existing.event_id:
                return True
        return False

    def get_prevalence(
        self,
        dst_ip: str | None = None,
        dst_port: int | None = None,
        domain: str | None = None,
        process_name: str | None = None,
        timestamp: datetime | None = None,
    ) -> PrevalenceResult:
        """Query the prevalence result for a destination or process+destination.

        Args:
            dst_ip: Destination IP address.
            dst_port: Destination port.
            domain: Domain name.
            process_name: Process name.
            timestamp: Query timestamp for cutoff evaluation (defaults to UTC now).

        Returns:
            PrevalenceResult with dest_host_count, process_dest_count,
            is_rare_destination, and is_environment_wide flags.
        """
        now = timestamp or datetime.now(UTC)
        now = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
        cutoff = now - self._window_duration

        keys_to_query: list[str] = []
        if dst_ip:
            ip_key = self._format_dest_key(dst_ip, dst_port, None)
            if ip_key:
                keys_to_query.append(ip_key)
        if domain:
            dom_key = self._format_dest_key(None, dst_port, domain)
            if dom_key and dom_key not in keys_to_query:
                keys_to_query.append(dom_key)

        with self._lock:
            dest_hosts: set[str] = set()
            for key in keys_to_query:
                if key in self._destinations:
                    bucket = self._destinations[key]
                    while bucket and bucket[0].timestamp < cutoff:
                        bucket.popleft()
                    for obs in bucket:
                        dest_hosts.add(obs.src_host)

            dest_host_count = len(dest_hosts)

            process_hosts: set[str] = set()
            if process_name and process_name.strip():
                p_name = process_name.strip().lower()
                for dest_key in keys_to_query:
                    proc_key = (p_name, dest_key)
                    if proc_key in self._process_destinations:
                        bucket = self._process_destinations[proc_key]
                        while bucket and bucket[0].timestamp < cutoff:
                            bucket.popleft()
                        for obs in bucket:
                            process_hosts.add(obs.src_host)

            process_dest_count = len(process_hosts)

            has_enough_warmup = self._total_observations >= self._min_observations
            is_rare = (
                has_enough_warmup and dest_host_count > 0 and dest_host_count < self._rare_threshold
            )
            is_env_wide = dest_host_count >= self._environment_wide_threshold

            return PrevalenceResult(
                dest_host_count=dest_host_count,
                process_dest_count=process_dest_count,
                is_rare_destination=is_rare,
                is_environment_wide=is_env_wide,
            )
