"""Endpoint ↔ network correlation engine.

Provides bounded in-memory correlation between process identity and
network observations.  Reuses the existing TemporalEngine for periodicity
analysis and enriches DetectionResult with process evidence when
available.

Source capability matrix (based on actual parser implementation):
-----------------------------------------------------------------
| Source            | Process | PID  | Network | Direct PID↔Net |
|-------------------|---------|------|---------|----------------|
| Sysmon            | yes     | yes  | yes     | yes (EventID 3)|
| Zeek              | no      | no   | yes     | no             |
| Suricata          | no      | no   | yes     | no             |
| Windows Event Log | yes     | no*  | limited | no             |
| Linux Audit       | yes     | yes  | yes**   | partial***     |

* Windows Event Log EventID 4688 provides ProcessID in attributes.
** Linux Audit SYSCALL events may include saddr/daddr/port fields.
*** Linux Audit correlates via shared hostname + timestamp window.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import timedelta
from threading import Lock
from typing import Any
from uuid import uuid4

from argusprowl.correlation.correlation_model import (
    CorrelatedActivity,
    NetworkDirection,
    NetworkObservation,
    ProcessIdentity,
)
from argusprowl.models.normalized_event import NormalizedEvent


class EndpointCorrelator:
    """Bounded endpoint ↔ network correlator.

    Tracks process identities and network observations within a
    correlation window.  When a network observation arrives with process
    attribution, it is associated with the corresponding process identity.
    When process attribution is unavailable, the network observation is
    still tracked for temporal analysis but without process context.

    Thread-safe for concurrent access from multiple collectors.
    """

    def __init__(
        self,
        correlation_window_seconds: float = 30.0,
        max_processes: int = 10000,
        max_observations: int = 1000,
    ) -> None:
        """Initialize endpoint correlator.

        Args:
            correlation_window_seconds: Time window for correlating
                process and network events.
            max_processes: Maximum tracked process identities.
            max_observations: Maximum network observations per key.
        """
        self._correlation_window = timedelta(seconds=correlation_window_seconds)
        self._max_processes = max_processes
        self._max_observations = max_observations
        self._processes: OrderedDict[tuple[str | None, int | None], ProcessIdentity] = OrderedDict()
        self._network_obs: OrderedDict[tuple[str, int], list[NetworkObservation]] = OrderedDict()
        self._correlations: list[CorrelatedActivity] = []
        self._lock = Lock()
        self._processed_count = 0
        self._correlation_count = 0

    def observe(self, event: NormalizedEvent) -> None:
        """Record an event for correlation.

        Args:
            event: NormalizedEvent to correlate.
        """
        with self._lock:
            self._processed_count += 1

            # Register process identity if available
            if event.process_name is not None or event.pid is not None:
                self._register_process(event)

            # Register network observation
            if event.dst_ip is not None:
                self._register_network_observation(event)

    def _register_process(self, event: NormalizedEvent) -> None:
        """Register or update process identity from an event."""
        pid = self._extract_pid(event)
        key = (event.hostname, pid)
        identity = ProcessIdentity(
            process_name=event.process_name,
            pid=pid,
            username=event.username,
            hostname=event.hostname,
            command_line=event.command_line,
            timestamp=event.timestamp,
            source_type=event.source_type,
        )

        # Evict if at capacity
        if key not in self._processes and len(self._processes) >= self._max_processes:
            self._processes.popitem(last=False)

        self._processes[key] = identity
        # Move to end for LRU
        if key in self._processes:
            self._processes.move_to_end(key)

    def _register_network_observation(self, event: NormalizedEvent) -> None:
        """Register a network observation and attempt correlation."""
        key = (event.dst_ip, event.dst_port or 0)
        direction = self._derive_direction(event)

        obs = NetworkObservation(
            event_id=event.event_id,
            timestamp=event.timestamp,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port or 0,
            src_ip=event.src_ip,
            src_port=event.src_port,
            protocol=event.protocol,
            process_name=event.process_name,
            pid=self._extract_pid(event),
            username=event.username,
            hostname=event.hostname,
            direction=direction,
            source_type=event.source_type,
            command_line=event.command_line,
        )

        if key not in self._network_obs:
            self._network_obs[key] = []

        observations = self._network_obs[key]
        # Evict expired
        cutoff = obs.timestamp - self._correlation_window
        self._network_obs[key] = [o for o in observations if o.timestamp >= cutoff]
        observations = self._network_obs[key]

        # Evict if at capacity
        if len(observations) >= self._max_observations:
            observations.pop(0)

        observations.append(obs)

        # Attempt correlation if process attribution exists
        if obs.has_process_attribution():
            self._attempt_correlation(obs)

    def _attempt_correlation(self, obs: NetworkObservation) -> None:
        """Attempt to correlate a network observation with a process identity."""
        proc_key = obs.process_key
        if proc_key in self._processes:
            process = self._processes[proc_key]
            # Verify timestamp is within correlation window
            time_diff = abs((obs.timestamp - process.timestamp).total_seconds())
            if time_diff <= self._correlation_window.total_seconds():
                self._create_correlation(obs, process)

    def _create_correlation(self, obs: NetworkObservation, process: ProcessIdentity) -> None:
        """Create a correlated activity record."""
        # Find existing correlation for this process+destination
        existing = None
        for corr in self._correlations:
            if (
                corr.pid == process.pid
                and corr.hostname == process.hostname
                and corr.dst_ip == obs.dst_ip
                and corr.dst_port == obs.dst_port
            ):
                existing = corr
                break

        if existing is not None:
            # Check if this is a duplicate event
            if obs.event_id in existing.event_ids:
                # Skip duplicate events to prevent artificial observation count inflation
                return

            # Update existing correlation, preferring non-None values from process
            corr = CorrelatedActivity(
                activity_id=existing.activity_id,
                process_name=process.process_name or existing.process_name,
                pid=process.pid or existing.pid,
                username=process.username or existing.username,
                hostname=process.hostname or existing.hostname,
                command_line=process.command_line or existing.command_line,
                dst_ip=obs.dst_ip,
                dst_port=obs.dst_port,
                protocol=obs.protocol or existing.protocol,
                direction=obs.direction,
                first_seen=min(existing.first_seen, obs.timestamp),
                last_seen=max(existing.last_seen, obs.timestamp),
                observation_count=existing.observation_count + 1,
                source_types=tuple(set(existing.source_types) | {obs.source_type or ""} - {""}),
                event_ids=(*existing.event_ids, obs.event_id),
                correlation_confidence=min(1.0, existing.correlation_confidence + 0.1),
            )
            self._correlations.remove(existing)
            self._correlations.append(corr)
        else:
            corr = CorrelatedActivity(
                activity_id=uuid4(),
                process_name=process.process_name,
                pid=process.pid,
                username=process.username,
                hostname=process.hostname,
                command_line=process.command_line,
                dst_ip=obs.dst_ip,
                dst_port=obs.dst_port,
                protocol=obs.protocol,
                direction=obs.direction,
                first_seen=obs.timestamp,
                last_seen=obs.timestamp,
                observation_count=1,
                source_types=(obs.source_type,) if obs.source_type else (),
                event_ids=(obs.event_id,),
                correlation_confidence=0.5,
            )
            self._correlations.append(corr)

        self._correlation_count += 1

    def _derive_direction(self, event: NormalizedEvent) -> NetworkDirection:
        """Derive network direction from available evidence.

        Direction is ONLY derived from explicit evidence, not from
        private/public IP heuristics.
        """
        # Check for explicit direction in attributes
        if event.attributes:
            explicit = event.attributes.get("direction")
            if explicit == "outbound":
                return NetworkDirection.OUTBOUND
            if explicit == "inbound":
                return NetworkDirection.INBOUND

        # Check Suricata-specific fields
        if event.attributes:
            in_iface = event.attributes.get("in_iface")
            if in_iface is not None and event.src_ip is not None:
                # If traffic came in on an interface, it's inbound
                return NetworkDirection.INBOUND

        # If we have both src and dst, and src matches hostname context, outbound
        # But we cannot assume this without deployment config, so return UNKNOWN
        return NetworkDirection.UNKNOWN

    def _extract_pid(self, event: NormalizedEvent) -> int | None:
        """Extract PID from event, checking attributes if not a direct field."""
        if hasattr(event, "pid") and event.pid is not None:
            return event.pid
        if event.attributes:
            pid_val = event.attributes.get("process_id") or event.attributes.get("ProcessId")
            if pid_val is not None:
                try:
                    return int(pid_val)
                except (ValueError, TypeError):
                    pass
        return None

    def get_correlations(
        self, dst_ip: str | None = None, dst_port: int | None = None
    ) -> list[CorrelatedActivity]:
        """Get correlations, optionally filtered by destination.

        Args:
            dst_ip: Filter by destination IP.
            dst_port: Filter by destination port.

        Returns:
            List of CorrelatedActivity records.
        """
        with self._lock:
            results = self._correlations[:]

        if dst_ip is not None:
            results = [c for c in results if c.dst_ip == dst_ip]
        if dst_port is not None:
            results = [c for c in results if c.dst_port == dst_port]

        return results

    def get_process_identity(
        self, hostname: str | None = None, pid: int | None = None
    ) -> ProcessIdentity | None:
        """Get process identity by (hostname, pid).

        Args:
            hostname: Hostname to search for.
            pid: Process ID to search for.

        Returns:
            ProcessIdentity if found, else None.
        """
        with self._lock:
            key = (hostname, pid)
            return self._processes.get(key)

    def get_statistics(self) -> dict[str, Any]:
        """Get correlator statistics.

        Returns:
            Dictionary with processing statistics.
        """
        with self._lock:
            return {
                "processed_count": self._processed_count,
                "correlation_count": self._correlation_count,
                "tracked_processes": len(self._processes),
                "tracked_network_keys": len(self._network_obs),
                "active_correlations": len(self._correlations),
            }

    def clear(self) -> None:
        """Clear all correlation state."""
        with self._lock:
            self._processes.clear()
            self._network_obs.clear()
            self._correlations.clear()

    @property
    def processed_count(self) -> int:
        return self._processed_count

    @property
    def correlation_count(self) -> int:
        return self._correlation_count
