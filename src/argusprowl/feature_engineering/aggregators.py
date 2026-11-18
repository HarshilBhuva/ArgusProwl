"""Event aggregation functions.

Provides aggregation logic for computing features from collections
of NormalizedEvents within a sliding window.
"""

from collections import defaultdict
from typing import Any

from argusprowl.models.normalized_event import NormalizedEvent


def aggregate_connection_features(events: list[NormalizedEvent]) -> dict[str, Any]:
    """Aggregate connection-level features from a list of events.

    Args:
        events: List of NormalizedEvents to aggregate.

    Returns:
        Dictionary containing aggregated features.
    """
    if not events:
        return {}

    # Use the most recent event as the reference
    reference_event = events[-1]

    # Basic counts
    connection_count = len(events)

    # Unique destinations
    dst_ports: set[int] = set()
    dst_ips: set[str] = set()
    src_ports: set[int] = set()

    # Connection state tracking
    failed_connections = 0
    syn_count = 0

    # Statistical collections
    durations: list[float] = []
    orig_bytes_list: list[int] = []
    resp_bytes_list: list[int] = []

    # Port distribution for concentration calculation
    port_counts: dict[int, int] = defaultdict(int)

    # Time tracking
    first_timestamp = events[0].timestamp
    last_timestamp = events[-1].timestamp

    for event in events:
        # Collect unique values
        if event.dst_port and event.dst_port > 0:
            dst_ports.add(event.dst_port)
            port_counts[event.dst_port] += 1

        if event.dst_ip:
            dst_ips.add(event.dst_ip)

        if event.src_port and event.src_port > 0:
            src_ports.add(event.src_port)

        # Count failed connections.  Zeek conn_state semantics:
        #   SF  - normal close (both FINs observed)        -> success
        #   S1  - established, no close observed yet       -> still established (not failure)
        #   S2  - SYN-sent peer close (passive)             -> success in practice
        #   S3  - SYN-ack sent peer close (active)          -> success in practice
        #   S0  - SYN-sent, no response                     -> failure
        #   REJ - rejected (RST seen)                       -> failure
        #   OTH - partial or unclassifiable                 -> failure
        # Counting ``SF`` here mis-classified successful TCP teardowns as failures
        # and inflated ``failed_connections`` for benign traffic.
        conn_state = event.attributes.get("conn_state", "")
        if conn_state in ("REJ", "S0", "OTH"):
            failed_connections += 1

        # Count SYN packets (history contains 'S' for SYN)
        history = event.attributes.get("history", "")
        if "S" in history:
            syn_count += 1

        # Collect durations and bytes
        duration = event.attributes.get("duration", 0.0)
        if duration > 0:
            durations.append(duration)

        orig_bytes = event.attributes.get("orig_bytes", 0)
        if orig_bytes > 0:
            orig_bytes_list.append(orig_bytes)

        resp_bytes = event.attributes.get("resp_bytes", 0)
        if resp_bytes > 0:
            resp_bytes_list.append(resp_bytes)

    # Calculate statistics
    avg_duration = sum(durations) / len(durations) if durations else 0.0
    max_duration = max(durations) if durations else 0.0
    min_duration = min(durations) if durations else 0.0

    # Standard deviation
    if len(durations) >= 2:
        mean_duration = avg_duration
        variance = sum((d - mean_duration) ** 2 for d in durations) / len(durations)
        std_duration = variance**0.5
    else:
        std_duration = 0.0

    # Byte statistics
    total_bytes_sent = sum(orig_bytes_list)
    total_bytes_received = sum(resp_bytes_list)
    avg_bytes_per_connection = (total_bytes_sent + total_bytes_received) / connection_count

    # Time-based features
    time_span = (last_timestamp - first_timestamp).total_seconds()
    connection_rate = connection_count / time_span if time_span > 0 else 0.0
    bytes_rate = (total_bytes_sent + total_bytes_received) / time_span if time_span > 0 else 0.0

    # Port concentration (how focused is the traffic on specific ports)
    port_concentration = (
        max(port_counts.values()) / connection_count
        if (connection_count > 0 and port_counts)
        else 0.0
    )

    # Behavioral flags
    is_multi_port = len(dst_ports) > 1
    is_multi_dst = len(dst_ips) > 1

    # Time since first connection
    time_since_first = (last_timestamp - first_timestamp).total_seconds()

    return {
        # Connection features
        "src_ip": reference_event.src_ip,
        "dst_ip": reference_event.dst_ip,
        "src_port": reference_event.src_port,
        "dst_port": reference_event.dst_port,
        "proto": reference_event.protocol,
        # Aggregated counts
        "connection_count": connection_count,
        "unique_dst_ports": len(dst_ports),
        "unique_dst_ips": len(dst_ips),
        "failed_connections": failed_connections,
        "syn_count": syn_count,
        # Statistical features
        "avg_duration": avg_duration,
        "max_duration": max_duration,
        "min_duration": min_duration,
        "std_duration": std_duration,
        "total_bytes_sent": total_bytes_sent,
        "total_bytes_received": total_bytes_received,
        "avg_bytes_per_connection": avg_bytes_per_connection,
        # Behavioral features
        "connection_rate": connection_rate,
        "bytes_rate": bytes_rate,
        "port_concentration": port_concentration,
        "is_multi_port": is_multi_port,
        "is_multi_dst": is_multi_dst,
        # Temporal features
        "time_since_first_connection": time_since_first,
        # Metadata
        "unique_src_ports": len(src_ports),
        "dst_ports_list": list(dst_ports),
        "dst_ips_list": list(dst_ips),
    }


def aggregate_by_src_ip(events: list[NormalizedEvent]) -> dict[str, list[NormalizedEvent]]:
    """Group events by source IP address.

    Args:
        events: List of events.

    Returns:
        Dictionary mapping source IP to list of events.
    """
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.src_ip:
            grouped[event.src_ip].append(event)
    return dict(grouped)


def aggregate_by_dst_port(events: list[NormalizedEvent]) -> dict[int, list[NormalizedEvent]]:
    """Group events by destination port.

    Args:
        events: List of events.

    Returns:
        Dictionary mapping destination port to list of events.
    """
    grouped: dict[int, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.dst_port and event.dst_port > 0:
            grouped[event.dst_port].append(event)
    return dict(grouped)


def aggregate_by_dst_ip(events: list[NormalizedEvent]) -> dict[str, list[NormalizedEvent]]:
    """Group events by destination IP address.

    Args:
        events: List of events.

    Returns:
        Dictionary mapping destination IP to list of events.
    """
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.dst_ip:
            grouped[event.dst_ip].append(event)
    return dict(grouped)
