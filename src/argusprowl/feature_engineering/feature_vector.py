"""Feature vector data model.

Immutable container for aggregated features extracted from network events
for use in threat detection.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class FeatureVector:
    """Immutable feature vector for detection analysis.

    Attributes:
        event_id: Source event identifier.
        window_start: Start of the aggregation window.
        window_end: End of the aggregation window.
        vector_id: Unique identifier for this feature vector.
        created_at: UTC timestamp of feature extraction.

        # Connection features
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        src_port: Source port number.
        dst_port: Destination port number.
        proto: Transport protocol.

        # Aggregated counts
        connection_count: Total connections in window.
        unique_dst_ports: Number of unique destination ports.
        unique_dst_ips: Number of unique destination IPs.
        failed_connections: Count of failed connections.
        syn_count: Count of SYN packets.

        # Statistical features
        avg_duration: Average connection duration in seconds.
        max_duration: Maximum connection duration.
        min_duration: Minimum connection duration.
        std_duration: Standard deviation of durations.
        total_bytes_sent: Total bytes sent by originator.
        total_bytes_received: Total bytes received by originator.
        avg_bytes_per_connection: Average bytes per connection.

        # Behavioral features
        connection_rate: Connections per second.
        bytes_rate: Bytes per second.
        port_concentration: Ratio of connections to top port.
        is_multi_port: Whether connections span multiple ports.
        is_multi_dst: Whether connections span multiple destinations.

        # Temporal features
        time_since_first_connection: Seconds since first connection in window.

        # Metadata
        features: Additional computed features as key-value pairs.
    """

    event_id: UUID
    window_start: datetime
    window_end: datetime
    vector_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Connection features
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    proto: str = ""

    # Aggregated counts
    connection_count: int = 0
    unique_dst_ports: int = 0
    unique_dst_ips: int = 0
    failed_connections: int = 0
    syn_count: int = 0

    # Statistical features
    avg_duration: float = 0.0
    max_duration: float = 0.0
    min_duration: float = 0.0
    std_duration: float = 0.0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    avg_bytes_per_connection: float = 0.0

    # Behavioral features
    connection_rate: float = 0.0
    bytes_rate: float = 0.0
    port_concentration: float = 0.0
    is_multi_port: bool = False
    is_multi_dst: bool = False

    # Temporal features
    time_since_first_connection: float = 0.0

    # Metadata
    features: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate feature vector constraints."""
        if self.window_start >= self.window_end:
            raise ValueError(
                f"window_start ({self.window_start}) must be before window_end ({self.window_end})"
            )
        if self.connection_count < 0:
            raise ValueError("connection_count must be non-negative.")
        if self.unique_dst_ports < 0:
            raise ValueError("unique_dst_ports must be non-negative.")
        if self.unique_dst_ips < 0:
            raise ValueError("unique_dst_ips must be non-negative.")
        if not 0.0 <= self.port_concentration <= 1.0:
            raise ValueError(
                f"port_concentration must be in [0.0, 1.0], got {self.port_concentration}"
            )

    def get_feature(self, key: str, default: object = None) -> object:
        """Retrieve a custom feature by key.

        Args:
            key: Feature name.
            default: Value to return if key not found.

        Returns:
            Feature value or default.
        """
        return self.features.get(key, default)

    def to_dict(self) -> dict[str, object]:
        """Convert feature vector to dictionary representation.

        Returns:
            Dictionary with all feature vector fields.
        """
        return {
            "vector_id": str(self.vector_id),
            "event_id": str(self.event_id),
            "created_at": self.created_at.isoformat(),
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "connection_count": self.connection_count,
            "unique_dst_ports": self.unique_dst_ports,
            "unique_dst_ips": self.unique_dst_ips,
            "failed_connections": self.failed_connections,
            "syn_count": self.syn_count,
            "avg_duration": self.avg_duration,
            "max_duration": self.max_duration,
            "min_duration": self.min_duration,
            "std_duration": self.std_duration,
            "total_bytes_sent": self.total_bytes_sent,
            "total_bytes_received": self.total_bytes_received,
            "avg_bytes_per_connection": self.avg_bytes_per_connection,
            "connection_rate": self.connection_rate,
            "bytes_rate": self.bytes_rate,
            "port_concentration": self.port_concentration,
            "is_multi_port": self.is_multi_port,
            "is_multi_dst": self.is_multi_dst,
            "time_since_first_connection": self.time_since_first_connection,
            "features": self.features,
        }
