"""Application configuration data model.

Provides a typed representation of the application's runtime configuration.
"""

from dataclasses import dataclass, field

from argusprowl.models.api_config import ApiConfig


@dataclass(slots=True)
class LoggingConfig:
    """Logging subsystem configuration.

    Attributes:
        level: Minimum log level (e.g. ``"DEBUG"``, ``"INFO"``).
        console_enabled: Whether to log to stdout.
        file_enabled: Whether to log to a rotating file.
        json_enabled: Whether to write JSON-structured log files.
        log_file: Path to the plain-text log file.
        json_log_file: Path to the JSON log file.
        max_bytes: Maximum size of a single log file before rotation.
        backup_count: Number of rotated log files to retain.
        colored_console: Whether console output uses ANSI colours.
    """

    level: str = "INFO"
    console_enabled: bool = True
    file_enabled: bool = True
    json_enabled: bool = False
    log_file: str = "logs/argusprowl.log"
    json_log_file: str = "logs/argusprowl.json"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5
    colored_console: bool = True


@dataclass(slots=True)
class StorageConfig:
    """Storage subsystem configuration.

    Attributes:
        backend: Storage backend type (e.g. ``"filesystem"``, ``"sqlite"``).
        base_path: Root directory for file-based storage.
    """

    backend: str = "sqlite"
    base_path: str = "data"
    database_path: str = "data/argusprowl.db"


@dataclass(slots=True)
class EventsConfig:
    """Event bus configuration.

    Attributes:
        queue_size: Maximum pending events in the internal queue.
        async_dispatch: Whether event dispatch is asynchronous.
    """

    queue_size: int = 1000
    async_dispatch: bool = False
    worker_count: int = 1
    shutdown_timeout_seconds: float = 5.0


@dataclass(slots=True)
class IngestionConfig:
    """Ingestion subsystem configuration.

    Attributes:
        zeek_log_path: Path to the Zeek log file (e.g. conn.log).
        poll_interval: Tailing sleep duration in seconds when waiting for new log data.
        batch_size: Number of records to read per batch iteration.
    """

    zeek_log_path: str = "data/conn.log"
    poll_interval: float = 0.5
    batch_size: int = 100


@dataclass(slots=True)
class BufferConfig:
    max_size: int = 1000
    overflow_policy: str = "drop_newest"


@dataclass(slots=True)
class RetryConfig:
    max_attempts: int = 3
    initial_delay: float = 0.1
    max_delay: float = 5.0
    jitter: bool = False


@dataclass(slots=True)
class DeduplicationConfig:
    enabled: bool = True
    default_cooldown: float = 300.0
    max_fingerprints: int = 10_000


@dataclass(slots=True)
class AlertQueueConfig:
    """Alert queue configuration.

    Attributes:
        max_size: Maximum number of alerts in the queue. Must be positive.
    """

    max_size: int = 10_000


@dataclass(slots=True)
class ReliabilityConfig:
    buffer: BufferConfig = field(default_factory=BufferConfig)
    retry: RetryConfig = field(default_factory=RetryConfig)

    deduplication: DeduplicationConfig = field(default_factory=DeduplicationConfig)
    alert_queue: AlertQueueConfig = field(default_factory=AlertQueueConfig)


@dataclass(slots=True)
class TemporalConfig:
    """Temporal detection configuration.

    Attributes:
        enabled: Whether temporal detection is active.
        max_keys: Maximum number of (dst_ip, dst_port) keys to track.
        max_observations_per_key: Maximum observations per key.
        window_duration_seconds: Time window for analysis.
        min_observations: Minimum observations for beaconing assessment.
        min_duration_seconds: Minimum duration for beaconing assessment.
        periodicity_threshold: Minimum periodicity score to flag.
    """

    enabled: bool = True
    max_keys: int = 10000
    max_observations_per_key: int = 1000
    window_duration_seconds: float = 3600.0
    min_observations: int = 10
    min_duration_seconds: float = 300.0
    periodicity_threshold: float = 0.7


@dataclass(slots=True)
class SysmonConfig:
    enabled: bool = False
    channel: str = "Microsoft-Windows-Sysmon/Operational"
    bookmark_path: str = "data/sysmon-bookmark.json"
    batch_size: int = 100
    polling_interval: float = 1.0
    supported_event_ids: tuple[int, ...] = (1, 3, 7, 8, 10, 11, 12, 13, 14, 22)


@dataclass(slots=True)
class WindowsEventLogConfig:
    enabled: bool = False
    channels: tuple[str, ...] = ("Security",)
    bookmark_path: str = "data/windows-event-bookmarks.json"
    batch_size: int = 100
    polling_interval: float = 1.0
    event_ids: tuple[int, ...] = (4624, 4625, 4648, 4672, 4688, 4697, 4720, 4728, 4732, 4756, 1102)


@dataclass(slots=True)
class LinuxAuditConfig:
    enabled: bool = False
    path: str = "/var/log/audit/audit.log"
    bookmark_path: str = "data/linux-audit-bookmark.json"
    batch_size: int = 100
    polling_interval: float = 1.0
    grouping_timeout: float = 1.0
    max_pending_groups: int = 1000
    supported_record_types: tuple[str, ...] = (
        "SYSCALL",
        "EXECVE",
        "USER_LOGIN",
        "USER_START",
        "USER_ACCT",
        "USER_CMD",
        "USER_ROLE_CHANGE",
        "USER_CHAUTHTOK",
        "CRED_ACQ",
        "CRED_REFR",
        "CRED_DISP",
        "USER_END",
    )


@dataclass(slots=True)
class EndpointCorrelationConfig:
    """Endpoint correlation configuration.

    Attributes:
        enabled: Whether endpoint correlation is active.
        correlation_window_seconds: Time window for correlating process and network events.
        max_processes: Maximum tracked process identities.
        max_observations: Maximum network observations per key.
    """

    enabled: bool = True
    correlation_window_seconds: float = 30.0
    max_processes: int = 10000
    max_observations: int = 1000


@dataclass(slots=True)
class EventCountCorrelationConfig:
    """Event-count correlation configuration.

    Attributes:
        enabled: Whether event-count correlation is active.
        max_keys: Maximum number of group keys to track.
        max_observations_per_key: Maximum observations per group key.
        default_count: Default event count threshold.
        default_timespan_seconds: Default time window in seconds.
        default_group_by: Default fields to group by.
        default_confidence: Default confidence score for detections.
    """

    enabled: bool = True
    max_keys: int = 10000
    max_observations_per_key: int = 1000
    default_count: int = 5
    default_timespan_seconds: float = 300.0
    default_group_by: tuple[str, ...] = ("src_ip",)
    default_confidence: float = 0.7


@dataclass(slots=True)
class BaselineConfig:
    """Baseline behavioral analysis configuration.

    Attributes:
        enabled: Whether baseline behavioral analysis is active.
        maturity_min_observations: Minimum observation count for maturity.
        maturity_window_seconds: Minimum wall-clock age for maturity.
        rare_threshold: Historical count > this → ESTABLISHED.
        future_skew_threshold_seconds: Clamp timestamps beyond this.
        max_distinct_values: Per entity-field; excess evicted LRU-style.
        max_observations_retained: Per entity-field; excess discarded.
        stale_after_seconds: No event for this duration → STALE.
    """

    enabled: bool = True
    maturity_min_observations: int = 20
    maturity_window_seconds: float = 3600.0
    rare_threshold: int = 5
    future_skew_threshold_seconds: float = 60.0
    max_distinct_values: int = 1000
    max_observations_retained: int = 10000
    stale_after_seconds: float = 86400.0


@dataclass(slots=True)
class BehaviorPersistenceConfig:
    """Entity behavior persistence configuration.

    Attributes:
        enabled: Whether to persist behavior state to SQLite.
        db_path: Path to the SQLite database file.
        save_interval_seconds: How often to save state (0 = on every change).
        max_profiles: Maximum profiles to persist.
    """

    enabled: bool = False
    db_path: str = "data/behavior_state.db"
    save_interval_seconds: float = 60.0
    max_profiles: int = 100000


@dataclass(slots=True)
class AnalystAnnotationConfig:
    """Analyst annotation configuration.

    Attributes:
        enabled: Whether analyst annotations are active.
        db_path: Path to the SQLite database file for annotations.
        max_annotations_per_target: Maximum annotations per target key.
        max_total_annotations: Maximum total annotations in storage.
    """

    enabled: bool = False
    db_path: str = "data/analyst_annotations.db"
    max_annotations_per_target: int = 50
    max_total_annotations: int = 10000


@dataclass(slots=True)
class AlertPersistenceConfig:
    """Alert persistence configuration.

    Attributes:
        enabled: Whether to persist alerts to SQLite.
        db_path: Path to the SQLite database file.
        max_alerts: Maximum number of alerts to retain.
    """

    enabled: bool = False
    db_path: str = "data/alerts.db"
    max_alerts: int = 10_000


@dataclass(slots=True)
class TelemetryEvidenceConfig:
    """Telemetry evidence store configuration.

    Attributes:
        enabled: Whether the evidence store is active.
        max_retained_events: Maximum number of events to retain in memory.
    """

    enabled: bool = True
    max_retained_events: int = 100_000


@dataclass(slots=True)
class AttckConfig:
    """ATT&CK knowledge layer configuration.

    Attributes:
        enabled: Whether the ATT&CK knowledge service is active.
            When False, core detection continues normally and all
            ATT&CK lookups return None.
        snapshot_path: Path to the current ATT&CK snapshot file.
        previous_snapshot_path: Path to the previous known-good snapshot.
            If empty, derived automatically from snapshot_path.
    """

    enabled: bool = False
    snapshot_path: str = "data/attck_snapshot.json"
    previous_snapshot_path: str = ""


@dataclass(slots=True)
class AppConfiguration:
    """Top-level application configuration container.

    Attributes:
        app_name: Human-readable application name.
        debug: Whether debug mode is enabled.
        environment: Deployment environment label.
        logging: Logging subsystem config.
        storage: Storage subsystem config.
        events: Event bus config.
        ingestion: Ingestion subsystem config.
    """

    app_name: str = "argusprowl"
    debug: bool = False
    environment: str = "production"
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    events: EventsConfig = field(default_factory=EventsConfig)
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    reliability: ReliabilityConfig = field(default_factory=ReliabilityConfig)
    temporal: TemporalConfig = field(default_factory=TemporalConfig)
    endpoint_correlation: EndpointCorrelationConfig = field(
        default_factory=EndpointCorrelationConfig
    )
    event_count_correlation: EventCountCorrelationConfig = field(
        default_factory=EventCountCorrelationConfig
    )
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    behavior_persistence: BehaviorPersistenceConfig = field(
        default_factory=BehaviorPersistenceConfig
    )
    analyst_annotations: AnalystAnnotationConfig = field(default_factory=AnalystAnnotationConfig)
    alert_persistence: AlertPersistenceConfig = field(default_factory=AlertPersistenceConfig)
    attck: AttckConfig = field(default_factory=AttckConfig)
    sysmon: SysmonConfig = field(default_factory=SysmonConfig)
    windows_event_log: WindowsEventLogConfig = field(default_factory=WindowsEventLogConfig)
    linux_audit: LinuxAuditConfig = field(default_factory=LinuxAuditConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    telemetry_evidence: TelemetryEvidenceConfig = field(default_factory=TelemetryEvidenceConfig)


# Short public name used by external plugin authors; keep the explicit name in
# internal code to distinguish application settings from plugin settings.
Configuration = AppConfiguration
